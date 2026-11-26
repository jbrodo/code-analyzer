"""C-06: porte della Fase 2 (feed, storia git, baseline, archivio) con i loro fake in memoria."""

import io
from datetime import UTC, date, datetime

import pytest
from pydantic import ValidationError

from ca_core.fakes import (
    FakeBaselineSource,
    FakeEnrichmentFeeds,
    InMemoryArtifactStore,
    InMemoryGitHistory,
)
from ca_core.ports import (
    ArtifactConflict,
    ArtifactIntegrityError,
    ArtifactNotFound,
    ArtifactStore,
    ArtifactTooLarge,
    BaselineLookup,
    BaselineOutcome,
    BaselineSource,
    BaselineSourceKind,
    ChangedFilesRequest,
    ChangedFilesResult,
    ChurnRequest,
    ChurnResult,
    EnrichmentFeeds,
    EpssAnswer,
    FeedSnapshot,
    FeedStatus,
    GitHistory,
    HistoryStatus,
    KevAnswer,
    StoredArtifact,
    validate_artifact_key,
    validate_cve,
)

NOW = datetime(2026, 11, 17, tzinfo=UTC)
SHA = "a" * 64
CVE = "CVE-2024-12345"


# --- le porte sono Protocol e i fake le soddisfano --------------------------------------------


def test_every_fake_satisfies_its_port() -> None:
    assert isinstance(FakeEnrichmentFeeds(), EnrichmentFeeds)
    assert isinstance(InMemoryGitHistory(), GitHistory)
    assert isinstance(FakeBaselineSource(), BaselineSource)
    assert isinstance(InMemoryArtifactStore(), ArtifactStore)


def test_models_round_trip_through_json_so_a_step_can_become_an_activity() -> None:
    """ADR-0002: ingressi e uscite serializzabili."""
    for model in (
        EpssAnswer(status=FeedStatus.FOUND, score=0.5, percentile=0.9),
        KevAnswer(status=FeedStatus.FOUND, date_added=date(2026, 1, 2), ransomware_use="Known"),
        FeedSnapshot(
            feed="epss",
            origin="cache",
            downloaded_at=NOW,
            sha256=SHA,
            content={"score_date": "2026-11-13"},
        ),
        ChurnRequest(commit="abc1234", window_days=30),
        ChurnResult(
            status=HistoryStatus.COMPLETE,
            window_days=90,
            head_time=NOW,
            commits_read=4,
            files={"a.py": 2},
        ),
        ChangedFilesRequest(base="abc1234", head="def5678"),
        ChangedFilesResult(available=True, files=["a.py"]),
        BaselineLookup(
            outcome=BaselineOutcome.FOUND,
            location="/tmp/r.json",
            source=BaselineSourceKind.BASE_SCAN,
        ),
        StoredArtifact(key="t/scan/report.json", size=3, sha256=SHA),
    ):
        assert type(model).model_validate_json(model.model_dump_json()) == model


# --- feed: tre risposte, mai un valore inventato ----------------------------------------------


def test_the_three_answers_for_epss_and_kev() -> None:
    kev = KevAnswer(status=FeedStatus.FOUND, date_added=date(2026, 3, 4), ransomware_use="Unknown")
    feeds = FakeEnrichmentFeeds(epss={CVE: (0.25, 0.8)}, kev={CVE: kev})
    assert feeds.epss(CVE) == EpssAnswer(status=FeedStatus.FOUND, score=0.25, percentile=0.8)
    assert feeds.kev(CVE) == kev
    other = "CVE-2023-0001"
    assert (
        feeds.epss(other).status is FeedStatus.NOT_LISTED
        and feeds.kev(other).status is FeedStatus.NOT_LISTED
    )
    gone = FakeEnrichmentFeeds(epss={CVE: (0.25, 0.8)}, available=False)
    assert (
        gone.epss(CVE).status is FeedStatus.SNAPSHOT_ABSENT
        and gone.kev(CVE).status is FeedStatus.SNAPSHOT_ABSENT
    )
    assert gone.snapshots() == []


def test_a_cve_not_listed_is_not_an_unavailable_feed_and_has_no_score() -> None:
    answer = FakeEnrichmentFeeds().epss(CVE)
    assert (
        answer.status is FeedStatus.NOT_LISTED
        and answer.score is None
        and answer.percentile is None
    )


@pytest.mark.parametrize(
    "kwargs",
    [
        {"status": FeedStatus.FOUND},  # found senza punteggio
        {"status": FeedStatus.NOT_LISTED, "score": 0.1},
        {"status": FeedStatus.SNAPSHOT_ABSENT, "percentile": 0.1},
        {"status": FeedStatus.FOUND, "score": 1.5},
        {"status": FeedStatus.FOUND, "score": -0.1},
    ],
)
def test_an_epss_answer_cannot_carry_a_score_without_being_found_or_vice_versa(
    kwargs: dict,
) -> None:
    with pytest.raises(ValidationError):
        EpssAnswer(**kwargs)


def test_a_kev_answer_without_a_hit_has_no_values() -> None:
    with pytest.raises(ValidationError):
        KevAnswer(status=FeedStatus.NOT_LISTED, date_added=date(2026, 1, 1))
    with pytest.raises(ValidationError):
        KevAnswer(status=FeedStatus.FOUND, ransomware_use="Maybe")  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "cve", ["", "cve-2024-1", "CVE-24-1234", "CVE-2024-12", "GHSA-xxxx", "CVE-2024-12345\n"]
)
def test_a_malformed_cve_is_refused_before_any_lookup(cve: str) -> None:
    feeds = FakeEnrichmentFeeds()
    with pytest.raises(ValueError):
        feeds.epss(cve)
    with pytest.raises(ValueError):
        validate_cve(cve)
    assert feeds.queries == []


def test_snapshots_are_ordered_and_identify_the_content() -> None:
    kev = FeedSnapshot(
        feed="kev",
        origin="public",
        downloaded_at=NOW,
        sha256="b" * 64,
        content={"catalogVersion": "2026.11.10"},
    )
    epss = FeedSnapshot(
        feed="epss",
        origin="mirror",
        downloaded_at=NOW,
        sha256=SHA,
        content={"score_date": "2026-11-13"},
    )
    assert [s.feed for s in FakeEnrichmentFeeds(snapshots=[kev, epss]).snapshots()] == [
        "epss",
        "kev",
    ]
    for bad in ({"feed": "osv"}, {"origin": "https://x"}, {"sha256": "xyz"}):
        with pytest.raises(ValidationError):
            FeedSnapshot(
                **{"feed": "epss", "origin": "cache", "downloaded_at": NOW, "sha256": SHA, **bad}
            )


# --- storia git -------------------------------------------------------------------------------


def test_a_complete_history_gives_counts_and_the_commit_date_not_the_scan_date() -> None:
    history = InMemoryGitHistory({"a.py": 3, "b.py": 0}, head_time=NOW, commits_read=12)
    result = history.churn(ChurnRequest(window_days=30))
    assert (result.status, result.window_days, result.head_time, result.commits_read) == (
        HistoryStatus.COMPLETE,
        30,
        NOW,
        12,
    )
    assert result.files == {"a.py": 3, "b.py": 0}


@pytest.mark.parametrize("status", [HistoryStatus.SHALLOW, HistoryStatus.ABSENT])
def test_an_incomplete_history_never_gives_a_count(status: HistoryStatus) -> None:
    """ADR-0022: un conteggio su storia troncata direbbe «poco modificato» di ogni file."""
    result = InMemoryGitHistory({"a.py": 3}, status=status, commits_read=1).churn(ChurnRequest())
    assert result.files == {} and result.head_time is None and result.status is status
    with pytest.raises(ValidationError):
        ChurnResult(status=status, window_days=90, files={"a.py": 1})


def test_churn_request_and_result_limits() -> None:
    for bad in ({"window_days": 0}, {"window_days": 4000}, {"commit": "XYZ"}, {"commit": "abc"}):
        with pytest.raises(ValidationError):
            ChurnRequest(**bad)
    with pytest.raises(ValidationError):
        ChurnResult(status=HistoryStatus.COMPLETE, window_days=90, files={"a.py": -1})


def test_changed_files_are_sorted_and_unknown_pairs_are_unavailable() -> None:
    history = InMemoryGitHistory(changed={("abc1234", "def5678"): ["b.py", "a.py"]})
    assert history.changed_files(ChangedFilesRequest(base="abc1234", head="def5678")).files == [
        "a.py",
        "b.py",
    ]
    missing = history.changed_files(ChangedFilesRequest(base="abc1234", head="9999999"))
    assert missing.available is False and missing.files == []
    with pytest.raises(ValidationError):
        ChangedFilesResult(available=False, files=["a.py"])


# --- baseline ---------------------------------------------------------------------------------


def test_a_baseline_is_found_with_its_source_or_missing_without_one() -> None:
    source = FakeBaselineSource({"abc1234": "/ci/report.json"}, BaselineSourceKind.BASE_SCAN)
    found = source.find("abc1234")
    assert (found.outcome, found.location, found.source) == (
        BaselineOutcome.FOUND,
        "/ci/report.json",
        BaselineSourceKind.BASE_SCAN,
    )
    missing = source.find("0000000")
    assert (missing.outcome, missing.location, missing.source) == (
        BaselineOutcome.MISSING,
        None,
        None,
    )
    assert source.queries == ["abc1234", "0000000"]


@pytest.mark.parametrize(
    "kwargs",
    [
        {"outcome": BaselineOutcome.FOUND},
        {"outcome": BaselineOutcome.FOUND, "location": "/r.json"},
        {
            "outcome": BaselineOutcome.MISSING,
            "location": "/r.json",
            "source": BaselineSourceKind.SERVER,
        },
        {"outcome": BaselineOutcome.MISSING, "source": BaselineSourceKind.SERVER},
    ],
)
def test_a_baseline_lookup_must_be_coherent(kwargs: dict) -> None:
    with pytest.raises(ValidationError):
        BaselineLookup(**kwargs)


# --- archivio ---------------------------------------------------------------------------------


def put(store: InMemoryArtifactStore, key: str, data: bytes, **kw: object) -> StoredArtifact:
    return store.put(key, io.BytesIO(data), max_bytes=kw.pop("max_bytes", 1024), **kw)  # type: ignore[arg-type]


def test_put_then_open_returns_the_same_bytes_with_size_and_digest() -> None:
    store = InMemoryArtifactStore()
    stored = put(store, "t_0123/scan1/report.json", b"contenuto")
    assert (stored.size, stored.key) == (9, "t_0123/scan1/report.json") and len(stored.sha256) == 64
    with store.open("t_0123/scan1/report.json") as handle:
        assert handle.read() == b"contenuto"
    assert store.exists("t_0123/scan1/report.json") and not store.exists("t_0123/scan1/other")


def test_the_same_content_twice_is_a_repetition_and_different_content_is_a_conflict() -> None:
    store = InMemoryArtifactStore()
    first = put(store, "k/a", b"uno")
    assert put(store, "k/a", b"uno") == first
    with pytest.raises(ArtifactConflict):
        put(store, "k/a", b"due")
    assert store.objects["k/a"] == b"uno"  # il conflitto non ha toccato nulla


def test_a_declared_digest_is_checked_while_writing_and_nothing_is_stored_on_mismatch() -> None:
    import hashlib

    store = InMemoryArtifactStore()
    good = hashlib.sha256(b"dati").hexdigest()
    assert put(store, "k/ok", b"dati", sha256=good).sha256 == good
    with pytest.raises(ArtifactIntegrityError):
        put(store, "k/bad", b"dati", sha256="0" * 64)
    assert not store.exists("k/bad")


def test_a_stream_over_the_limit_is_refused_after_reading_at_most_limit_plus_one() -> None:
    store = InMemoryArtifactStore()

    class Counting(io.BytesIO):
        asked: list[int] = []

        def read(self, size: int | None = -1) -> bytes:
            self.asked.append(size if size is not None else -1)
            return super().read(size)

    stream = Counting(b"x" * 10_000)
    with pytest.raises(ArtifactTooLarge):
        store.put("k/big", stream, max_bytes=100)
    assert stream.asked == [101] and not store.exists("k/big")
    with pytest.raises(ValueError):
        store.put("k/zero", io.BytesIO(b""), max_bytes=0)


def test_missing_keys_and_idempotent_delete() -> None:
    store = InMemoryArtifactStore()
    with pytest.raises(ArtifactNotFound):
        store.open("k/none")
    store.delete("k/none")  # nessun errore
    put(store, "k/a", b"x")
    store.delete("k/a")
    store.delete("k/a")
    assert not store.exists("k/a")
    assert (
        put(store, "k/a", b"altro").size == 5
    )  # dopo la cancellazione la chiave e' di nuovo libera


@pytest.mark.parametrize(
    "key",
    [
        "",
        "/abs",
        "a//b",
        "a/./b",
        "a/../b",
        "../x",
        "a/b/",
        "a\\b",
        "a\x00b",
        "a b",
        "a/\n",
        "é/x",
        "x" * 129,
        "/".join("a" for _ in range(13)),
    ],
)
def test_keys_that_could_escape_or_confuse_an_adapter_are_refused_everywhere(key: str) -> None:
    store = InMemoryArtifactStore()
    with pytest.raises(ValueError):
        validate_artifact_key(key)
    for call in (
        lambda: put(store, key, b"x"),
        lambda: store.open(key),
        lambda: store.exists(key),
        lambda: store.delete(key),
    ):
        with pytest.raises(ValueError):
            call()
    assert store.objects == {}


@pytest.mark.parametrize(
    "key", ["a", "t_0123456789abcdef/scan-1/sbom.cdx.json", "a/b=c/d.e_f-g", "_x", "A1"]
)
def test_the_keys_the_server_builds_are_accepted(key: str) -> None:
    assert validate_artifact_key(key) == key
