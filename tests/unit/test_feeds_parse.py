"""E-01: lettura difensiva di EPSS e KEV, porta in memoria (ADR-0024). Nessuna rete."""

import json
from datetime import UTC, date, datetime

import pytest

from ca_core.models.scan_report import EnrichmentSnapshot
from ca_core.ports import EnrichmentFeeds, FeedStatus
from ca_core.scoring.feeds.limits import EpssLimits, FeedLimits, KevLimits, load_limits
from ca_core.scoring.feeds.parse import (
    EpssTable,
    FeedRejected,
    KevTable,
    parse_epss,
    parse_kev,
    plausible,
)
from ca_core.scoring.feeds.snapshot import SnapshotFeeds

HEAD = "#model_version:v2026.06.15,score_date:2026-11-13T12:03:22Z\ncve,epss,percentile\n"
EPSS = EpssLimits(
    max_download_bytes=10_000, max_decompressed_bytes=10_000, min_entries=2, max_entries=5
)
KEV = KevLimits(max_download_bytes=10_000, min_entries=1, max_entries=3)


def epss(body: str, head: str = HEAD, limits: EpssLimits = EPSS) -> EpssTable:
    return parse_epss((head + body).encode(), limits)


def kev(items: list[dict], **top: object) -> bytes:
    document = {"catalogVersion": "2026.11.13", "dateReleased": "2026-11-13T20:24:18.3008Z"}
    document |= {"vulnerabilities": items, **top}
    return json.dumps(document).encode()


def item(cve: str = "CVE-2024-0001", **kv: object) -> dict:
    return {
        "cveID": cve,
        "dateAdded": "2024-02-01",
        "knownRansomwareCampaignUse": "Unknown",
        "shortDescription": "descrizione che non deve entrare in nessun report",
        **kv,
    }


# --- EPSS --------------------------------------------------------------------------------------


def test_epss_is_read_with_its_identity() -> None:
    table = epss("CVE-2024-0001,0.5,0.9\nCVE-2024-0002,0.01,0.1\n")
    assert table.entries == {"CVE-2024-0001": (0.5, 0.9), "CVE-2024-0002": (0.01, 0.1)}
    assert table.model_version == "v2026.06.15"
    assert table.score_date == datetime(2026, 11, 13, 12, 3, 22, tzinfo=UTC)
    assert table.identity() == {
        "model_version": "v2026.06.15",
        "score_date": "2026-11-13T12:03:22Z",
    }


@pytest.mark.parametrize(
    ("body", "code"),
    [
        ("CVE-2024-0001,0.5\nCVE-2024-0002,0.1,0.1\n", "epss-row"),
        ("CVE-2024-0001,0.5,0.9,extra\nCVE-2024-0002,0.1,0.1\n", "epss-row"),
        ("CVE-24-1,0.5,0.9\nCVE-2024-0002,0.1,0.1\n", "epss-cve"),
        ("cve-2024-0001,0.5,0.9\nCVE-2024-0002,0.1,0.1\n", "epss-cve"),
        ("CVE-2024-0001,1.5,0.9\nCVE-2024-0002,0.1,0.1\n", "epss-range"),
        ("CVE-2024-0001,-0.1,0.9\nCVE-2024-0002,0.1,0.1\n", "epss-range"),
        ("CVE-2024-0001,nan,0.9\nCVE-2024-0002,0.1,0.1\n", "epss-range"),
        ("CVE-2024-0001,inf,0.9\nCVE-2024-0002,0.1,0.1\n", "epss-range"),
        ("CVE-2024-0001,abc,0.9\nCVE-2024-0002,0.1,0.1\n", "epss-number"),
        ("CVE-2024-0001,0.5,0.9\nCVE-2024-0001,0.1,0.1\n", "epss-duplicate"),
        ("CVE-2024-0001,0.5,0.9\n", "epss-too-few"),
        ("".join(f"CVE-2024-{i:04d},0.1,0.1\n" for i in range(6)), "epss-too-many"),
    ],
)
def test_epss_rows_are_validated(body: str, code: str) -> None:
    with pytest.raises(FeedRejected, match=code):
        epss(body)


@pytest.mark.parametrize(
    "head",
    [
        "",
        "cve,epss,percentile\n",
        "#model_version:v1,score_date:2026-11-13\ncve,epss,percentile\n",
        "#model_version:v1,score_date:2026-13-45T00:00:00Z\ncve,epss,percentile\n",
        "#model_version:v1,score_date:2026-11-13T12:03:22Z\ncve,score,percentile\n",
        "#model_version:<script>,score_date:2026-11-13T12:03:22Z\ncve,epss,percentile\n",
    ],
)
def test_epss_header_is_validated(head: str) -> None:
    with pytest.raises(FeedRejected, match="epss-shape"):
        epss("CVE-2024-0001,0.5,0.9\nCVE-2024-0002,0.1,0.1\n", head=head)


def test_epss_rejects_non_ascii_and_oversize_without_echoing_content() -> None:
    with pytest.raises(FeedRejected, match="epss-encoding"):
        parse_epss((HEAD + "CVE-2024-0001,0.5,0.9\nCVE-2024-0002,0.1,0.1é\n").encode(), EPSS)
    big = EpssLimits(max_download_bytes=1, max_decompressed_bytes=50, min_entries=0, max_entries=9)
    with pytest.raises(FeedRejected, match="epss-too-large") as caught:
        parse_epss(HEAD.encode() * 3, big)
    assert "model_version" not in str(caught.value)


# --- KEV ---------------------------------------------------------------------------------------


def test_kev_keeps_only_the_three_fields_it_needs() -> None:
    table = parse_kev(kev([item(), item("CVE-2024-0002", knownRansomwareCampaignUse="Known")]), KEV)
    assert table.entries == {
        "CVE-2024-0001": (date(2024, 2, 1), "Unknown"),
        "CVE-2024-0002": (date(2024, 2, 1), "Known"),
    }
    assert table.catalog_version == "2026.11.13"
    assert table.identity()["date_released"] == "2026-11-13T20:24:18Z"
    assert "descrizione" not in repr(table)  # il testo di KEV non entra mai


@pytest.mark.parametrize(
    ("raw", "code"),
    [
        (b"{", "kev-json"),
        (b"[]", "kev-shape"),
        (kev([item()], catalogVersion=5), "kev-version"),
        (kev([item()], catalogVersion="<b>"), "kev-version"),
        (kev([item()], dateReleased="ieri"), "kev-date"),
        (kev([item()], dateReleased="2026-11-13T20:24:18"), "kev-date"),
        (kev([item()], vulnerabilities="x"), "kev-shape"),
        (kev(["x"]), "kev-row"),
        (kev([item("not-a-cve")]), "kev-row"),
        (kev([{"cveID": "CVE-2024-0001"}]), "kev-row"),
        (kev([item(dateAdded="2024-13-01")]), "kev-row"),
        (kev([item(knownRansomwareCampaignUse="Maybe")]), "kev-row"),
        (kev([item(), item()]), "kev-duplicate"),
        (kev([]), "kev-too-few"),
        (kev([item(f"CVE-2024-{i:04d}") for i in range(4)]), "kev-too-many"),
    ],
)
def test_kev_is_validated(raw: bytes, code: str) -> None:
    with pytest.raises(FeedRejected, match=code):
        parse_kev(raw, KEV)


def test_kev_over_the_size_limit_is_rejected() -> None:
    tiny = KevLimits(max_download_bytes=10, min_entries=0, max_entries=3)
    with pytest.raises(FeedRejected, match="kev-too-large"):
        parse_kev(kev([item()]), tiny)


def test_deeply_nested_json_is_rejected_not_a_crash() -> None:
    with pytest.raises(FeedRejected, match="kev-json"):
        parse_kev(b"[" * 9_000, KEV)


# --- plausibilità e limiti ----------------------------------------------------------------------


@pytest.mark.parametrize(
    ("new", "previous", "ok"),
    [(100, None, True), (100, 0, True), (80, 100, True), (79, 100, False), (200, 100, True)],
)
def test_a_drop_over_the_threshold_is_not_plausible(
    new: int, previous: int | None, ok: bool
) -> None:
    assert plausible(new, previous, 20) is ok


def test_packaged_limits_are_the_adr_values_and_closed() -> None:
    limits = load_limits()
    assert limits.epss.max_download_bytes == 32 * 1024**2
    assert limits.epss.max_decompressed_bytes == 128 * 1024**2
    assert (limits.epss.min_entries, limits.kev.min_entries) == (100_000, 500)
    assert (limits.max_drop_percent, limits.max_age_hours) == (20, 24)
    with pytest.raises(ValueError):
        FeedLimits.model_validate({**limits.model_dump(), "extra": 1})


# --- la porta ------------------------------------------------------------------------------------


def snapshot(feed: str) -> EnrichmentSnapshot:
    return EnrichmentSnapshot(
        feed=feed,  # type: ignore[arg-type]
        origin="public",
        downloaded_at=datetime(2026, 11, 17, tzinfo=UTC),
        sha256="a" * 64,
        content={"k": "v"},
    )


def test_the_three_answers_never_blur() -> None:
    feeds = SnapshotFeeds(
        epss("CVE-2024-0001,0.5,0.9\nCVE-2024-0002,0.1,0.1\n"),
        parse_kev(kev([item()]), KEV),
        [snapshot("kev"), snapshot("epss")],
    )
    assert isinstance(feeds, EnrichmentFeeds)
    found = feeds.epss("CVE-2024-0001")
    assert (found.status, found.score, found.percentile) == (FeedStatus.FOUND, 0.5, 0.9)
    assert feeds.epss("CVE-2023-9999").status is FeedStatus.NOT_LISTED
    assert feeds.kev("CVE-2024-0001").status is FeedStatus.FOUND
    assert feeds.kev("CVE-2024-0001").ransomware_use == "Unknown"
    assert feeds.kev("CVE-2023-9999").status is FeedStatus.NOT_LISTED
    assert [s.feed for s in feeds.snapshots()] == ["epss", "kev"]


def test_a_missing_table_is_snapshot_absent_not_not_listed() -> None:
    feeds = SnapshotFeeds()
    assert feeds.epss("CVE-2024-0001").status is FeedStatus.SNAPSHOT_ABSENT
    assert feeds.kev("CVE-2024-0001").status is FeedStatus.SNAPSHOT_ABSENT
    assert feeds.snapshots() == []


def test_a_malformed_cve_in_a_query_is_an_error() -> None:
    with pytest.raises(ValueError):
        SnapshotFeeds().epss("not-a-cve")


def test_kev_with_a_null_ransomware_field_answers_none() -> None:
    table = KevTable(
        "v", datetime(2026, 1, 1, tzinfo=UTC), {"CVE-2024-0001": (date(2024, 1, 1), None)}
    )
    assert SnapshotFeeds(kev=table).kev("CVE-2024-0001").ransomware_use is None
