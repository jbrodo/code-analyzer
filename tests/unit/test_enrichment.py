"""E-02, E-03: scaricamento, cache e lettura difensiva di EPSS e KEV. Nessuna rete esterna."""

import gzip
import hashlib
import json
import os
import threading
from collections.abc import Iterator
from datetime import UTC, datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from ca_core.fakes import FixedClock
from ca_core.ports import FeedStatus
from ca_core.scoring.feeds.limits import EpssLimits, FeedLimits, KevLimits
from ca_plugins import enrichment as en

T0 = datetime(2026, 11, 17, 12, 0, tzinfo=UTC)
LIMITS = FeedLimits(
    version=1,
    epss=EpssLimits(
        max_download_bytes=100_000,
        max_decompressed_bytes=200_000,
        min_entries=2,
        max_entries=50,
    ),
    kev=KevLimits(max_download_bytes=100_000, min_entries=1, max_entries=50),
    max_drop_percent=20,
    max_age_hours=24,
)


def epss_file(n: int = 3, date: str = "2026-11-17") -> bytes:
    rows = "".join(f"CVE-2024-{i:04d},0.{i + 1},0.5\n" for i in range(n))
    head = f"#model_version:v2026.06.15,score_date:{date}T12:03:22Z\ncve,epss,percentile\n"
    return (head + rows).encode()


def kev_file(n: int = 2, released: str = "2026-11-13", start: int = 0) -> bytes:
    items = [
        {"cveID": f"CVE-2023-{i:04d}", "dateAdded": "2024-01-01",
         "knownRansomwareCampaignUse": "Unknown"}
        for i in range(start, start + n)
    ]  # fmt: skip
    return json.dumps(
        {
            "catalogVersion": released.replace("-", "."),
            "dateReleased": f"{released}T00:00:00Z",
            "vulnerabilities": items,
        }
    ).encode()


class FakeFetcher:
    def __init__(self, epss: bytes | Exception = b"", kev: bytes | Exception = b"") -> None:
        self.responses = {en.PUBLIC_EPSS: epss, en.PUBLIC_KEV: kev}
        self.calls: list[str] = []

    def fetch(self, url: str, *, max_bytes: int, gzip: bool, max_decompressed: int) -> bytes:
        self.calls.append(url)
        value = self.responses[url]
        if isinstance(value, Exception):
            raise value
        return value


@pytest.fixture
def cache(tmp_path: Path) -> Path:
    return tmp_path / "enrichment"


def load(cache: Path, fetcher: FakeFetcher, clock: FixedClock, **kv: object) -> en.EnrichmentResult:
    return en.load_enrichment(cache, fetcher, clock, limits=LIMITS, **kv)  # type: ignore[arg-type]


def codes(result: en.EnrichmentResult) -> list[tuple[str, str | None]]:
    return [(w.code, w.subject) for w in result.warnings]


# --- sincronizzazione e cache -------------------------------------------------------------------


def test_first_run_downloads_validates_and_answers(cache: Path) -> None:
    fetcher = FakeFetcher(epss_file(), kev_file())
    result = load(cache, fetcher, FixedClock(T0))
    assert result.warnings == [] and sorted(fetcher.calls) == sorted(
        [en.PUBLIC_EPSS, en.PUBLIC_KEV]
    )
    assert result.feeds.epss("CVE-2024-0001").status is FeedStatus.FOUND
    assert result.feeds.kev("CVE-2023-0001").status is FeedStatus.FOUND
    assert result.feeds.epss("CVE-2020-9999").status is FeedStatus.NOT_LISTED
    snaps = {s.feed: s for s in result.feeds.snapshots()}
    assert snaps["epss"].origin == "public" and snaps["epss"].downloaded_at == T0
    assert snaps["epss"].sha256 == hashlib.sha256(epss_file()).hexdigest()
    assert snaps["epss"].content["score_date"] == "2026-11-17T12:03:22Z"
    assert snaps["kev"].content["catalog_version"] == "2026.11.13"


def test_a_fresh_cache_is_used_without_the_network(cache: Path) -> None:
    clock = FixedClock(T0)
    load(cache, FakeFetcher(epss_file(), kev_file()), clock)
    clock.advance(23 * 3600)
    second = FakeFetcher(OSError("non deve scaricare"), OSError("non deve scaricare"))
    result = load(cache, second, clock)
    assert second.calls == [] and result.warnings == []
    assert result.feeds.epss("CVE-2024-0001").status is FeedStatus.FOUND


def test_an_old_cache_is_synced_again_and_the_old_snapshot_is_pruned(cache: Path) -> None:
    clock = FixedClock(T0)
    load(cache, FakeFetcher(epss_file(3), kev_file()), clock)
    clock.advance(25 * 3600)
    fetcher = FakeFetcher(epss_file(4, date="2026-11-18"), kev_file())
    result = load(cache, fetcher, clock)
    assert len(fetcher.calls) == 2 and result.warnings == []
    assert result.feeds.epss("CVE-2024-0003").status is FeedStatus.FOUND
    assert len([p for p in (cache / "epss").iterdir() if p.name.startswith("snap-")]) == 1


def test_offline_uses_an_old_snapshot_and_says_so(cache: Path) -> None:
    clock = FixedClock(T0)
    load(cache, FakeFetcher(epss_file(), kev_file()), clock)
    clock.advance(30 * 24 * 3600)
    fetcher = FakeFetcher(OSError("no"), OSError("no"))
    result = load(cache, fetcher, clock, offline=True)
    assert fetcher.calls == []
    assert codes(result) == [("feeds-stale", "epss"), ("feeds-stale", "kev")]
    assert result.feeds.epss("CVE-2024-0001").status is FeedStatus.FOUND


def test_offline_without_a_snapshot_is_snapshot_absent_with_a_warning(cache: Path) -> None:
    fetcher = FakeFetcher()
    result = load(cache, fetcher, FixedClock(T0), offline=True)
    assert fetcher.calls == []
    assert codes(result) == [
        ("enrichment-feed-missing", "epss"),
        ("enrichment-feed-missing", "kev"),
    ]
    assert result.feeds.epss("CVE-2024-0001").status is FeedStatus.SNAPSHOT_ABSENT
    assert result.feeds.kev("CVE-2023-0001").status is FeedStatus.SNAPSHOT_ABSENT
    assert result.feeds.snapshots() == []


def test_a_failed_sync_keeps_the_previous_snapshot_with_a_warning(cache: Path) -> None:
    clock = FixedClock(T0)
    load(cache, FakeFetcher(epss_file(), kev_file()), clock)
    clock.advance(2 * 24 * 3600)
    result = load(cache, FakeFetcher(en.FetchError("network"), kev_file()), clock)
    assert codes(result) == [("feeds-sync-failed", "epss")]
    assert result.feeds.epss("CVE-2024-0001").status is FeedStatus.FOUND
    assert result.feeds.snapshots()[0].downloaded_at == T0  # lo snapshot vecchio, non uno nuovo


def test_a_failed_first_sync_is_snapshot_absent_for_that_feed_only(cache: Path) -> None:
    result = load(cache, FakeFetcher(en.FetchError("network"), kev_file()), FixedClock(T0))
    assert codes(result) == [("enrichment-feed-missing", "epss")]
    assert result.feeds.epss("CVE-2024-0001").status is FeedStatus.SNAPSHOT_ABSENT
    assert result.feeds.kev("CVE-2023-0001").status is FeedStatus.FOUND


@pytest.mark.parametrize(
    "bad",
    [b"", b"<html>", epss_file(1), b"#model_version:v,score_date:x\n", epss_file(60)],
    ids=["empty", "html", "too-few", "bad-header", "too-many"],
)
def test_an_invalid_download_is_discarded_whole_and_the_pointer_stays(
    cache: Path, bad: bytes
) -> None:
    clock = FixedClock(T0)
    load(cache, FakeFetcher(epss_file(), kev_file()), clock)
    pointer = (cache / "epss" / en.POINTER).read_bytes()
    clock.advance(2 * 24 * 3600)
    result = load(cache, FakeFetcher(bad, kev_file()), clock)
    assert ("feeds-sync-failed", "epss") in codes(result)
    assert (cache / "epss" / en.POINTER).read_bytes() == pointer
    snaps = [p for p in (cache / "epss").iterdir() if p.name.startswith("snap-")]
    assert len(snaps) == 1  # nessuna cartella nuova rimasta


def test_a_big_drop_in_entries_is_rejected_as_implausible(cache: Path) -> None:
    clock = FixedClock(T0)
    load(cache, FakeFetcher(epss_file(10), kev_file()), clock)
    clock.advance(2 * 24 * 3600)
    result = load(cache, FakeFetcher(epss_file(7), kev_file()), clock)  # -30%
    assert ("feeds-sync-failed", "epss") in codes(result)
    assert result.feeds.epss("CVE-2024-0009").status is FeedStatus.FOUND  # resta il vecchio
    clock.advance(1)
    ok = load(cache, FakeFetcher(epss_file(9, date="2026-11-19"), kev_file()), clock)  # -10%
    assert ok.warnings == [] and ok.feeds.epss("CVE-2024-0008").status is FeedStatus.FOUND


def test_an_authentic_but_older_snapshot_is_not_an_update(cache: Path) -> None:
    """S5-M1: un file vecchio di mesi supera forma, dimensione e conteggio, ma non è più recente."""
    clock = FixedClock(T0)
    load(cache, FakeFetcher(epss_file(date="2026-11-17"), kev_file(released="2026-11-13")), clock)
    clock.advance(2 * 24 * 3600)
    old = FakeFetcher(epss_file(date="2026-06-01"), kev_file(released="2026-06-01"))
    result = load(cache, old, clock)
    assert {("feeds-sync-failed", "epss"), ("feeds-sync-failed", "kev")} <= set(codes(result))
    assert result.feeds.epss("CVE-2024-0001").status is FeedStatus.FOUND  # resta quello di prima


def test_a_kev_entry_that_disappears_is_an_anomaly_but_new_ones_are_welcome(cache: Path) -> None:
    """S5-M2: il catalogo cresce; una voce tolta (per far cadere l'override) non si accetta."""
    clock = FixedClock(T0)
    load(cache, FakeFetcher(epss_file(), kev_file(3)), clock)
    clock.advance(2 * 24 * 3600)
    dropped = kev_file(3, released="2026-11-17", start=1)  # CVE-2023-0000 sparita
    result = load(cache, FakeFetcher(epss_file(date="2026-11-19"), dropped), clock)
    assert ("feeds-sync-failed", "kev") in codes(result)
    assert result.feeds.kev("CVE-2023-0000").status is FeedStatus.FOUND
    clock.advance(1)
    grown = kev_file(4, released="2026-11-17")  # le tre di prima e una nuova
    ok = load(cache, FakeFetcher(epss_file(date="2026-11-19"), grown), clock)
    assert ("feeds-sync-failed", "kev") not in codes(ok)
    assert ok.feeds.kev("CVE-2023-0003").status is FeedStatus.FOUND


def test_a_custom_origin_is_labelled_mirror_never_with_its_url(cache: Path) -> None:
    fetcher = FakeFetcher(epss_file(), kev_file())
    fetcher.responses["https://mirror.example/e.csv.gz"] = epss_file()
    fetcher.responses["https://mirror.example/k.json"] = kev_file()
    origin = en.Origin("https://mirror.example/e.csv.gz", "https://mirror.example/k.json")
    result = load(cache, fetcher, FixedClock(T0), origin=origin)
    assert {s.origin for s in result.feeds.snapshots()} == {"mirror"}
    assert "mirror.example" not in json.dumps(
        [s.model_dump(mode="json") for s in result.feeds.snapshots()]
    )


def test_on_sync_reports_which_feeds_use_the_network(cache: Path) -> None:
    seen: list[str] = []
    load(cache, FakeFetcher(epss_file(), kev_file()), FixedClock(T0), on_sync=seen.append)
    assert seen == ["epss", "kev"]


# --- cache non fidata ----------------------------------------------------------------------------


def snapshot_file(cache: Path, feed: str) -> Path:
    pointer = json.loads((cache / feed / en.POINTER).read_text())
    return cache / feed / pointer["dir"] / en.DATA


def test_a_tampered_snapshot_file_is_treated_as_absent(cache: Path) -> None:
    clock = FixedClock(T0)
    load(cache, FakeFetcher(epss_file(), kev_file()), clock)
    snapshot_file(cache, "epss").write_bytes(epss_file(3).replace(b"0.1", b"0.9"))
    result = load(cache, FakeFetcher(OSError("no"), OSError("no")), clock, offline=True)
    assert ("enrichment-feed-missing", "epss") in codes(result)
    assert result.feeds.epss("CVE-2024-0000").status is FeedStatus.SNAPSHOT_ABSENT


def test_a_symlinked_pointer_or_data_file_is_not_followed(cache: Path, tmp_path: Path) -> None:
    clock = FixedClock(T0)
    load(cache, FakeFetcher(epss_file(), kev_file()), clock)
    real = snapshot_file(cache, "epss")
    outside = tmp_path / "outside"
    outside.write_bytes(real.read_bytes())
    real.unlink()
    real.symlink_to(outside)
    result = load(cache, FakeFetcher(OSError("x"), OSError("x")), clock, offline=True)
    assert result.feeds.epss("CVE-2024-0000").status is FeedStatus.SNAPSHOT_ABSENT
    pointer = cache / "kev" / en.POINTER
    saved = pointer.read_bytes()
    pointer.unlink()
    pointer.symlink_to(tmp_path / "elsewhere")
    (tmp_path / "elsewhere").write_bytes(saved)
    result = load(cache, FakeFetcher(OSError("x"), OSError("x")), clock, offline=True)
    assert result.feeds.kev("CVE-2023-0000").status is FeedStatus.SNAPSHOT_ABSENT


@pytest.mark.parametrize("pointer", [b"", b"{", b'{"dir": "../etc"}', b"[]", b"x" * 10_000])
def test_a_malformed_pointer_is_treated_as_absent(cache: Path, pointer: bytes) -> None:
    clock = FixedClock(T0)
    load(cache, FakeFetcher(epss_file(), kev_file()), clock)
    (cache / "epss" / en.POINTER).write_bytes(pointer)
    result = load(cache, FakeFetcher(OSError("x"), OSError("x")), clock, offline=True)
    assert result.feeds.epss("CVE-2024-0000").status is FeedStatus.SNAPSHOT_ABSENT


def test_a_pointer_to_a_directory_name_outside_the_pattern_is_refused(cache: Path) -> None:
    clock = FixedClock(T0)
    load(cache, FakeFetcher(epss_file(), kev_file()), clock)
    pointer = json.loads((cache / "epss" / en.POINTER).read_text())
    pointer["dir"] = "../kev"
    (cache / "epss" / en.POINTER).write_text(json.dumps(pointer))
    assert en._load_pointer(cache / "epss") is None


def test_a_cache_writable_by_others_is_an_environment_error(cache: Path) -> None:
    cache.mkdir(mode=0o700)
    cache.chmod(0o777)
    with pytest.raises(en.EnrichmentError):
        load(cache, FakeFetcher(epss_file(), kev_file()), FixedClock(T0))


def test_a_symlinked_cache_dir_is_refused(tmp_path: Path) -> None:
    real = tmp_path / "real"
    real.mkdir(mode=0o700)
    link = tmp_path / "link"
    link.symlink_to(real)
    with pytest.raises(en.EnrichmentError):
        load(link, FakeFetcher(epss_file(), kev_file()), FixedClock(T0))


def test_the_snapshot_symlink_left_in_the_cache_is_unlinked_never_followed(
    cache: Path, tmp_path: Path
) -> None:
    clock = FixedClock(T0)
    load(cache, FakeFetcher(epss_file(), kev_file()), clock)
    victim = tmp_path / "victim"
    victim.mkdir()
    (victim / "keep.txt").write_text("x")
    (cache / "epss" / "snap-AAAAAAAA").symlink_to(victim)
    clock.advance(2 * 24 * 3600)
    load(cache, FakeFetcher(epss_file(4, "2026-11-19"), kev_file()), clock)
    assert (victim / "keep.txt").exists() and not (cache / "epss" / "snap-AAAAAAAA").exists()


def test_the_cache_files_are_private(cache: Path) -> None:
    load(cache, FakeFetcher(epss_file(), kev_file()), FixedClock(T0))
    assert (cache.stat().st_mode & 0o077) == 0
    assert (cache / "epss").stat().st_mode & 0o022 == 0


# --- URL di origine ------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "url",
    [
        "http://example.org/x",
        "ftp://example.org/x",
        "https://user:pw@example.org/x",
        "https://example.org/x#frag",
        "https:///x",
        "file:///etc/passwd",
        "javascript:alert(1)",
    ],
)
def test_origin_urls_must_be_https_without_credentials(url: str) -> None:
    with pytest.raises(ValueError):
        en.check_url(url)


def test_loopback_http_is_allowed_only_when_asked() -> None:
    with pytest.raises(ValueError):
        en.check_url("http://127.0.0.1:1/x")
    assert en.check_url("http://127.0.0.1:1/x", allow_loopback_http=True)
    with pytest.raises(ValueError):
        en.check_url("http://example.org/x", allow_loopback_http=True)


# --- il fetcher vero contro un server locale ----------------------------------------------------


class Handler(BaseHTTPRequestHandler):
    routes: dict[str, tuple[int, dict[str, str], bytes]] = {}

    def log_message(self, *args: object) -> None:
        pass

    def do_GET(self) -> None:  # noqa: N802
        status, headers, body = self.routes.get(self.path, (404, {}, b""))
        self.send_response(status)
        for key, value in headers.items():
            self.send_header(key, value)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


@pytest.fixture
def server() -> Iterator[tuple[str, dict[str, tuple[int, dict[str, str], bytes]]]]:
    Handler.routes = {}
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    try:
        yield f"http://127.0.0.1:{httpd.server_port}", Handler.routes
    finally:
        httpd.shutdown()
        httpd.server_close()


def fetch(
    base: str, path: str, *, max_bytes: int = 10_000, gz: bool = False, cap: int = 10_000
) -> bytes:
    fetcher = en.UrllibFetcher(allow_loopback_http=True)
    return fetcher.fetch(base + path, max_bytes=max_bytes, gzip=gz, max_decompressed=cap)


def test_fetch_reads_plain_and_gzip_bodies(server: tuple) -> None:
    base, routes = server
    routes["/a"] = (200, {}, b"hello")
    routes["/g"] = (200, {}, gzip.compress(b"world" * 10))
    assert fetch(base, "/a") == b"hello"
    assert fetch(base, "/g", gz=True) == b"world" * 10


def test_fetch_follows_a_redirect_on_the_same_host_only(server: tuple) -> None:
    base, routes = server
    routes["/old"] = (302, {"Location": base + "/new"}, b"")
    routes["/new"] = (200, {}, b"ok")
    routes["/away"] = (302, {"Location": "http://localhost.invalid/new"}, b"")
    routes["/loop"] = (302, {"Location": base + "/loop"}, b"")
    assert fetch(base, "/old") == b"ok"
    for path in ("/away", "/loop"):
        with pytest.raises(en.FetchError):
            fetch(base, path)


def test_fetch_enforces_the_download_cap_while_reading(server: tuple) -> None:
    base, routes = server
    routes["/big"] = (200, {}, b"x" * 5_000)
    with pytest.raises(en.FetchError, match="too-large"):
        fetch(base, "/big", max_bytes=1_000)


def test_fetch_enforces_the_decompression_cap_against_a_gzip_bomb(server: tuple) -> None:
    base, routes = server
    routes["/bomb"] = (200, {}, gzip.compress(b"\0" * 5_000_000))
    assert len(routes["/bomb"][2]) < 10_000
    with pytest.raises(en.FetchError, match="too-large"):
        fetch(base, "/bomb", gz=True, cap=100_000)


@pytest.mark.parametrize(
    "body", [b"not gzip", gzip.compress(b"x" * 100)[:-5]], ids=["not-gzip", "truncated"]
)
def test_fetch_rejects_bad_or_truncated_gzip(server: tuple, body: bytes) -> None:
    base, routes = server
    routes["/g"] = (200, {}, body)
    with pytest.raises(en.FetchError):
        fetch(base, "/g", gz=True)


@pytest.mark.parametrize("status", [404, 500, 204])
def test_fetch_rejects_non_200(server: tuple, status: int) -> None:
    base, routes = server
    routes["/x"] = (status, {}, b"")
    with pytest.raises(en.FetchError):
        fetch(base, "/x")


def test_fetch_refuses_plain_http_unless_loopback_is_allowed() -> None:
    with pytest.raises(ValueError):
        en.UrllibFetcher().fetch(
            "http://127.0.0.1:1/x", max_bytes=1, gzip=False, max_decompressed=1
        )


def test_fetch_on_a_closed_port_is_a_fetch_error() -> None:
    with pytest.raises(en.FetchError):
        fetch("http://127.0.0.1:1", "/x")


def test_the_default_cache_dir_follows_xdg(tmp_path: Path) -> None:
    assert en.default_cache_dir({"XDG_CACHE_HOME": str(tmp_path)}) == (
        tmp_path / "code-analyzer" / "feeds" / "enrichment"
    )
    assert os.sep in str(en.default_cache_dir({}))


def test_each_feed_has_its_own_origin_label() -> None:
    assert [en.Origin().label(f) for f in en.FEEDS] == ["public", "public"]
    mixed = en.Origin(kev_url="https://mirror.example/k.json")
    assert [mixed.label(f) for f in en.FEEDS] == ["public", "mirror"]
    assert mixed.key("epss") == "" and len(mixed.key("kev")) == 64
    assert "mirror.example" not in mixed.key("kev")
