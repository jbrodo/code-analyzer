"""E-04: origine dei feed da flag, ambiente o pacchetto, mai dal repository. Nessuna rete."""

import re
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError
from test_cli_scan_gate import FEEDS, Env, SyncingExecutor, load, manifest
from test_feeds import MANIFEST, SyncStub, good
from test_runner_r09 import calls, executor, feeds_manifest

from ca_core.fakes import FixedClock
from ca_core.ports import FeedsSyncRequest, RunOutcome
from ca_plugins import enrichment, origins, runner
from ca_plugins.feeds import POINTER, ensure_snapshot

ROOT = Path(__file__).resolve().parents[2]
MIRROR = "https://mirror.example/osv"
ARGS = (f"--base-url={MIRROR}",)


def test_without_flags_or_environment_the_package_origins_are_used() -> None:
    chosen = origins.resolve_origins((), {})
    assert chosen == origins.FeedOrigins()
    assert chosen.sync_args("osv-scanner") == chosen.sync_args("trivy") == ()


def test_every_feed_can_come_from_the_environment() -> None:
    checks = "localhost:5000/aquasec/trivy-checks@sha256:" + "a" * 64
    chosen = origins.resolve_origins(
        (),
        {
            "CA_FEEDS_EPSS_URL": "https://m.example/e.gz",
            "CA_FEEDS_KEV_URL": "https://m.example/k.json",
            "CA_FEEDS_OSV_URL": MIRROR + "/",
            "CA_FEEDS_TRIVY_DB": "registry.example:5000/aquasec/trivy-db:2",
            "CA_FEEDS_TRIVY_CHECKS": checks,
        },
    )
    assert chosen.enrichment.epss_url == "https://m.example/e.gz"
    assert chosen.sync_args("osv-scanner") == ARGS
    assert chosen.sync_args("trivy") == (
        "--db-repository=registry.example:5000/aquasec/trivy-db:2",
        f"--checks-bundle-repository={checks}",
    )
    assert chosen.sync_args("syft") == ()


def test_a_flag_wins_over_the_environment_and_leaves_the_others() -> None:
    env = {"CA_FEEDS_OSV_URL": "https://env.example/osv", "CA_FEEDS_TRIVY_DB": "r.example/db:2"}
    chosen = origins.resolve_origins([f"osv={MIRROR}"], env)
    assert chosen.osv_url == MIRROR and chosen.trivy_db == "r.example/db:2"


def test_the_public_osv_address_is_not_a_mirror_and_matches_the_adapter() -> None:
    adapter = ROOT / "packages/ca-plugins/src/ca_plugins/builtin/osv_scanner"
    source = (adapter / "osv_scanner_adapter.py").read_text()
    declared = re.search(r'^BASE_URL = "(.+)"$', source, re.M)
    assert declared is not None and declared[1] == origins.PUBLIC_OSV
    assert origins.resolve_origins([f"osv={origins.PUBLIC_OSV}/"], {}).osv_url is None


@pytest.mark.parametrize(
    ("name", "value"),
    [
        ("epss", "http://m.example/e"),
        ("kev", "https://user:segreto@m.example/k"),
        ("osv", "file:///etc/passwd"),
        ("osv", "https://m.example/osv?token=segreto"),
        ("osv", "https://m.example/a b"),
        ("trivy-db", "https://m.example/db:2"),
        ("trivy-db", "user:segreto@m.example/db:2"),
        ("trivy-db", "--insecure"),
        ("trivy-db", "m.example/db:2,evil.example/db:2"),
        ("trivy-checks", "senza-percorso"),
    ],
)
def test_a_bad_origin_stops_without_repeating_the_value(name: str, value: str) -> None:
    for flags, env in (([f"{name}={value}"], {}), ([], {origins.ENVIRONMENT[name]: value})):
        with pytest.raises(origins.OriginError) as caught:
            origins.resolve_origins(flags, env)
        assert value not in str(caught.value) and name in str(caught.value)


@pytest.mark.parametrize(
    "flags", [["nvd=https://m.example"], ["osv"], ["osv="], [f"osv={MIRROR}", f"osv={MIRROR}"]]
)
def test_a_malformed_flag_is_an_error(flags: list[str]) -> None:
    with pytest.raises(origins.OriginError):
        origins.resolve_origins(flags, {})


def test_an_unknown_name_is_not_repeated_because_it_may_be_a_value() -> None:
    with pytest.raises(origins.OriginError) as caught:
        origins.resolve_origins(["https://user:segreto@m.example"], {})
    assert "segreto" not in str(caught.value)


def test_a_new_origin_makes_the_snapshot_stale_and_is_labelled(tmp_path: Path) -> None:
    clock, ex = FixedClock(), SyncStub(good)
    other = ("--base-url=https://b.example",)
    outcomes = [
        ensure_snapshot(MANIFEST, ex, tmp_path, clock, origin_args=args)
        for args in ((), ARGS, ARGS, other)
    ]
    assert [r.origin_args for r in ex.syncs] == [(), ARGS, other]
    assert [o.feed.origin for o in outcomes if o.feed] == ["public", "mirror", "mirror", "mirror"]
    assert "example" not in (tmp_path / "osv-scanner" / POINTER).read_text()


def test_a_fallback_keeps_the_label_of_where_the_data_came_from(tmp_path: Path) -> None:
    clock = FixedClock()
    ensure_snapshot(MANIFEST, SyncStub(good), tmp_path, clock)
    failing = SyncStub(None, RunOutcome.FAILED)
    failed = ensure_snapshot(MANIFEST, failing, tmp_path, clock, origin_args=ARGS)
    offline = ensure_snapshot(MANIFEST, failing, tmp_path, clock, offline=True, origin_args=ARGS)
    assert failed.feed and failed.feed.origin == "public" and failed.feed.sync_failed
    assert [w.code for w in failed.warnings] == ["feeds-sync-failed"]
    assert offline.feed and offline.feed.origin == "public"
    assert [w.code for w in offline.warnings] == ["feeds-stale"]


def test_a_pointer_written_before_this_change_counts_as_public(tmp_path: Path) -> None:
    clock, ex = FixedClock(), SyncStub(good)
    ensure_snapshot(MANIFEST, ex, tmp_path, clock)
    path = tmp_path / "osv-scanner" / POINTER
    old = path.read_text().replace(',"origin":"public","origin_key":""', "")
    assert "origin" not in old
    path.write_text(old)
    again = ensure_snapshot(MANIFEST, ex, tmp_path, clock)
    assert len(ex.syncs) == 1 and again.feed and again.feed.origin == "public"


@pytest.mark.parametrize("bad", [("sync",), ("--a=b c",), ("--a",), ("--a=b",) * 5])
def test_the_sync_request_only_takes_a_few_options(bad: tuple[str, ...]) -> None:
    with pytest.raises(ValidationError):
        FeedsSyncRequest(manifest=MANIFEST, snapshot_dir="/s", max_bytes=1, origin_args=bad)


def test_the_runner_appends_the_options_to_the_sync_command(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(runner, "FEEDS_MIN_FREE_BYTES", 0)
    snap = tmp_path / "snap"
    snap.mkdir()
    request = FeedsSyncRequest(
        manifest=feeds_manifest(), snapshot_dir=str(snap), max_bytes=4096, origin_args=ARGS
    )
    with executor(tmp_path, out={"wait": ""}) as ex:
        ex.sync_feeds(request)
    (create,) = (c for c in calls(tmp_path) if c[0] == "create")
    assert create[-1] == ARGS[0]


def scan_with_feeds(tmp_path: Path, *flags: str) -> tuple[int, Any, Env]:
    env = Env(tmp_path)
    ex = SyncingExecutor({"osv-scanner": env.ok()})
    code = env.scan(env.context(ex, [manifest("osv-scanner", feeds=FEEDS)]), *flags)
    return code, ex, env


@pytest.fixture(autouse=True)
def clean_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in origins.ENVIRONMENT.values():
        monkeypatch.delenv(name, raising=False)


def test_scan_passes_the_flag_to_the_sync_and_reports_only_a_label(tmp_path: Path) -> None:
    code, ex, env = scan_with_feeds(tmp_path, "--feed-origin", f"osv={MIRROR}")
    assert code == 0 and [r.origin_args for r in ex.syncs] == [ARGS]
    report = load(env)
    plugin = next(p for p in report["plugins"] if p["name"] == "osv-scanner")
    assert plugin["feed"]["origin"] == "mirror"
    assert "mirror.example" not in (env.out / "code-analyzer.report.json").read_text()


def test_the_scanned_repository_cannot_choose_an_origin(tmp_path: Path) -> None:
    env = Env(tmp_path)
    (env.repo / ".code-analyzer.yml").write_text(f"version: 1\nfeeds:\n  osv: {MIRROR}\n")
    ex = SyncingExecutor({"osv-scanner": env.ok()})
    code = env.scan(env.context(ex, [manifest("osv-scanner", feeds=FEEDS)]))
    assert code == 2 and ex.syncs == []  # chiave sconosciuta: la configurazione è rifiutata


def test_scan_stops_before_any_download_on_a_bad_origin(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    code, ex, env = scan_with_feeds(tmp_path, "--feed-origin", "osv=http://user:segreto@m.example")
    assert code == 2 and ex.syncs == [] and not env.out.exists()
    printed = capsys.readouterr()
    assert "segreto" not in printed.out + printed.err


def test_two_mirrors_have_different_cache_keys() -> None:
    first = enrichment.Origin(kev_url="https://a.example/k").key("kev")
    assert first != enrichment.Origin(kev_url="https://b.example/k").key("kev")
