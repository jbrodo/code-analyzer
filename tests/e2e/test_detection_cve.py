"""T-08: E2E di rilevamento dei CVE con lo snapshot congelato e `--offline`. Chiude G1.c.

Tutti i CVE attesi di python-app e js-ts-app devono essere rilevati, e osv-scanner e trivy sullo
stesso CVE devono risultare un solo finding con entrambi in `tools` (fusione, ADR-0008). I feed
sono quelli di F-05 (`tests/fixtures/feeds`), montati in sola lettura da una cache per utente
costruita dal laboratorio; le scansioni sono quelle di `conftest.py` (le stesse di T-05).
"""

from pathlib import Path
from typing import Any

import pytest

from .e2e_lab import REPOS, Fleet, e2e_marks, needs_feeds
from .expectations import describe, load_expected, matching, near_misses

pytestmark = [*e2e_marks, needs_feeds]

FIXTURE_SCAN = {"python-app": "python_scan", "js-ts-app": "jsts_scan"}


def entries(fixture: str) -> list[dict[str, Any]]:
    path = REPOS / fixture / "expected-findings.yaml"
    return [e for e in load_expected(path) if e["category"] == "dependency"]


CASES = [pytest.param(f, e, id=f"{f}::{describe(e)}") for f in FIXTURE_SCAN for e in entries(f)]


@pytest.mark.parametrize(("fixture", "entry"), CASES)
def test_expected_cve_is_detected(
    fixture: str, entry: dict[str, Any], request: pytest.FixtureRequest
) -> None:
    scan = request.getfixturevalue(FIXTURE_SCAN[fixture])
    assert scan.result.returncode == 0, scan.result.stderr[-2000:]
    assert matching(entry, scan.findings), (
        f"CVE mancante {describe(entry)}; stesso CVE altrove: {near_misses(entry, scan.findings)}"
    )


@pytest.mark.parametrize(("fixture", "entry"), CASES)
def test_osv_scanner_and_trivy_on_the_same_cve_are_one_finding_with_both_tools(
    fixture: str, entry: dict[str, Any], request: pytest.FixtureRequest
) -> None:
    scan = request.getfixturevalue(FIXTURE_SCAN[fixture])
    found = [f for f in scan.findings if entry["cve"] in f["cve"] and f["category"] == "dependency"]
    assert len(found) == 1, [(f["rule_id"], f["tools"], f["location"].get("purl")) for f in found]
    assert {"osv-scanner", "trivy"} <= set(found[0]["tools"]), found[0]["tools"]
    assert found[0]["tool"] == min(found[0]["tools"])


@pytest.mark.parametrize("fixture", list(FIXTURE_SCAN))
def test_feed_plugins_ran_offline_on_the_frozen_snapshot(
    fixture: str, request: pytest.FixtureRequest
) -> None:
    scan = request.getfixturevalue(FIXTURE_SCAN[fixture])
    runs = {p["name"]: p for p in scan.report["plugins"]}
    for name in ("osv-scanner", "trivy"):
        run = runs[name]
        assert run["outcome"] == "ok", run["failure"]
        assert run["feed"]["sync_failed"] is False and run["feed"]["origin"] == "public"
    codes = {w["code"] for w in scan.report["warnings"]}
    assert "feeds-sync-failed" not in codes
    failed = [(n, r["failure"]) for n, r in runs.items() if r["outcome"] != "ok"]
    assert scan.report["status"] == "complete", (failed, sorted(codes))


def test_offline_without_any_snapshot_fails_the_feed_plugins_without_starting_them(
    fleet: Fleet, feeds_cache: Path, tmp_path: Path
) -> None:
    """L-07: `--offline` senza snapshot non scarica nulla: i plugin falliscono, report parziale."""
    fleet.add_builtin("osv-scanner")
    fleet.add_builtin("trivy")
    root = tmp_path / "repo"
    (root / "x").mkdir(parents=True)
    (root / "package-lock.json").write_text('{"lockfileVersion": 3, "packages": {}}')
    out = tmp_path / "out"
    empty = tmp_path / "empty-cache"
    done = fleet.scan(root, out, "--offline", plugins=["osv-scanner", "trivy"], feeds_cache=empty)
    assert done.returncode == 0, done.stderr[-2000:]
    report = done.report
    assert report["status"] == "partial"
    failures = {p["name"]: p["failure"] for p in report["plugins"]}
    assert all("offline" in (text or "") for text in failures.values()), failures
    assert fleet.run(tmp_path, "gate", "--report", str(out / "code-analyzer.report.json"),
                     plugins=["trivy"]).returncode == 2  # fmt: skip
    assert not feeds_cache.samefile(empty)
