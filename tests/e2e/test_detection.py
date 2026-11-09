"""T-05: E2E di rilevamento senza CVE. Parte di G1.c: nessun atteso mancante sulle tre fixture.

Un test per atteso (categorie secret, sast, iac, license) di python-app, js-ts-app e
secrets-history: l'esito di ciascuno e' la tabella di G1.c. Le scansioni sono quelle di
`conftest.py` (`code-analyzer scan --offline`, tutti i plugin, immagini firmate, feed congelati).
Le dipendenze (CVE) sono di `test_detection_cve.py` (T-08).
"""

from pathlib import Path
from typing import Any

import pytest

from .e2e_lab import REPOS, e2e_marks, needs_feeds
from .expectations import describe, load_expected, matching, near_misses

pytestmark = [*e2e_marks, needs_feeds]

FIXTURES = ("python-app", "js-ts-app", "secrets-history")
FIXTURE_SCAN = {
    "python-app": "python_scan",
    "js-ts-app": "jsts_scan",
    "secrets-history": "secrets_scan",
}


def entries(fixture: str) -> list[dict[str, Any]]:
    path = REPOS / fixture / "expected-findings.yaml"
    return [e for e in load_expected(path) if e["category"] != "dependency"]


LICENSE_LINES = pytest.mark.xfail(
    strict=True,
    reason="difetto del prodotto (o atteso troppo stretto, da decidere): il finding di licenza su "
    "file ha il percorso ma nessuna riga (`location.start_line` nullo, `tools` solo `ca-core`: "
    "ADR-0013 'finding su file'), mentre l'atteso chiede la riga che scancode trova. "
    "Rilevato per percorso e regola: vedi test_license_expectation_is_detected_by_path_and_rule.",
)


def lacks_lines_by_design(entry: dict[str, Any]) -> bool:
    return entry["category"] == "license" and "start_line" in entry


CASES = [
    pytest.param(
        f,
        e,
        id=f"{f}::{describe(e)}",
        marks=[LICENSE_LINES] if lacks_lines_by_design(e) else [],
    )
    for f in FIXTURES
    for e in entries(f)
]


@pytest.mark.parametrize(("fixture", "entry"), CASES)
def test_expected_finding_is_detected(
    fixture: str, entry: dict[str, Any], request: pytest.FixtureRequest
) -> None:
    scan = request.getfixturevalue(FIXTURE_SCAN[fixture])
    assert scan.result.returncode == 0, scan.result.stderr[-2000:]
    found = matching(entry, scan.findings)
    assert found, (
        f"atteso mancante {describe(entry)} tools={entry['tools']}; "
        f"stessa regola altrove: {near_misses(entry, scan.findings)}"
    )


@pytest.mark.parametrize(
    ("fixture", "entry"),
    [pytest.param(f, e, id=f"{f}::{describe(e)}") for f in FIXTURES for e in entries(f)
     if lacks_lines_by_design(e)],
)  # fmt: skip
def test_license_expectation_is_detected_by_path_and_rule(
    fixture: str, entry: dict[str, Any], request: pytest.FixtureRequest
) -> None:
    """Stessa prova senza le righe: la violazione di policy e' nel report, nel file giusto."""
    scan = request.getfixturevalue(FIXTURE_SCAN[fixture])
    found = matching(entry, scan.findings, ignore_lines=True)
    assert found and all(f["license_spdx"] == "AGPL-3.0-only" for f in found), found


@pytest.mark.parametrize("fixture", FIXTURES)
def test_every_plugin_ran_signed_and_the_scan_is_complete(
    fixture: str, request: pytest.FixtureRequest
) -> None:
    """Un atteso rilevato da un report parziale non basta come prova per G1.c."""
    scan = request.getfixturevalue(FIXTURE_SCAN[fixture])
    report = scan.report
    runs = {p["name"]: p for p in report["plugins"]}
    assert {"gitleaks", "osv-scanner", "scancode", "syft", "trivy"} <= set(runs)
    failed = {n: p["failure"] for n, p in runs.items() if p["outcome"] != "ok"}
    assert failed == {}, failed
    assert {p["signature"] for p in runs.values()} == {"verified"}
    assert report["status"] == "complete", report["warnings"]


def test_the_repository_fixtures_were_not_touched_by_the_scans() -> None:
    """Le scansioni lavorano su copie: la fixture nel repository resta com'e'."""
    for fixture in FIXTURES:
        assert not any((REPOS / fixture).rglob(".code-analyzer.yml"))
        assert not any(Path(REPOS / fixture).rglob("code-analyzer.report.json"))


def test_full_history_secret_in_head_is_a_single_finding_with_the_head_line_as_occurrence(
    secrets_scan: Any,
) -> None:
    """Stesso segreto nei commit 1 e 3 e HEAD: un finding, riga 6 tra le occorrenze (ADR-0008)."""
    found = [f for f in secrets_scan.findings if f["rule_id"] == "github-pat"]
    assert len(found) == 1
    lines = {o["start_line"] for o in found[0]["evidence"]["occurrences"]}
    assert lines == {3, 6}
    assert secrets_scan.report["repository"]["history"] == "full"


def test_shallow_clone_detects_only_the_secret_in_head(secrets_shallow_scan: Any) -> None:
    """Clone superficiale: resta il segreto in HEAD alla riga 6, quello solo nella storia no."""
    scan = secrets_shallow_scan
    assert scan.result.returncode == 0, scan.result.stderr[-2000:]
    secrets = {(f["rule_id"], f["location"]["path"], f["location"]["start_line"])
               for f in scan.findings if f["category"] == "secret"}  # fmt: skip
    assert secrets == {("github-pat", "app/settings.py", 6)}
    assert scan.report["repository"]["history"] == "shallow"


@pytest.mark.xfail(
    strict=True,
    reason="difetto del prodotto: l'avviso di gitleaks sulla copertura ridotta (clone "
    "superficiale) viaggia in `invocations` del suo SARIF e il nucleo non lo legge; il report ha "
    "solo `repository.history: shallow`, nessun `warnings[]` che avvisi chi legge il gate.",
)
def test_shallow_clone_reduced_coverage_is_a_report_warning(secrets_shallow_scan: Any) -> None:
    codes = {w["code"] for w in secrets_shallow_scan.report["warnings"]}
    assert any("shallow" in c or "history" in c or "coverage" in c for c in codes), sorted(codes)
