"""T-03: E2E di rilevamento della Fase 2 con le immagini firmate (qualità, IaC, grafo, copertura).

Come T-05: `code-analyzer scan --offline` vero, immagini costruite e firmate sul registry locale,
feed congelati per trivy, confronto automatico con gli attesi delle fixture.

- F-02 (`quality-python`, `quality-js-ts`, `iac-app`): un test per atteso, e i gruppi di
  correlazione di ADR-0026 per le voci di `iac-app` che portano `correlation`.
- F-01 (`graph-python`, `graph-js-ts`): archi e metriche del grafo pubblicato, e i finding di
  architettura per ogni smell atteso. Il prodotto usa le soglie predefinite, senza la guardia sul
  grado degli hub (ADR-0020): gli hub in più non sono un errore, i negativi di cicli e dipendenze
  instabili sì.
- F-03 (copertura): ogni report valido si legge, ogni report ostile è rifiutato senza effetti. I
  report della fixture hanno meno righe della soglia di segnalazione del plugin, quindi il
  rilevamento di un file poco coperto si prova con un report generato qui.
"""

import json
from pathlib import Path
from typing import Any

import pytest
import yaml

from .conftest import DURATIONS, Scan
from .e2e_lab import REPOS, Fleet, copy_fixture, e2e_marks, needs_feeds
from .expectations import describe, load_expected, matching, near_misses

pytestmark = [*e2e_marks, needs_feeds]

COVERAGE = REPOS.parent / "coverage"
PLUGINS = ["ca-graph", "checkov", "eslint", "hadolint", "ruff", "trivy"]
# I plugin che devono aver girato: gli altri possono essere saltati per linguaggio.
MUST_RUN = {
    "quality-python": {"ruff", "ca-graph"},
    "quality-js-ts": {"eslint", "ca-graph"},
    "iac-app": {"checkov", "hadolint", "trivy"},
    "graph-python": {"ca-graph"},
    "graph-js-ts": {"ca-graph"},
}
F02 = ("quality-python", "quality-js-ts", "iac-app")
GRAPHS = ("graph-python", "graph-js-ts")
CYCLE = "ca.arch.cyclic-dependency"
HUB = "ca.arch.hub-like-dependency"
UNSTABLE = "ca.arch.unstable-dependency"


@pytest.fixture(scope="module")
def scans(fleet: Fleet, feeds_cache: Path, tmp_path_factory: pytest.TempPathFactory) -> Any:
    """Scansione per fixture, fatta al primo uso e riusata dagli altri test del modulo."""
    for plugin in PLUGINS:
        fleet.add_builtin(plugin)
    base = tmp_path_factory.mktemp("e2e-phase2")
    done: dict[str, Scan] = {}

    def get(name: str) -> Scan:
        if name not in done:
            root = copy_fixture(name, base)
            out = base / f"out-{name}"
            result = fleet.scan(root, out, "--offline", plugins=PLUGINS, feeds_cache=feeds_cache)
            DURATIONS[f"scansione {name}"] = result.seconds
            done[name] = Scan(name, result, root)
        scan = done[name]
        assert scan.result.returncode == 0, scan.result.stderr[-2000:]
        return scan

    return get


@pytest.mark.parametrize("fixture", [*F02, *GRAPHS])
def test_the_phase_2_plugins_ran_signed_without_failures(fixture: str, scans: Any) -> None:
    report = scans(fixture).report
    runs = {p["name"]: p for p in report["plugins"]}
    failed = {n: p.get("failure") for n, p in runs.items() if p["outcome"] == "failed"}
    assert failed == {}, failed
    assert {n for n in MUST_RUN[fixture] if runs[n]["outcome"] == "ok"} == MUST_RUN[fixture]
    assert {p["signature"] for p in runs.values() if p["outcome"] == "ok"} == {"verified"}
    assert report["status"] == "complete", report["warnings"]


# --- F-02 ---------------------------------------------------------------------------------------


def entries(fixture: str) -> list[dict[str, Any]]:
    return load_expected(REPOS / fixture / "expected-findings.yaml")


@pytest.mark.parametrize(
    ("fixture", "entry"),
    [pytest.param(f, e, id=f"{f}::{describe(e)}") for f in F02 for e in entries(f)],
)
def test_expected_finding_is_detected(fixture: str, entry: dict[str, Any], scans: Any) -> None:
    findings = scans(fixture).findings
    assert matching(entry, findings), (
        f"atteso mancante {describe(entry)} tools={entry['tools']}; "
        f"stessa regola altrove: {near_misses(entry, findings)}"
    )


def _correlated() -> dict[tuple[str, str], list[dict[str, Any]]]:
    """Voci di `iac-app` per (percorso, problema): due o tre strumenti sullo stesso problema."""
    groups: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for entry in entries("iac-app"):
        if "correlation" in entry:
            groups.setdefault((entry["path"], entry["correlation"]), []).append(entry)
    return groups


@pytest.mark.parametrize("key", sorted(_correlated()), ids=lambda k: f"{k[0]}::{k[1]}")
def test_findings_on_the_same_problem_share_one_correlation_group(
    key: tuple[str, str], scans: Any
) -> None:
    findings = scans("iac-app").findings
    found = [f for entry in _correlated()[key] for f in matching(entry, findings)]
    values = {f.get("correlation") for f in found}
    assert len(values) == 1 and None not in values, [(f["rule_id"], f.get("correlation"))
                                                    for f in found]  # fmt: skip


def test_different_problems_have_different_correlation_groups(scans: Any) -> None:
    findings = scans("iac-app").findings
    by_key = {
        key: matching(group[0], findings)[0]["correlation"] for key, group in _correlated().items()
    }
    assert len(set(by_key.values())) == len(by_key), by_key


# --- F-01 ---------------------------------------------------------------------------------------


def expected_graph(fixture: str) -> dict[str, Any]:
    data: dict[str, Any] = yaml.safe_load((REPOS / fixture / "expected-graph.yaml").read_text())
    return data


def artifact(scan: Scan) -> dict[str, Any]:
    assert scan.result.out_dir is not None
    data: dict[str, Any] = json.loads(
        (scan.result.out_dir / "code-analyzer.graph.json").read_text()
    )
    return data


def smell_findings(scan: Scan, rule: str, scope: str) -> list[dict[str, Any]]:
    return [
        f
        for f in scan.findings
        if f["rule_id"] == rule and f["evidence"]["ca-graph"]["scope"] == scope
    ]


def members(finding: dict[str, Any]) -> set[str]:
    return set(finding["evidence"]["ca-graph"]["members"])


@pytest.mark.parametrize("fixture", GRAPHS)
def test_the_published_graph_has_the_expected_edges_and_metrics(fixture: str, scans: Any) -> None:
    graph, wanted = artifact(scans(fixture)), expected_graph(fixture)
    modules = {m["path"]: m for m in graph["modules"]}
    tests = {p for p, m in modules.items() if m.get("test")}
    assert tests == set(wanted["test_modules"])
    edges = {
        (e["source"], e["target"])
        for e in graph["edges"]
        if not e.get("external") and e["source"] not in tests
    }
    assert edges == {tuple(e) for e in wanted["internal_edges"]}
    packages = {p["path"]: p for p in graph["packages"]}
    for kind, nodes in (("modules", modules), ("packages", packages)):
        for path, values in wanted["metrics"][kind].items():
            got = nodes[path]["metrics"]
            assert (got["fan_in"], got["fan_out"]) == (values["ca"], values["ce"]), path
            assert got["instability"] == pytest.approx(values["instability"], abs=1e-3), path
    # ADR-0023: l'immagine firmata di ca-graph conta le righe e l'host scrive l'ADI
    assert all(m["lines"] >= 0 for m in graph["modules"])
    assert any(m.get("metrics", {}).get("adi", 0) > 0 for m in graph["modules"])


@pytest.mark.parametrize("fixture", GRAPHS)
@pytest.mark.parametrize("scope", ["module", "package"])
def test_expected_cycles_are_found_and_only_those(fixture: str, scope: str, scans: Any) -> None:
    wanted = expected_graph(fixture)["smells"]["cycles"]
    found = smell_findings(scans(fixture), CYCLE, scope)
    assert sorted(sorted(members(f)) for f in found) == sorted(sorted(c) for c in wanted[scope])
    if scope == "module":
        inside = {m for f in found for m in members(f)}
        assert not inside & set(wanted["not_in_any_cycle"])


@pytest.mark.parametrize("fixture", GRAPHS)
def test_expected_hubs_are_found(fixture: str, scans: Any) -> None:
    wanted = expected_graph(fixture)["smells"]["hubs"]
    found = {f["location"]["path"] for f in smell_findings(scans(fixture), HUB, "module")}
    assert set(wanted["present"]) <= found, found


@pytest.mark.parametrize("fixture", GRAPHS)
def test_expected_unstable_dependencies_are_found_and_the_negatives_are_not(
    fixture: str, scans: Any
) -> None:
    wanted = expected_graph(fixture)["smells"]["unstable_dependencies"]
    # l'evidenza di uno Unstable Dependency elenca i pacchetti meno stabili, non `members`
    found = {
        f["location"]["path"]: {d["package"] for d in f["evidence"]["ca-graph"]["less_stable"]}
        for f in smell_findings(scans(fixture), UNSTABLE, "package")
    }
    for item in wanted["present"]:
        assert item["package"] in found, found
        assert set(item["depends_on"]) <= found[item["package"]], found
    assert not set(wanted["absent"]) & set(found), found


# --- F-03 ---------------------------------------------------------------------------------------

REPORTS: dict[str, dict[str, Any]] = yaml.safe_load((COVERAGE / "expected.yaml").read_text())[
    "reports"
]
SECRET_MARKER = "ca-e2e-coverage-outside-workspace"


def coverage_scan(
    fleet: Fleet, base: Path, name: str, report: bytes, fmt: str, files: list[str]
) -> Scan:
    """Un workspace con il report, i file che nomina e la configurazione che lo indica."""
    fleet.add_builtin("coverage")
    root = base / name
    root.mkdir()
    for relative in files:
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("x = 1\n" * 30)
    (root / "report.dat").write_bytes(report)
    (root / ".code-analyzer.yml").write_text(
        yaml.safe_dump(
            {
                "version": 1,
                "plugins": {"coverage": {"reports": [{"path": "report.dat", "format": fmt}]}},
            }
        )
    )
    out = base / f"out-{name}"
    result = fleet.scan(root, out, "--offline", plugins=["coverage"])
    DURATIONS[f"scansione coverage {name}"] = result.seconds
    return Scan(name, result, root)


def coverage_run(scan: Scan) -> dict[str, Any]:
    assert scan.result.returncode == 0, scan.result.stderr[-2000:]
    return next(p for p in scan.report["plugins"] if p["name"] == "coverage")


@pytest.mark.parametrize("report", sorted(REPORTS), ids=lambda r: r.replace("/", "-"))
def test_each_coverage_report_is_read_or_refused_as_expected(
    report: str, fleet: Fleet, tmp_path: Path
) -> None:
    case = REPORTS[report]
    base = tmp_path / "w"
    base.mkdir()
    (base / "outside.txt").write_text(SECRET_MARKER)
    scan = coverage_scan(
        fleet,
        base,
        "ws",
        (COVERAGE / report).read_bytes(),
        case["format"],
        list(case.get("files", {})),
    )
    run = coverage_run(scan)
    if case["outcome"] == "refused":
        assert run["outcome"] == "failed", run
        assert scan.report["status"] == "partial"
        assert [f["category"] for f in scan.findings] == ["health"]
    else:
        assert run["outcome"] == "ok", run
        # file sotto le righe minime del plugin: letti, nessun finding
        assert scan.findings == []
    assert SECRET_MARKER not in scan.result.all_text()


def test_a_poorly_covered_file_is_detected_and_a_well_covered_one_is_not(
    fleet: Fleet, tmp_path: Path
) -> None:
    def lcov(path: str, covered: int, total: int = 25) -> str:
        lines = "".join(f"DA:{n},{1 if n <= covered else 0}\n" for n in range(1, total + 1))
        return f"SF:{path}\n{lines}end_of_record\n"

    report = (lcov("pkg/low.py", 5) + lcov("pkg/high.py", 24)).encode()
    scan = coverage_scan(fleet, tmp_path, "low", report, "lcov", ["pkg/low.py", "pkg/high.py"])
    assert coverage_run(scan)["outcome"] == "ok"
    found = [(f["category"], f["rule_id"], f["location"]["path"]) for f in scan.findings]
    assert found == [("test", "ca.coverage.low-file-coverage", "pkg/low.py")]
    assert scan.findings[0]["level"] in ("medio", "basso")
