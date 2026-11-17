"""G-10: passo `build_graph` con le porte finte, sui grafi estratti dalle fixture F-01."""

import copy
import json
from pathlib import Path
from typing import Any

import pytest
from graph_builders import extract

from ca_core.fakes import FixedClock, InMemorySourceReader
from ca_core.models import CodeAnalyzerConfig, PackagedPluginManifest
from ca_core.models.finding import Category, Level, LevelSource
from ca_core.models.plugin_manifest import _EXAMPLE as BASE
from ca_core.models.scan_report import Isolation, Outcome, PluginRun, ReportStatus
from ca_core.pipeline.normalize import NormalizeRequest, normalize
from ca_core.pipeline.run_plugins import PluginExecution
from ca_core.ports import Signature
from ca_core.schema_validation import SchemaStore
from ca_graph.smells import CYCLIC, HUB_LIKE, UNSTABLE, SmellConfig
from ca_graph.step import BuildGraphRequest, build_graph, finding_of

ROOT = Path(__file__).resolve().parents[3]
REPOS = ROOT / "tests/fixtures/repos"
OUT = "/out"
DIGEST = "sha256:" + "a" * 64
CLOCK = FixedClock()
GUARD = SmellConfig(hub_min_degree=6)  # il valore delle fixture F-01


@pytest.fixture(scope="module")
def store() -> SchemaStore:
    return SchemaStore(ROOT / "schemas" / "vendor")


def graph_manifest(max_bytes: int = 10**8) -> PackagedPluginManifest:
    data = {
        **copy.deepcopy(BASE),
        "name": "ca-graph",
        "image": f"registry.invalid/ca/ca-graph:1.0.0@{DIGEST}",
        "languages": [],
        "categories": ["architecture"],
        "outputs": {"graph": "/out/graph.json", "max_bytes": max_bytes},
    }
    return PackagedPluginManifest.model_validate(data)


def execution(outcome: Outcome = Outcome.OK, directory: str | None = OUT) -> PluginExecution:
    failed = outcome is Outcome.FAILED
    run = PluginRun(
        name="ca-graph",
        version="1.0.0",
        digest=DIGEST,
        signature=Signature.VERIFIED,
        isolation=Isolation.HARDENED_CONTAINER,
        duration_seconds=1.0,
        outcome=outcome,
        failure="esecuzione fallita" if failed else None,
    )
    return PluginExecution(manifest=graph_manifest(), run=run, output_dir=directory)


def reader(document: dict[str, Any] | bytes) -> InMemorySourceReader:
    data = document if isinstance(document, bytes) else json.dumps(document).encode()
    return InMemorySourceReader({OUT: {"graph.json": data}})


def request(executions: list[PluginExecution], **kw: Any) -> BuildGraphRequest:
    kw = {"smells": GUARD, **kw}
    return BuildGraphRequest(
        repository="repo", commit="abc", executions=executions, exclude=[], **kw
    )


def run(fixture: str = "graph-python", **kw: Any):
    return build_graph(request([execution()], **kw), reader(extract(REPOS / fixture)), CLOCK)


# --- finding -----------------------------------------------------------------------------------


@pytest.mark.parametrize("fixture", ["graph-python", "graph-js-ts"])
def test_the_fixture_gives_the_four_expected_architecture_findings(fixture: str) -> None:
    result = run(fixture)
    assert [(f.rule_id, f.evidence["ca-graph"]["scope"]) for f in result.findings] == [
        (CYCLIC, "module"), (CYCLIC, "package"), (HUB_LIKE, "module"), (UNSTABLE, "package"),
    ]  # fmt: skip
    for found in result.findings:
        assert found.category is Category.ARCHITECTURE and found.tools == ["ca-graph"]
        assert found.location.repository == "repo" and found.location.start_line is None
        assert found.id == found.fingerprint and found.level is None  # il livello lo dà normalize


def test_finding_carries_anchor_title_and_the_size_in_the_evidence() -> None:
    cycle = next(
        f
        for f in run().findings
        if f.rule_id == CYCLIC and "module" in f.title.lower() or f.rule_id == CYCLIC
    )
    assert cycle.location.path == "shop/billing/a.py" and "3 moduli" in cycle.title
    assert cycle.evidence["ca-graph"]["size"] == 3 and cycle.evidence["ca-graph"]["edges"] == 3
    assert "shop/billing/b.py" in cycle.message


def test_the_fingerprint_does_not_change_when_a_cycle_gains_a_member(tmp_path: Path) -> None:
    """ADR-0020: l'ancora è il primo membro, quindi un membro in più non cambia l'identità."""
    base = extract(REPOS / "graph-python")
    grown = copy.deepcopy(base)
    grown["modules"].append(
        {"path": "shop/billing/z.py", "language": "python", "parse": "completa", "test": False}
    )
    grown["modules"].sort(key=lambda m: m["path"])
    grown["edges"] += [
        {"source": "shop/billing/c.py", "target": "shop/billing/z.py", "external": False,
         "imports": 1, "dynamic": False, "type_only": False, "confidence": "dichiarato"},
        {"source": "shop/billing/z.py", "target": "shop/billing/a.py", "external": False,
         "imports": 1, "dynamic": False, "type_only": False, "confidence": "dichiarato"},
    ]  # fmt: skip
    grown["edges"].sort(key=lambda e: (e["source"], e["external"], e["target"]))

    def cycle_fingerprint(document: dict[str, Any]) -> str:
        found = build_graph(request([execution()]), reader(document), CLOCK).findings
        return next(
            f for f in found if f.rule_id == CYCLIC and f.evidence["ca-graph"]["scope"] == "module"
        ).fingerprint

    assert cycle_fingerprint(base) == cycle_fingerprint(grown)


def test_the_step_is_idempotent_and_deterministic() -> None:
    first, second = run(), run()
    assert [f.model_dump() for f in first.findings] == [f.model_dump() for f in second.findings]
    assert (
        first.graph is not None and first.graph.model_dump_json() == second.graph.model_dump_json()
    )


def test_the_graph_is_returned_with_metrics_and_pagerank() -> None:
    graph = run().graph
    assert graph is not None and graph.packages
    hub = next(m for m in graph.modules if m.path == "shop/core/hub.py")
    assert hub.metrics is not None and (hub.metrics.fan_in, hub.metrics.fan_out) == (4, 4)
    assert hub.metrics.pagerank is not None and 0 <= hub.metrics.pagerank <= 1


# --- esclusioni, configurazione, test ---------------------------------------------------------------


def test_excluded_paths_leave_the_graph_before_any_calculation() -> None:
    result = build_graph(
        BuildGraphRequest(
            repository="repo", executions=[execution()], exclude=["shop/billing"], smells=GUARD
        ),
        reader(extract(REPOS / "graph-python")),
        CLOCK,
    )
    assert not any(f.rule_id == CYCLIC for f in result.findings)  # il ciclo stava in billing
    assert any(f.rule_id == HUB_LIKE for f in result.findings)
    assert result.graph is not None
    assert not any(m.path.startswith("shop/billing") for m in result.graph.modules)
    touching = [
        e
        for e in result.graph.edges
        if "shop/billing" in (e.source, e.target)
        or e.source.startswith("shop/billing/")
        or e.target.startswith("shop/billing/")
    ]
    assert touching == []


def test_thresholds_come_from_the_request() -> None:
    quiet = run(
        smells=SmellConfig(cycle_scopes=("package",), hub_min_degree=99, unstable_min_degree=1.0)
    )
    assert [f.evidence["ca-graph"]["scope"] for f in quiet.findings if f.rule_id == CYCLIC] == [
        "package"
    ]
    assert not any(f.rule_id == HUB_LIKE for f in quiet.findings)


# --- fallimenti -----------------------------------------------------------------------------------------


def test_a_failed_graph_plugin_gives_no_findings_and_is_left_for_normalize() -> None:
    failed = [execution(Outcome.FAILED, None)]
    result = build_graph(request(failed), InMemorySourceReader(), CLOCK)
    assert result.findings == [] and result.graph is None and result.executions == failed


@pytest.mark.parametrize(
    "data",
    [b"non json", b"[]", b'{"version": 1}', json.dumps({"version": 2}).encode(), b"\x00" * 50],
)
def test_an_invalid_graph_fails_the_plugin_instead_of_giving_an_empty_graph(data: bytes) -> None:
    result = build_graph(request([execution()]), reader(data), CLOCK)
    assert result.findings == [] and result.graph is None
    [plugin] = result.executions
    assert plugin.run.outcome is Outcome.FAILED and "grafo" in (plugin.run.failure or "")


def test_a_missing_oversized_or_unreadable_graph_fails_the_plugin() -> None:
    missing = build_graph(request([execution()]), InMemorySourceReader({OUT: {}}), CLOCK)
    assert missing.executions[0].run.outcome is Outcome.FAILED
    big = build_graph(request([execution()]), reader(b"x" * 2_000), CLOCK)
    assert big.executions[0].run.outcome is Outcome.FAILED
    no_dir = build_graph(request([execution(directory=None)]), InMemorySourceReader(), CLOCK)
    assert no_dir.executions[0].run.failure == "output assente"


def test_without_a_graph_plugin_the_step_does_nothing() -> None:
    result = build_graph(request([]), InMemorySourceReader(), CLOCK)
    assert result.findings == [] and result.executions == [] and result.graph is None


def test_the_failure_text_never_echoes_the_content() -> None:
    result = build_graph(
        request([execution()]), reader(b'{"version": 1, "secret": "TOKEN-123"}'), CLOCK
    )
    assert "TOKEN-123" not in (result.executions[0].run.failure or "")


# --- con normalize ---------------------------------------------------------------------------------------


def normalize_with(
    findings: list, executions: list[PluginExecution], store: SchemaStore, **config: Any
):
    return normalize(
        NormalizeRequest(
            repository="repo",
            commit="abc",
            workspace="/ws",
            executions=executions,
            config=CodeAnalyzerConfig.model_validate({"version": 1, **config}),
            extra_findings=findings,
        ),
        InMemorySourceReader(),
        store,
        CLOCK,
    )


def test_architecture_findings_get_the_low_default_level_and_stay_complete(
    store: SchemaStore,
) -> None:
    built = run()
    result = normalize_with(built.findings, built.executions, store)
    assert result.status is ReportStatus.COMPLETE
    assert {f.level for f in result.findings} == {Level.LOW}
    assert {f.level_source for f in result.findings} == {LevelSource.DEFAULT}
    assert len(result.findings) == 4


def test_a_failed_graph_becomes_a_health_finding_and_a_partial_report(store: SchemaStore) -> None:
    built = build_graph(request([execution()]), reader(b"non json"), CLOCK)
    result = normalize_with(built.findings, built.executions, store)
    assert result.status is ReportStatus.PARTIAL
    assert [(f.category, f.tool) for f in result.findings] == [(Category.HEALTH, "ca-graph")]


def test_exceptions_by_fingerprint_apply_to_architecture_findings(store: SchemaStore) -> None:
    built = run()
    target = next(f for f in built.findings if f.rule_id == HUB_LIKE)
    exception = {
        "fingerprint": target.fingerprint,
        "reason": "hub voluto",
        "expires": "2099-01-01",
        "approved_by": "revisore",
    }
    result = normalize_with(built.findings, built.executions, store, exceptions=[exception])
    status = {f.rule_id: f.status.value for f in result.findings}
    assert status[HUB_LIKE] == "accettato" and status[CYCLIC] == "aperto"


def test_finding_of_is_pure_for_the_same_clock() -> None:
    from ca_graph.smells import Smell

    smell = Smell(rule_id=HUB_LIKE, scope="module", anchor="a.py", members=("a.py",),
                  evidence={"fan_in": 3, "fan_out": 3})  # fmt: skip
    one = finding_of(smell, repository="r", commit=None, clock=CLOCK)
    assert one == finding_of(smell, repository="r", commit=None, clock=CLOCK)
