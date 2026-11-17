"""G-04: grafo per modulo e pacchetto con le metriche di accoppiamento e instabilità."""

import json
from pathlib import Path
from typing import Any

import pytest
import yaml
from jsonschema import Draft202012Validator

from ca_core.models.graph import Graph
from ca_graph import deps
from ca_graph.deps import Options, build, instability, package_path, with_metrics

ROOT = Path(__file__).resolve().parents[3]
REPOS = ROOT / "tests/fixtures/repos"
STATS = {"files_parsed": 0}
HISTORY = {"status": "assente", "window_days": 90}


def make(modules: list[tuple[str, bool]], edges: list[tuple[str, str, dict[str, Any]]]) -> Graph:
    """Grafo di prova: moduli (percorso, test) e archi (origine, destinazione, opzioni)."""
    document = {
        "version": 1,
        "modules": [
            {"path": p, "language": "python", "parse": "completa", "test": t}
            for p, t in sorted(modules)
        ],
        "edges": [
            {"source": s, "target": t, "imports": 1, "confidence": "dichiarato", **kw}
            for s, t, kw in sorted(edges, key=lambda e: (e[0], e[2].get("external", False), e[1]))
        ],
        "externals": [
            {"name": name, "ecosystem": "pypi"}
            for name in sorted({t for _, t, kw in edges if kw.get("external")})
        ],
        "stats": STATS,
        "history": HISTORY,
    }
    return Graph.model_validate(document)


# --- unità ---------------------------------------------------------------------------------------


def test_instability_is_ce_over_ca_plus_ce_and_zero_when_isolated() -> None:
    assert instability(0, 0) == 0.0
    assert instability(1, 3) == 0.75
    assert instability(4, 0) == 0.0 and instability(0, 2) == 1.0


@pytest.mark.parametrize(
    ("module", "package"),
    [("a.py", "."), ("pkg/a.py", "pkg"), ("pkg/sub/a.py", "pkg/sub")],
)
def test_package_of_a_module_is_its_folder_and_dot_for_the_root(module: str, package: str) -> None:
    assert package_path(module) == package


def test_fan_in_and_fan_out_count_distinct_neighbours() -> None:
    graph = make(
        [("a.py", False), ("b.py", False), ("c.py", False)],
        [("a.py", "b.py", {"imports": 5}), ("c.py", "b.py", {}), ("a.py", "c.py", {})],
    )
    result = with_metrics(graph)
    metrics = {m.path: m.metrics for m in result.modules}
    assert (metrics["b.py"].fan_in, metrics["b.py"].fan_out) == (2, 0)  # 5 import = un arco
    assert (metrics["a.py"].fan_in, metrics["a.py"].fan_out) == (0, 2)
    assert metrics["a.py"].instability == 1.0 and metrics["b.py"].instability == 0.0


def test_external_edges_and_self_references_do_not_count() -> None:
    graph = make(
        [("a.py", False), ("b.py", False)],
        [("a.py", "b.py", {}), ("a.py", "requests", {"external": True})],
    )
    metrics = {m.path: m.metrics for m in with_metrics(graph).modules}
    assert metrics["a.py"].fan_out == 1


def test_test_modules_are_excluded_by_default_with_their_edges() -> None:
    graph = make(
        [("src/a.py", False), ("src/b.py", False), ("tests/test_a.py", True)],
        [("src/a.py", "src/b.py", {}), ("tests/test_a.py", "src/a.py", {})],
    )
    default = {m.path: m.metrics for m in with_metrics(graph).modules}
    assert default["tests/test_a.py"] is None and default["src/a.py"].fan_in == 0
    included = {m.path: m.metrics for m in with_metrics(graph, Options(include_tests=True)).modules}
    assert included["tests/test_a.py"] is not None and included["src/a.py"].fan_in == 1
    assert [p.path for p in with_metrics(graph).packages] == ["src"]  # `tests` non è un pacchetto


def test_type_only_edges_count_by_default_and_can_be_left_out() -> None:
    graph = make([("a.py", False), ("b.py", False)], [("a.py", "b.py", {"type_only": True})])
    assert build(graph).module_out["a.py"] == ("b.py",)
    assert build(graph, Options(include_type_only=False)).module_out["a.py"] == ()


def test_package_edges_exist_between_different_folders_only_and_count_their_support() -> None:
    graph = make(
        [("p/a.py", False), ("p/b.py", False), ("q/x.py", False), ("q/y.py", False)],
        [
            ("p/a.py", "p/b.py", {}),
            ("p/a.py", "q/x.py", {}),
            ("p/b.py", "q/y.py", {}),
            ("q/x.py", "p/a.py", {}),
        ],
    )
    built = build(graph)
    assert built.package_out == {"p": ("q",), "q": ("p",)}
    assert built.package_edges == {("p", "q"): 2, ("q", "p"): 1}
    packages = {p.path: p for p in with_metrics(graph).packages}
    assert packages["p"].modules == 2 and packages["p"].metrics.fan_in == 1


def test_a_subfolder_is_a_package_of_its_own() -> None:
    graph = make([("p/a.py", False), ("p/sub/b.py", False)], [("p/a.py", "p/sub/b.py", {})])
    assert build(graph).package_out["p"] == ("p/sub",)


def test_metrics_do_not_keep_a_stale_pagerank_removed_or_invented() -> None:
    graph = with_metrics(make([("a.py", False)], []))
    assert graph.modules[0].metrics is not None and graph.modules[0].metrics.pagerank is None


def test_result_is_a_valid_graph_with_sorted_packages_and_the_original_is_untouched() -> None:
    graph = make([("b/x.py", False), ("a/y.py", False), ("z.py", False)], [])
    result = with_metrics(graph)
    Graph.model_validate(result.model_dump(mode="json"))
    assert [p.path for p in result.packages] == [".", "a", "b"]
    assert all(m.metrics is None for m in graph.modules) and graph.packages == []


def test_build_is_deterministic_in_any_module_and_edge_order() -> None:
    modules = [("a/1.py", False), ("a/2.py", False), ("b/1.py", False)]
    edges = [("a/1.py", "b/1.py", {}), ("a/2.py", "b/1.py", {}), ("a/1.py", "a/2.py", {})]
    first = with_metrics(make(modules, edges)).model_dump_json()
    second = with_metrics(make(list(reversed(modules)), list(reversed(edges)))).model_dump_json()
    assert first == second


def test_empty_graph() -> None:
    result = with_metrics(make([], []))
    assert result.modules == [] and result.packages == []


# --- fixture F-01 ---------------------------------------------------------------------------------


def expected(name: str) -> dict[str, Any]:
    return yaml.safe_load((REPOS / name / "expected-graph.yaml").read_text(encoding="utf-8"))


def from_expected(document: dict[str, Any]) -> Graph:
    """Grafo costruito dagli archi attesi (non dall'estrattore): prova G-04 da sola."""
    paths = sorted(
        {p for edge in document["internal_edges"] for p in edge} | set(document["test_modules"])
    )
    tests = set(document["test_modules"])
    edges = [(s, t, {}) for s, t in document["internal_edges"]]
    modules = [(p, p in tests) for p in paths]
    return make(modules, edges)


@pytest.mark.parametrize(
    ("fixture", "language"), [("graph-python", "python"), ("graph-js-ts", "typescript")]
)
def test_fixture_metrics_match_the_designed_expectations(fixture: str, language: str) -> None:
    document = expected(fixture)
    result = with_metrics(from_expected(document))
    by_module = {m.path: m.metrics for m in result.modules}
    for path, want in document["metrics"]["modules"].items():
        got = by_module[path]
        assert got is not None, path
        assert (got.fan_in, got.fan_out) == (want["ca"], want["ce"]), path
        assert got.instability == pytest.approx(want["instability"], abs=1e-4), path
    by_package = {p.path: p.metrics for p in result.packages}
    for path, want in document["metrics"]["packages"].items():
        if path not in by_package:
            continue  # un pacchetto senza archi interni non compare nel grafo costruito dagli archi
        got = by_package[path]
        assert (got.fan_in, got.fan_out) == (want["ca"], want["ce"]), path
        assert got.instability == pytest.approx(want["instability"], abs=1e-4), path


def test_the_expected_graph_files_follow_their_schema() -> None:
    schema = json.loads((ROOT / "tests/fixtures/expected-graph.schema.json").read_text())
    for fixture in ("graph-python", "graph-js-ts"):
        assert list(Draft202012Validator(schema).iter_errors(expected(fixture))) == []


def test_deps_module_does_not_import_the_parser() -> None:
    assert "tree_sitter" not in (Path(deps.__file__).read_text())
