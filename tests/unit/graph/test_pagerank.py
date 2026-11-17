"""G-08: PageRank dei moduli, normalizzato in [0, 1], con parametri in configurazione."""

import math
from pathlib import Path

import pytest
from graph_builders import extract
from hypothesis import given, settings
from hypothesis import strategies as st
from test_deps import make

from ca_core.models.graph import Graph
from ca_graph.deps import Options, build
from ca_graph.pagerank import PageRankConfig, normalized, pagerank, with_pagerank

ROOT = Path(__file__).resolve().parents[3]
REPOS = ROOT / "tests/fixtures/repos"


def graph_of(names: list[str], edges: list[tuple[str, str]]) -> Graph:
    return make([(n, False) for n in names], [(a, b, {}) for a, b in edges])


# --- valori noti -----------------------------------------------------------------------------------


def test_two_modules_one_dependency_matches_the_closed_form() -> None:
    """a → b con smorzamento 0,85 e `b` pendente: risolto a mano nel sistema a due equazioni."""
    raw = pagerank(build(graph_of(["a.py", "b.py"], [("a.py", "b.py")])))
    assert raw["a.py"] == pytest.approx(0.13875 / 0.21375 * 0.425 + 0.075, abs=1e-8)
    assert raw["b.py"] == pytest.approx(0.13875 / 0.21375, abs=1e-8)
    assert sum(raw.values()) == pytest.approx(1.0, abs=1e-12)


def test_a_cycle_of_equal_nodes_is_uniform() -> None:
    names = ["a.py", "b.py", "c.py"]
    edges = [("a.py", "b.py"), ("b.py", "c.py"), ("c.py", "a.py")]
    raw = pagerank(build(graph_of(names, edges)))
    assert all(v == pytest.approx(1 / 3, abs=1e-9) for v in raw.values())


def test_the_module_everyone_depends_on_ranks_highest() -> None:
    names = ["core.py", *[f"u{i}.py" for i in range(5)]]
    raw = pagerank(build(graph_of(names, [(f"u{i}.py", "core.py") for i in range(5)])))
    assert max(raw, key=raw.__getitem__) == "core.py"
    users = {v for k, v in raw.items() if k != "core.py"}
    assert len({round(v, 12) for v in users}) == 1  # i dipendenti sono equivalenti
    assert normalized(raw)["core.py"] == 1.0


def test_a_graph_without_edges_is_uniform_and_normalizes_to_one() -> None:
    raw = pagerank(build(graph_of(["a.py", "b.py", "c.py", "d.py"], [])))
    assert all(v == pytest.approx(0.25, abs=1e-12) for v in raw.values())
    assert set(normalized(raw).values()) == {1.0}


def test_damping_zero_gives_a_uniform_rank_whatever_the_edges() -> None:
    raw = pagerank(
        build(graph_of(["a.py", "b.py", "c.py"], [("a.py", "b.py"), ("c.py", "b.py")])),
        PageRankConfig(damping=0.0),
    )
    assert all(v == pytest.approx(1 / 3, abs=1e-12) for v in raw.values())


def test_a_longer_chain_ranks_the_end_above_the_start() -> None:
    names = ["a.py", "b.py", "c.py", "d.py"]
    raw = pagerank(build(graph_of(names, list(zip(names, names[1:], strict=False)))))
    assert raw["d.py"] > raw["c.py"] > raw["b.py"] > raw["a.py"]


def test_empty_graph_and_empty_normalization() -> None:
    assert pagerank(build(make([], []))) == {} and normalized({}) == {}


# --- configurazione --------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "bad", [{"damping": 1.0}, {"damping": -0.1}, {"tolerance": 0}, {"max_iterations": 0}]
)
def test_invalid_parameters_are_refused(bad: dict[str, float]) -> None:
    with pytest.raises(ValueError):
        PageRankConfig(**bad)


def test_parameters_change_the_result_and_iterations_are_bounded() -> None:
    deps = build(graph_of(["a.py", "b.py"], [("a.py", "b.py")]))
    default = pagerank(deps)
    assert pagerank(deps, PageRankConfig(damping=0.5))["b.py"] < default["b.py"]
    one = pagerank(deps, PageRankConfig(max_iterations=1))
    assert one != default and sum(one.values()) == pytest.approx(1.0, abs=1e-12)


# --- proprietà --------------------------------------------------------------------------------------


def random_graph(size: int, pairs: set[tuple[int, int]]) -> tuple[list[str], list[tuple[str, str]]]:
    names = [f"n{i:02d}.py" for i in range(size)]
    return names, [(names[a], names[b]) for a, b in sorted(pairs) if a != b]


@settings(max_examples=120, deadline=None)
@given(st.integers(1, 12), st.data())
def test_ranks_are_a_distribution_and_normalization_stays_in_the_unit_interval(
    size: int, data: st.DataObject
) -> None:
    pairs = data.draw(st.sets(st.tuples(st.integers(0, size - 1), st.integers(0, size - 1))))
    names, edges = random_graph(size, pairs)
    raw = pagerank(build(graph_of(names, edges)))
    assert set(raw) == set(names)
    assert all(v >= 0 for v in raw.values()) and math.isclose(sum(raw.values()), 1.0, abs_tol=1e-9)
    scaled = normalized(raw)
    assert all(0.0 <= v <= 1.0 for v in scaled.values()) and max(scaled.values()) == 1.0


@settings(max_examples=80, deadline=None)
@given(st.integers(2, 10), st.data())
def test_the_result_does_not_depend_on_the_order_of_modules_and_edges(
    size: int, data: st.DataObject
) -> None:
    pairs = data.draw(st.sets(st.tuples(st.integers(0, size - 1), st.integers(0, size - 1))))
    names, edges = random_graph(size, pairs)
    first = pagerank(build(graph_of(names, edges)))
    second = pagerank(build(graph_of(list(reversed(names)), list(reversed(edges)))))
    assert first == second  # stessi byte, non solo approssimati


# --- sul grafo ----------------------------------------------------------------------------------------


def test_with_pagerank_fills_every_considered_module_and_leaves_test_modules_out() -> None:
    graph = make(
        [("src/a.py", False), ("src/b.py", False), ("tests/t.py", True)],
        [("src/a.py", "src/b.py", {}), ("tests/t.py", "src/b.py", {})],
    )
    result = with_pagerank(graph)
    metrics = {m.path: m.metrics for m in result.modules}
    assert metrics["tests/t.py"] is None
    assert metrics["src/b.py"].pagerank == 1.0 and 0 < metrics["src/a.py"].pagerank < 1.0
    assert (metrics["src/b.py"].fan_in, metrics["src/a.py"].fan_out) == (1, 1)
    Graph.model_validate(result.model_dump(mode="json"))
    with_tests = {
        m.path: m.metrics for m in with_pagerank(graph, Options(include_tests=True)).modules
    }
    assert with_tests["tests/t.py"] is not None


def test_f01_the_most_imported_utility_is_the_most_critical_module() -> None:
    graph = Graph.model_validate(extract(REPOS / "graph-python"))
    scores = {m.path: m.metrics.pagerank for m in with_pagerank(graph).modules if m.metrics}
    assert scores["shop/util/helpers.py"] == 1.0  # Ca 5: la più importata
    assert scores["shop/stable/core.py"] > scores["shop/svc1/main.py"]
    assert all(0.0 <= v <= 1.0 for v in scores.values())
