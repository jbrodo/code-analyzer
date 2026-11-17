"""G-05, G-06, G-07: Cyclic, Hub-Like e Unstable Dependency, sulle fixture F-01 e su grafi di prova."""

from pathlib import Path
from typing import Any

import pytest
import yaml
from graph_builders import extract
from hypothesis import given, settings
from hypothesis import strategies as st
from test_deps import make

from ca_core.models.graph import Graph
from ca_graph.deps import Options, build
from ca_graph.smells import (
    CYCLIC,
    HUB_LIKE,
    UNSTABLE,
    Smell,
    SmellConfig,
    detect,
    find_cycles,
    find_hubs,
    find_unstable,
)
from ca_graph.smells.cycles import strongly_connected

ROOT = Path(__file__).resolve().parents[3]
REPOS = ROOT / "tests/fixtures/repos"
FIXTURES = ["graph-python", "graph-js-ts"]


def expected(name: str) -> dict[str, Any]:
    return yaml.safe_load((REPOS / name / "expected-graph.yaml").read_text(encoding="utf-8"))


def fixture_deps(name: str, **options: Any):
    graph = Graph.model_validate(extract(REPOS / name))
    return build(graph, Options(**options))


def fixture_config(name: str) -> SmellConfig:
    smells = expected(name)["smells"]["config"]
    return SmellConfig(
        hub_min_degree=smells["hub_min_degree"], unstable_min_degree=smells["unstable_min_degree"]
    )


def chain(*names: str, close: bool = False) -> Graph:
    edges = [(a, b, {}) for a, b in zip(names, names[1:], strict=False)]
    if close:
        edges.append((names[-1], names[0], {}))
    return make([(n, False) for n in names], edges)


# --- G-05: cicli ------------------------------------------------------------------------------------


@pytest.mark.parametrize("fixture", FIXTURES)
def test_f01_cycles_are_found_and_the_negatives_are_absent(fixture: str) -> None:
    want = expected(fixture)["smells"]["cycles"]
    found = find_cycles(fixture_deps(fixture), fixture_config(fixture))
    by_scope = {s: [list(x.members) for x in found if x.scope == s] for s in ("module", "package")}
    assert by_scope["module"] == want["module"] and by_scope["package"] == want["package"]
    in_a_cycle = {m for x in found if x.scope == "module" for m in x.members}
    assert in_a_cycle.isdisjoint(want["not_in_any_cycle"])


@pytest.mark.parametrize("fixture", FIXTURES)
def test_cycle_evidence_has_level_size_members_and_edges(fixture: str) -> None:
    want = expected(fixture)["smells"]["cycles"]
    cycles = {s.scope: s for s in find_cycles(fixture_deps(fixture))}
    module = cycles["module"]
    assert module.rule_id == CYCLIC and module.anchor == want["module"][0][0]
    assert module.evidence["level"] == "module" and module.evidence["size"] == 3
    assert module.evidence["edges"] == 3 and module.evidence["members"] == want["module"][0]
    package = cycles["package"]
    assert package.evidence["size"] == 2 and package.evidence["edges"] == 2  # a→x e y→b


def test_thresholds_come_from_the_configuration() -> None:
    deps = fixture_deps("graph-python")
    assert {s.scope for s in find_cycles(deps)} == {"module", "package"}
    assert {s.scope for s in find_cycles(deps, SmellConfig(cycle_min_size=3))} == {"module"}
    assert {s.scope for s in find_cycles(deps, SmellConfig(cycle_scopes=("package",)))} == {
        "package"
    }
    assert find_cycles(deps, SmellConfig(cycle_min_size=4)) == []


def test_a_two_cycle_is_a_cycle_and_a_chain_is_not() -> None:
    """Un modulo che importa se stesso non arriva qui: il contratto `graph` lo rifiuta."""
    assert len(find_cycles(build(chain("a.py", "b.py", close=True)))) == 1
    assert find_cycles(build(chain("a.py", "b.py", "c.py"))) == []


def test_type_only_cycles_count_by_default_and_not_when_left_out() -> None:
    graph = make(
        [("a.py", False), ("b.py", False)],
        [("a.py", "b.py", {}), ("b.py", "a.py", {"type_only": True})],
    )
    assert len(find_cycles(build(graph))) == 1
    assert find_cycles(build(graph, Options(include_type_only=False))) == []


def test_test_modules_do_not_close_a_cycle() -> None:
    graph = make(
        [("src/a.py", False), ("tests/t.py", True)],
        [("src/a.py", "tests/t.py", {}), ("tests/t.py", "src/a.py", {})],
    )
    assert find_cycles(build(graph)) == []
    included = find_cycles(build(graph, Options(include_tests=True)))
    assert [x.scope for x in included] == ["module", "package"]


def test_a_very_long_chain_and_cycle_do_not_recurse() -> None:
    names = [f"m{i:06d}.py" for i in range(20_000)]
    assert strongly_connected(names, {a: [b] for a, b in zip(names, names[1:], strict=False)}) == [
        (n,) for n in names
    ]
    big = strongly_connected(
        names, {a: [b] for a, b in zip(names, [*names[1:], names[0]], strict=True)}
    )
    assert big == [tuple(sorted(names))]


def test_evidence_lists_are_capped_but_the_size_is_the_real_one() -> None:
    names = [f"m{i:03d}.py" for i in range(30)]
    [smell] = find_cycles(build(chain(*names, close=True)))
    assert smell.evidence["size"] == 30 and len(smell.evidence["members"]) == 20
    assert smell.anchor == "m000.py" and len(smell.members) == 30


def naive_components(nodes: list[str], edges: set[tuple[str, str]]) -> set[tuple[str, ...]]:
    reach = {n: {n} for n in nodes}
    changed = True
    while changed:
        changed = False
        for a, b in edges:
            new = reach[b] - reach[a]
            if new:
                reach[a] |= new
                changed = True
    seen: set[tuple[str, ...]] = set()
    for n in nodes:
        seen.add(tuple(sorted(m for m in nodes if m in reach[n] and n in reach[m])))
    return seen


@settings(max_examples=150, deadline=None)
@given(st.integers(1, 9), st.data())
def test_components_match_a_naive_mutual_reachability(size: int, data: st.DataObject) -> None:
    nodes = [f"n{i}" for i in range(size)]
    pairs = data.draw(st.sets(st.tuples(st.sampled_from(nodes), st.sampled_from(nodes))))
    successors: dict[str, list[str]] = {n: [] for n in nodes}
    for a, b in sorted(pairs):
        successors[a].append(b)
    assert set(strongly_connected(nodes, successors)) == naive_components(nodes, set(pairs))


# --- G-06: hub ---------------------------------------------------------------------------------------


@pytest.mark.parametrize("fixture", FIXTURES)
def test_f01_hub_is_found_and_the_negatives_are_not(fixture: str) -> None:
    want = expected(fixture)["smells"]["hubs"]
    found = find_hubs(fixture_deps(fixture), fixture_config(fixture))
    assert [s.anchor for s in found] == want["present"]
    assert {s.anchor for s in found}.isdisjoint(want["absent"])
    evidence = found[0].evidence
    assert (evidence["fan_in"], evidence["fan_out"], evidence["imbalance"]) == (4, 4, 0.0)
    assert found[0].rule_id == HUB_LIKE and found[0].scope == "module"


def test_without_the_degree_guard_the_median_zero_makes_small_modules_hubs() -> None:
    """Il rumore che la guardia di ADR-0020 toglie: gradi 1/1 superano una mediana pari a 0."""
    found = {s.anchor for s in find_hubs(fixture_deps("graph-python"), SmellConfig())}
    assert "shop/billing/c.py" in found and "shop/catalog/price.py" in found
    assert "shop/util/helpers.py" not in found and "shop/main.py" not in found  # mai: un lato solo


def test_balance_threshold_comes_from_the_configuration() -> None:
    graph = make(
        [(f"m{i}.py", False) for i in range(8)],
        [("m0.py", "m1.py", {}), ("m0.py", "m2.py", {}), ("m0.py", "m3.py", {}),
         ("m4.py", "m0.py", {})],
    )  # fmt: skip
    deps = build(graph)
    assert find_hubs(deps, SmellConfig(hub_balance=0.25)) == []  # Ca 1, Ce 3: sbilanciato
    assert [s.anchor for s in find_hubs(deps, SmellConfig(hub_balance=0.6))] == ["m0.py"]


def test_hubs_use_a_strict_median_and_an_empty_graph_has_none() -> None:
    assert find_hubs(build(make([], []))) == []
    flat = make([("a.py", False), ("b.py", False)], [("a.py", "b.py", {}), ("b.py", "a.py", {})])
    assert find_hubs(build(flat)) == []  # Ca e Ce uguali alla mediana, non sopra


def test_hub_config_is_validated() -> None:
    for bad in (
        {"hub_balance": 1.5},
        {"hub_min_degree": -1},
        {"cycle_min_size": 1},
        {"unstable_min_degree": -0.1},
    ):
        with pytest.raises(ValueError):
            SmellConfig(**bad)


# --- G-07: dipendenza instabile ------------------------------------------------------------------------


@pytest.mark.parametrize("fixture", FIXTURES)
def test_f01_unstable_dependency_is_found_and_the_negatives_are_not(fixture: str) -> None:
    want = expected(fixture)["smells"]["unstable_dependencies"]
    found = find_unstable(fixture_deps(fixture), fixture_config(fixture))
    assert [{"package": s.anchor, "depends_on": list(s.members[1:])} for s in found] == want[
        "present"
    ]
    assert {s.anchor for s in found}.isdisjoint(want["absent"])
    evidence = found[0].evidence
    assert (evidence["instability"], evidence["degree"], evidence["outgoing"]) == (0.2, 1.0, 1)
    assert evidence["less_stable"][0]["instability"] == 0.8 and found[0].rule_id == UNSTABLE


def test_equal_instability_is_not_an_unstable_dependency() -> None:
    """billing e ledger hanno la stessa instabilità: il ciclo è un altro smell."""
    found = find_unstable(fixture_deps("graph-python"))
    assert not {"shop/billing", "shop/ledger"} & {s.anchor for s in found}


def test_degree_and_outgoing_guard_come_from_the_configuration() -> None:
    """`s` ha Ca 4 e Ce 3 (I 0,43) e dipende da due pacchetti più instabili e da uno stabile."""
    modules = ["s", "a", "b", "c", "x1", "x2", "x3", "t1", "t2", "t3", "t4"]
    edges = [(f"t{i}/m.py", "s/m.py") for i in range(1, 5)]
    edges += [("s/m.py", f"{p}/m.py") for p in ("a", "b", "c")]
    edges += [(f"{p}/m.py", f"x{i}/m.py") for p in ("a", "b") for i in range(1, 4)]
    deps = build(make([(f"{m}/m.py", False) for m in modules], [(a, b, {}) for a, b in edges]))
    [found] = find_unstable(deps, SmellConfig(unstable_min_degree=0.3))
    assert found.anchor == "s" and found.members == ("s", "a", "b")
    assert found.evidence["degree"] == pytest.approx(2 / 3, abs=1e-5)
    assert find_unstable(deps, SmellConfig(unstable_min_degree=0.9)) == []
    assert find_unstable(deps, SmellConfig(unstable_min_outgoing=4)) == []


# --- insieme ----------------------------------------------------------------------------------------------


@pytest.mark.parametrize("fixture", FIXTURES)
def test_detect_gives_one_of_each_in_a_stable_order(fixture: str) -> None:
    smells = detect(fixture_deps(fixture), fixture_config(fixture))
    assert [(s.rule_id, s.scope) for s in smells] == [
        (CYCLIC, "module"), (CYCLIC, "package"), (HUB_LIKE, "module"), (UNSTABLE, "package"),
    ]  # fmt: skip
    assert smells == detect(fixture_deps(fixture), fixture_config(fixture))
    assert all(isinstance(s, Smell) and s.anchor == s.members[0] for s in smells)


def test_detect_on_an_empty_graph_is_empty() -> None:
    assert detect(build(make([], []))) == []
