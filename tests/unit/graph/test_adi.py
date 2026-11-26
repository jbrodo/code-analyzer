"""G-13: Architectural Debt Index per modulo e per pacchetto (ADR-0023)."""

from typing import Any

import pytest

from ca_core.models.graph import Graph
from ca_graph.adi import with_adi
from ca_graph.pagerank import with_pagerank
from ca_graph.smells import CYCLIC, HUB_LIKE, UNSTABLE, Smell


def module(path: str, *, test: bool = False) -> dict[str, Any]:
    return {"path": path, "language": "python", "parse": "completa", "test": test}


def edge(source: str, target: str) -> dict[str, Any]:
    return {"source": source, "target": target, "imports": 1, "confidence": "dichiarato"}


GRAPH = with_pagerank(
    Graph.model_validate(
        {
            "version": 1,
            "modules": [module("app/a.py"), module("app/b.py"), module("lib/c.py"),
                        module("tests/test_a.py", test=True)],
            "edges": [edge("app/a.py", "app/b.py"), edge("app/b.py", "app/a.py"),
                      edge("app/b.py", "lib/c.py")],
            "stats": {"files_parsed": 4},
            "history": {"status": "assente", "window_days": 90},
        }
    )
)  # fmt: skip

CYCLE = Smell(CYCLIC, "module", "app/a.py", ("app/a.py", "app/b.py"), {"size": 2})
HUB = Smell(HUB_LIKE, "module", "app/b.py", ("app/b.py",), {"fan_in": 1, "fan_out": 2, "size": 1})
UNSTABLE_APP = Smell(UNSTABLE, "package", "app", ("app", "lib"), {"size": 2})
G = {CYCLIC: 0.5, HUB_LIKE: 0.25, UNSTABLE: 0.125}


def adi(graph: Graph) -> dict[str, float | None]:
    values: dict[str, float | None] = {
        m.path: m.metrics.adi if m.metrics else None for m in graph.modules
    }
    values.update({f"pkg:{p.path}": p.metrics.adi for p in graph.packages})
    return values


def test_adi_sums_the_g_of_every_smell_that_includes_the_module() -> None:
    out = with_adi(GRAPH, [CYCLE, HUB, UNSTABLE_APP], lambda s: G[s.rule_id])
    assert adi(out) == {
        "app/a.py": 0.63,  # ciclo 0,5 + pacchetto 0,125 = 0,625, due decimali
        "app/b.py": 0.88,  # ciclo, hub e pacchetto: 0,875
        "lib/c.py": 0.13,  # solo il pacchetto `lib`, membro dello smell
        "tests/test_a.py": None,  # di test: senza metriche, senza ADI
        "pkg:app": 1.5,  # somma sui moduli prima dell'arrotondamento: 0,625 + 0,875
        "pkg:lib": 0.13,
    }


def test_a_smell_without_g_does_not_count_and_modules_without_smells_are_zero() -> None:
    out = with_adi(GRAPH, [CYCLE, HUB], lambda s: None if s.rule_id == HUB_LIKE else 0.5)
    assert adi(out)["app/b.py"] == 0.5 and adi(out)["lib/c.py"] == 0.0


def test_without_smells_every_module_has_zero_and_the_graph_still_conforms() -> None:
    out = with_adi(GRAPH, [], lambda s: pytest.fail("nessuno smell"))
    assert {v for k, v in adi(out).items() if v is not None} == {0.0}
    Graph.model_validate_json(out.model_dump_json())
