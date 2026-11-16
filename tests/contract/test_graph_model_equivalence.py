"""Equivalenza tra `Graph` e `schemas/graph.schema.json`.

ECCEZIONE VOLUTA alla regola di C-07 (i test di contratto non importano `ca_core.models`):
vedi `test_finding_model_equivalence.py`. Ogni differenza non elencata in `MODEL_ONLY` fa fallire.
"""

import pytest
from conftest import Json, case_params, errors_of, make_validator, mutated
from pydantic import ValidationError
from test_graph_contract import FULL, INVALID, MINIMAL, VALID, A, B

from ca_core.models.graph import Graph

VALIDATOR = make_validator("graph")
EDGE: Json = {"source": "app/a.py", "target": "app/b.py", "imports": 1, "confidence": "dichiarato"}


def _with(**kv: object):
    return lambda i: i.update(kv)


# Rifiutati solo dal modello (ADR-0003, "Dove vive un'invariante"): lo schema li accetta.
MODEL_ONLY: dict[str, Json] = {
    "modules-not-sorted": mutated(MINIMAL, _with(modules=[B, A])),
    "modules-duplicate-path": mutated(MINIMAL, _with(modules=[A, A])),
    "edges-duplicate": mutated(MINIMAL, _with(modules=[A, B], edges=[EDGE, EDGE])),
    "edge-from-missing-module": mutated(MINIMAL, _with(modules=[B], edges=[EDGE])),
    "edge-to-missing-module": mutated(MINIMAL, _with(modules=[A], edges=[EDGE])),
    "edge-to-missing-external": mutated(
        MINIMAL, _with(modules=[A], edges=[{**EDGE, "target": "requests", "external": True}])
    ),
    "edge-to-itself": mutated(MINIMAL, _with(modules=[A], edges=[{**EDGE, "target": "app/a.py"}])),
    "entrypoint-on-missing-module": mutated(
        MINIMAL,
        _with(entrypoints=[{"path": "app/a.py", "kind": "main-module", "confidence": "dedotto"}]),
    ),
    # Senza un validatore di formato installato lo schema non controlla il fuso orario.
    "history-naive-head-time": mutated(
        MINIMAL, lambda i: i["history"].update(head_time="2026-11-13T10:00:00")
    ),
    "churn-with-shallow-history": mutated(
        FULL, lambda i: i["history"].update(status="superficiale")
    ),
}


def _model_accepts(instance: object) -> bool:
    try:
        Graph.model_validate(instance)
    except ValidationError:
        return False
    return True


@pytest.mark.parametrize(
    "instance", case_params(VALID, "valid:") + case_params(INVALID, "invalid:")
)
def test_model_and_schema_agree(instance: Json) -> None:
    assert _model_accepts(instance) == (errors_of(VALIDATOR, instance) == [])


@pytest.mark.parametrize("instance", case_params(MODEL_ONLY))
def test_model_only_rules_are_rejected_by_model_and_accepted_by_schema(instance: Json) -> None:
    assert not _model_accepts(instance)
    assert errors_of(VALIDATOR, instance) == []


def test_full_example_round_trips_through_the_model() -> None:
    graph = Graph.model_validate(FULL)
    again = Graph.model_validate_json(graph.model_dump_json())
    assert again == graph
    assert [m.churn for m in graph.modules] == [4, 0, 1]
