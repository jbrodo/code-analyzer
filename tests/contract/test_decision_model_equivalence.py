"""Equivalenza tra i modelli del motore decisionale e i loro schemi (come C-07).

ECCEZIONE VOLUTA: la somma delle probabilità e l'unicità delle soglie non si esprimono nello
schema JSON; le controlla solo il modello (test in `tests/unit/test_ca_decision.py`).
"""

import pytest
from conftest import Json, errors_of
from pydantic import ValidationError
from test_decision_contract import INVALID, VALID, VALIDATORS, cases

from ca_core.models.decision import Decision, DecisionThresholds, Evidence

MODELS = {"decision": Decision, "evidence": Evidence, "decision-thresholds": DecisionThresholds}


@pytest.mark.parametrize("name,instance", cases(VALID) + cases(INVALID))
def test_model_and_schema_agree(name: str, instance: Json) -> None:
    try:
        MODELS[name].model_validate(instance)
        accepted = True
    except ValidationError:
        accepted = False
    assert accepted == (errors_of(VALIDATORS[name], instance) == [])
