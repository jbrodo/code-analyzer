"""Equivalenza tra `ScoringBenchmark` e `schemas/scoring-benchmark.schema.json`.

ECCEZIONE VOLUTA alla regola di C-07: vedi `test_finding_model_equivalence.py`. L'ordine dei
quantili non è nello schema né nel modello: lo controlla il lettore (`ca_core.scoring.benchmark`).
"""

import pytest
from conftest import Json, case_params, errors_of, make_validator
from pydantic import ValidationError
from test_scoring_benchmark_contract import INVALID, VALID

from ca_core.models.scoring_benchmark import ScoringBenchmark

VALIDATOR = make_validator("scoring-benchmark")


def _model_accepts(instance: object) -> bool:
    try:
        ScoringBenchmark.model_validate(instance)
    except ValidationError:
        return False
    return True


@pytest.mark.parametrize(
    "instance", case_params(VALID, "valid:") + case_params(INVALID, "invalid:")
)
def test_model_and_schema_agree(instance: Json) -> None:
    assert _model_accepts(instance) == (errors_of(VALIDATOR, instance) == [])
