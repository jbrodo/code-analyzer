"""Equivalenza tra i modelli del golden set e i loro schemi in `schemas/` (come C-07)."""

import pytest
from conftest import Json, errors_of
from pydantic import ValidationError
from test_golden_set_contract import INVALID, VALID, VALIDATORS, cases

from ca_core.models.golden_set import GoldenLabels, GoldenSample

MODELS = {"golden-sample": GoldenSample, "golden-labels": GoldenLabels}


@pytest.mark.parametrize("name,instance", cases(VALID) + cases(INVALID))
def test_model_and_schema_agree(name: str, instance: Json) -> None:
    try:
        MODELS[name].model_validate(instance)
        accepted = True
    except ValidationError:
        accepted = False
    assert accepted == (errors_of(VALIDATORS[name], instance) == [])
