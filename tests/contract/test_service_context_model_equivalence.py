"""Equivalenza tra `ServiceContextFile` e `schemas/service-context.schema.json`.

ECCEZIONE VOLUTA alla regola di C-07: vedi `test_finding_model_equivalence.py`.
"""

import pytest
from conftest import Json, case_params, errors_of, make_validator
from pydantic import ValidationError
from test_service_context_contract import INVALID, VALID

from ca_core.models.service_context_file import ServiceContextFile

VALIDATOR = make_validator("service-context")


def _model_accepts(instance: object) -> bool:
    try:
        ServiceContextFile.model_validate(instance)
    except ValidationError:
        return False
    return True


@pytest.mark.parametrize(
    "instance", case_params(VALID, "valid:") + case_params(INVALID, "invalid:")
)
def test_model_and_schema_agree(instance: Json) -> None:
    assert _model_accepts(instance) == (errors_of(VALIDATOR, instance) == [])
