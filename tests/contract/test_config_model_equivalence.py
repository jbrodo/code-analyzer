"""Equivalenza tra `CodeAnalyzerConfig` e `schemas/code-analyzer-config.schema.json`.

ECCEZIONE VOLUTA alla regola di C-07 (i test di contratto non importano `ca_core.models`):
vedi `test_finding_model_equivalence.py`. Ogni differenza non elencata in `MODEL_ONLY` fa fallire.
"""

import pytest
from conftest import Json, case_params, errors_of, make_validator
from pydantic import ValidationError
from test_config_contract import FORBIDDEN, INVALID, VALID

from ca_core.models import CodeAnalyzerConfig

VALIDATOR = make_validator("code-analyzer-config")

# Nessun vincolo del modello è oggi assente dallo schema di config.
MODEL_ONLY: dict[str, Json] = {}


def _model_accepts(instance: object) -> bool:
    try:
        CodeAnalyzerConfig.model_validate(instance)
    except ValidationError:
        return False
    return True


@pytest.mark.parametrize(
    "instance",
    case_params(VALID, "valid:")
    + case_params(INVALID, "invalid:")
    + case_params(FORBIDDEN, "forbidden:"),
)
def test_model_and_schema_agree(instance: Json) -> None:
    assert _model_accepts(instance) == (errors_of(VALIDATOR, instance) == [])


def test_schema_rejects_version_true() -> None:
    """`True == 1` in Python: `const: 1` non deve accettarlo."""
    assert errors_of(VALIDATOR, {"version": True}) != []


def test_model_rejects_version_true() -> None:
    assert not _model_accepts({"version": True})


def test_model_only_rules_are_rejected_by_model_and_accepted_by_schema() -> None:
    """Vuoto oggi (nessun parametro: pytest salterebbe); ogni voce futura va elencata per nome."""
    for name, instance in MODEL_ONLY.items():
        assert not _model_accepts(instance), name
        assert errors_of(VALIDATOR, instance) == [], name
