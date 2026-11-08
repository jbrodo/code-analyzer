"""Equivalenza tra i modelli di manifest e `schemas/plugin-manifest.schema.json`.

ECCEZIONE VOLUTA alla regola di C-07 (i test di contratto non importano `ca_core.models`):
vedi `test_finding_model_equivalence.py`. Ogni differenza non elencata in `MODEL_ONLY` fa fallire.
"""

import pytest
from conftest import Json, case_params, errors_of, make_validator
from pydantic import ValidationError
from test_manifest_contract import (
    PACKAGED_INVALID,
    PACKAGED_VALID,
    SOURCE_INVALID,
    SOURCE_VALID,
)

from ca_core.models import PackagedPluginManifest, PluginManifest

SOURCE = make_validator("plugin-manifest")
PACKAGED = make_validator("plugin-manifest", "PackagedPluginManifest")

# Rifiutati solo dal modello: vuoto finché non emergono differenze (da elencare per nome).
MODEL_ONLY: dict[str, Json] = {}


def _accepts(model: type, instance: object) -> bool:
    try:
        model.model_validate(instance)
    except ValidationError:
        return False
    return True


@pytest.mark.parametrize(
    "instance", case_params(SOURCE_VALID, "valid:") + case_params(SOURCE_INVALID, "invalid:")
)
def test_source_model_and_schema_agree(instance: Json) -> None:
    assert _accepts(PluginManifest, instance) == (errors_of(SOURCE, instance) == [])


@pytest.mark.parametrize(
    "instance",
    case_params(PACKAGED_VALID, "valid:")
    + case_params(PACKAGED_INVALID, "invalid:")
    + case_params(SOURCE_INVALID, "source-invalid:"),
)
def test_packaged_model_and_schema_agree(instance: Json) -> None:
    assert _accepts(PackagedPluginManifest, instance) == (errors_of(PACKAGED, instance) == [])


def test_model_only_rules_are_rejected_by_model_and_accepted_by_schema() -> None:
    """Vuoto oggi (nessun parametro: pytest salterebbe); ogni voce futura va elencata per nome."""
    for name, instance in MODEL_ONLY.items():
        assert not _accepts(PluginManifest, instance), name
        assert errors_of(SOURCE, instance) == [], name
