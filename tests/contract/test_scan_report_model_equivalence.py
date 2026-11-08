"""Equivalenza tra `ScanReport` e `schemas/scan-report.schema.json`.

ECCEZIONE VOLUTA alla regola di C-07 (i test di contratto non importano `ca_core.models`):
vedi `test_finding_model_equivalence.py`. Ogni differenza non elencata in `MODEL_ONLY` fa fallire.
"""

import pytest
from conftest import Json, case_params, errors_of, make_validator, mutated
from pydantic import ValidationError
from test_scan_report_contract import FINDING, INVALID, MINIMAL, PLUGIN_OK, VALID

from ca_core.models import ScanReport

VALIDATOR = make_validator("scan-report")

# Rifiutati solo dal modello (ADR-0003, "Dove vive un'invariante"): lo schema li accetta.
MODEL_ONLY: dict[str, Json] = {
    "plugin-names-not-unique": mutated(MINIMAL, lambda i: i.update(plugins=[PLUGIN_OK, PLUGIN_OK])),
    "disabled-plugin-also-run": mutated(MINIMAL, lambda i: i.update(disabled_plugins=["bandit"])),
    "embedded-finding-tool-not-first": mutated(
        MINIMAL,
        lambda i: i.update(findings=[{**FINDING, "tool": "z", "tools": ["a", "z"]}]),
    ),
    "embedded-finding-end-line-before-start-line": mutated(
        MINIMAL,
        lambda i: i.update(
            findings=[{**FINDING, "location": {"repository": "r", "start_line": 5, "end_line": 4}}]
        ),
    ),
}


def _model_accepts(instance: object) -> bool:
    try:
        ScanReport.model_validate(instance)
    except ValidationError:
        return False
    return True


@pytest.mark.parametrize(
    "instance", case_params(VALID, "valid:") + case_params(INVALID, "invalid:")
)
def test_model_and_schema_agree(instance: Json) -> None:
    assert _model_accepts(instance) == (errors_of(VALIDATOR, instance) == [])


def test_schema_rejects_version_true() -> None:
    """`True == 1` in Python: `const: 1` non deve accettarlo."""
    assert errors_of(VALIDATOR, mutated(MINIMAL, lambda i: i.update(version=True))) != []


def test_model_rejects_version_true() -> None:
    assert not _model_accepts(mutated(MINIMAL, lambda i: i.update(version=True)))


@pytest.mark.parametrize("instance", case_params(MODEL_ONLY))
def test_model_only_rules_are_rejected_by_model_and_accepted_by_schema(instance: Json) -> None:
    assert not _model_accepts(instance)
    assert errors_of(VALIDATOR, instance) == []
