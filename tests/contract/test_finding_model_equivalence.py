"""Equivalenza tra `Finding` e `schemas/finding.schema.json`.

ECCEZIONE VOLUTA alla regola di C-07 (i test di contratto non importano `ca_core.models`, ADR-0003):
i file `test_*_model_equivalence.py` sono gli unici che importano il modello, qui per verificare
che modello e schema accettino e rifiutino gli stessi casi. Ogni differenza non elencata in
`MODEL_ONLY` fa fallire il test.
"""

import pytest
from conftest import Json, case_params, errors_of, make_validator, mutated
from pydantic import ValidationError
from test_finding_contract import INVALID, MINIMAL, VALID

from ca_core.models import Finding

VALIDATOR = make_validator("finding")

# Rifiutati solo dal modello (ADR-0003, "Dove vive un'invariante"): lo schema li accetta.
MODEL_ONLY: dict[str, Json] = {
    "tool-not-first-of-tools": mutated(MINIMAL, lambda i: i.update(tool="z", tools=["a", "z"])),
    "end-line-before-start-line": mutated(
        MINIMAL,
        lambda i: i.update(location={"repository": "r", "start_line": 5, "end_line": 4}),
    ),
}


def _model_accepts(instance: object) -> bool:
    try:
        Finding.model_validate(instance)
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
