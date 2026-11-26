"""Equivalenza tra `ScoringConfig` e `schemas/scoring-config.schema.json`.

ECCEZIONE VOLUTA alla regola di C-07 (i test di contratto non importano `ca_core.models`):
vedi `test_finding_model_equivalence.py`. Ogni differenza non elencata in `MODEL_ONLY` fa fallire.
"""

import pytest
from conftest import Json, case_params, errors_of, make_validator, mutated
from pydantic import ValidationError
from test_scoring_config_contract import DEFAULT, INVALID, VALID, _set

from ca_core.models.scoring_config import ScoringConfig

VALIDATOR = make_validator("scoring-config")

# Rifiutati solo dal modello (ADR-0003, "Dove vive un'invariante"): lo schema li accetta.
MODEL_ONLY: dict[str, Json] = {
    "thresholds-not-descending": mutated(DEFAULT, _set("levels.thresholds.alto", 80)),
    "thresholds-equal": mutated(DEFAULT, _set("levels.thresholds.medio", 40)),
    "severity-not-monotonic": mutated(DEFAULT, _set("g.severity.low", 0.9)),
    "sarif-levels-not-monotonic": mutated(DEFAULT, _set("g.severity.note", 0.9)),
    "tier-1-below-tier-2": mutated(DEFAULT, _set("c.tier_1", 0.5)),
    "e-grows-with-less-reachability": mutated(DEFAULT, _set("e.not_reachable_or_test", 0.9)),
}


def _model_accepts(instance: object) -> bool:
    try:
        ScoringConfig.model_validate(instance)
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
