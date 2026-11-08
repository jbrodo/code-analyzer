"""Equivalenza tra `PluginSarifProperties` e `schemas/plugin-sarif-properties.schema.json`.

ECCEZIONE VOLUTA alla regola di C-07 (i test di contratto non importano `ca_core.models`):
questo è l'unico test che importa il modello, perché verifica proprio che modello e schema
accettino e rifiutino gli stessi casi (rinvio di `backend`). Va tenuto in un file a parte.
Importa i casi dal modulo gemello solo per riuso dei dati, non la logica di validazione.
"""

import pytest
from conftest import errors_of, make_validator
from pydantic import ValidationError
from test_sarif_properties_contract import INVALID, VALID

from ca_core.models.plugin_sarif import PluginSarifProperties

VALIDATOR = make_validator("plugin-sarif-properties")

# DISCREPANZA NOTA modello/schema (segnalata a `backend`/`architect`): in modalità lax Pydantic
# coerce la stringa "9" in float, lo schema la rifiuta (`type: number`). Il modello è più permissivo
# del contratto che vedono gli adattatori. `strict=True`: quando il modello sarà corretto
# (es. `Cvss.score: StrictFloat`) l'xfail diventa XPASS e fa fallire il test, da rimuovere.
KNOWN_MODEL_GAPS = {
    "cvss-score-string": "il modello coerce str->float, lo schema no",
}
_XFAIL = {
    k: pytest.mark.xfail(strict=True, reason=r, raises=AssertionError)
    for k, r in KNOWN_MODEL_GAPS.items()
}


def _params(cases: dict, prefix: str = ""):
    return [pytest.param(v, id=f"{prefix}{k}", marks=_XFAIL.get(k, ())) for k, v in cases.items()]


def _model_accepts(instance: object) -> bool:
    try:
        PluginSarifProperties.model_validate(instance)
    except ValidationError:
        return False
    return True


@pytest.mark.parametrize("instance", _params(VALID, "valid:") + _params(INVALID, "invalid:"))
def test_model_and_schema_agree(instance: dict) -> None:
    assert _model_accepts(instance) == (errors_of(VALIDATOR, instance) == [])


@pytest.mark.parametrize("instance", _params(VALID))
def test_model_accepts_every_valid_case(instance: dict) -> None:
    assert _model_accepts(instance)


@pytest.mark.parametrize("instance", _params(INVALID))
def test_model_rejects_every_invalid_case(instance: dict) -> None:
    assert not _model_accepts(instance)
