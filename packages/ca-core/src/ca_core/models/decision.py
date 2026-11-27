"""Contratti `decision` e `decision-thresholds`: il motore decisionale (§10, ADR-0036).

Una `Decision` è un suggerimento: non cambia stato, livello, punteggio o gate. In questa fetta c'è
solo `is_true_positive`; «true» vuol dire «vero» nel senso di ADR-0034. Rinunciare a decidere non è
compito del motore ma dell'instradamento (`ca_decision.routing`).

L'evidenza contiene codice: si passa al motore e non si registra né si riporta in errori e log.
"""

import math
from typing import Annotated, Literal, Self

from pydantic import BaseModel, ConfigDict, Field, StrictBool, StrictInt, model_validator

QuestionId = Literal["is_true_positive"]
DecisionKind = Literal["boolean"]
Route = Literal["suggerimento", "umano"]

SUM_TOLERANCE = 0.001

# Strict: un booleano o una stringa non valgono come numero; un intero JSON sì.
_Unit = Annotated[float, Field(ge=0, le=1, strict=True)]
_Model = Annotated[str, Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9][\w./-]*$")]
_Digest = Annotated[str, Field(pattern=r"^sha256:[0-9a-f]{64}$")]


class _Frozen(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, protected_namespaces=())


class Evidence(_Frozen):
    """Ciò che il motore può leggere, già ridotto entro il suo limite da chi lo seleziona."""

    text: str = Field(min_length=1, max_length=100_000)
    reduced: StrictBool = Field(
        description="Chi l'ha selezionata ha tolto parti per rientrare nel limite."
    )


class Probabilities(_Frozen):
    true: _Unit
    false: _Unit


class Decision(_Frozen):
    question_id: QuestionId
    kind: DecisionKind
    probabilities: Probabilities
    score: None = Field(default=None, description="Per le domande a punteggio, non ancora fatte.")
    confidence: _Unit = Field(description="Dichiarata dal motore: non è una probabilità calibrata.")
    model: _Model
    model_version: _Digest = Field(description="Digest dei pesi.")

    @model_validator(mode="after")
    def _probabilities_sum_to_one(self) -> Self:
        total = self.probabilities.true + self.probabilities.false
        if not math.isclose(total, 1.0, rel_tol=0, abs_tol=SUM_TOLERANCE):
            raise ValueError("le probabilità non sommano a 1")
        return self


class Threshold(_Frozen):
    """Soglia calibrata per una domanda e per i pesi esatti di un modello."""

    question_id: QuestionId
    model: _Model
    model_version: _Digest
    minimum_confidence: _Unit


class DecisionThresholds(_Frozen):
    """Dato del prodotto, mai letto da `.code-analyzer.yml`. Senza una soglia: `umano`."""

    version: StrictInt = Field(ge=1)
    thresholds: list[Threshold] = Field(max_length=1000)

    @model_validator(mode="after")
    def _one_per_question_and_weights(self) -> Self:
        keys = [(t.question_id, t.model, t.model_version) for t in self.thresholds]
        if len(set(keys)) != len(keys):
            raise ValueError("due soglie per la stessa domanda e gli stessi pesi")
        return self
