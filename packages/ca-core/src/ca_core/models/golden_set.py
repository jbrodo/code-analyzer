"""Contratti `golden-sample` e `golden-labels`: il golden set del triage (G3-02, ADR-0034).

Il repository è pubblico, quindi nel golden set entrano solo **riferimenti** a repository pubblici
(indirizzo, commit, fingerprint, posizione) e i giudizi umani: nessuna riga di codice, nessun
messaggio dei tool, nessuna nota. Il codice si rilegge in locale dal commit indicato.

Il campione non porta livello, severità né punteggio: chi annota non li vede.
"""

from typing import Annotated, Literal

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, StrictInt

MAX_ITEMS = 5000

SetName = Literal["pilota", "pilota-2", "pilota-3", "calibrazione", "test", "addestramento"]
Label = Literal["vero", "falso-positivo", "non-so"]

_Url = Annotated[
    str,
    Field(max_length=200, pattern=r"^https://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$"),
]
_Commit = Annotated[str, Field(pattern=r"^[0-9a-f]{40}$")]
_Digest = Annotated[str, Field(pattern=r"^sha256:[0-9a-f]{64}$")]
_Rule = Annotated[str, Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9][\w./-]*$")]
_Line = Annotated[StrictInt, Field(ge=1)]
_Positive = Annotated[StrictInt, Field(ge=1)]


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Sampling(_Strict):
    seed: str = Field(min_length=1, max_length=64)
    cap_per_repository_and_rule: _Positive
    excluded_rules: list[_Rule]
    pool_size: _Positive = Field(
        description="Punti di codice tra cui si è estratto, dopo filtri e tetto."
    )


class SampleItem(_Strict):
    repository: _Url = Field(description="Repository pubblico.")
    commit: _Commit
    tool: _Rule
    rule_id: _Rule
    path: str = Field(
        min_length=1,
        max_length=1024,
        pattern=r"^[^/\x00][^\x00]*$",
        description="Percorso relativo alla radice del repository.",
    )
    start_line: _Line
    end_line: _Line
    fingerprint: _Digest = Field(description="Fingerprint del finding (ADR-0008).")


class GoldenSample(_Strict):
    version: Literal[1]
    set: SetName
    language: Literal["python"]
    sampling: Sampling
    items: list[SampleItem] = Field(
        min_length=1, max_length=MAX_ITEMS, description="Nell'ordine in cui si annotano."
    )


class LabelItem(_Strict):
    repository: _Url
    fingerprint: _Digest
    label: Label
    seconds: Annotated[StrictInt, Field(ge=0)] = Field(
        description="Tempo in cui la voce è stata sullo schermo con la pagina in uso."
    )


class GoldenLabels(_Strict):
    version: Literal[1]
    set: SetName
    sample_sha256: _Digest = Field(description="Digest del file del campione annotato.")
    annotator: str = Field(
        pattern=r"^annotatore-[0-9]{1,3}$",
        description="Una persona, indicata senza nome. Un modello non annota.",
    )
    round: _Positive = Field(description="1 per il primo giro; oltre, riannotazione.")
    delivered_at: AwareDatetime
    labels: list[LabelItem] = Field(min_length=1, max_length=MAX_ITEMS)
