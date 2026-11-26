"""Contratto `scoring-benchmark`: la distribuzione di benchmark della Variante B (ADR-0023, K-06).

Un dato del prodotto, versionato nel pacchetto (`ca_core/scoring/benchmark.json`) e ricalcolato
solo con la procedura di `scripts/benchmark/` (D2-11). Contiene solo numeri e l'identità del corpus
pubblico: nessun percorso, nome di funzione o testo del codice misurato.

Ogni distribuzione è la miscela a pesi uguali delle distribuzioni dei repository che hanno
osservazioni per quella metrica, descritta dai suoi quantili ai livelli di `levels` (percentuali,
una griglia per tutto il file). La griglia è più fitta nella coda alta, l'unica che l'indice di
intensità usa: le soglie delle regole stanno oltre il 94° percentile. Che i livelli crescano da 0
a 100, che i quantili non decrescano e che le lunghezze coincidano lo controlla il lettore
(`ca_core.scoring.benchmark`): lo schema JSON non lo sa esprimere.
"""

from typing import Annotated, Literal

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, StrictInt

MAX_LEVELS = 1001

_Name = Annotated[str, Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9@][\w./@-]*$")]
_Version = Annotated[str, Field(min_length=1, max_length=64, pattern=r"^[0-9A-Za-z.+\-]+$")]
_Count = Annotated[StrictInt, Field(ge=1)]
_Value = Annotated[float, Field(ge=0, strict=True)]  # un intero JSON vale come numero


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class CorpusRepository(_Strict):
    url: str = Field(
        max_length=200,
        pattern=r"^https://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$",
        description="Repository pubblico del corpus (D2-11).",
    )
    commit: str = Field(pattern=r"^[0-9a-f]{40}$")
    tag: _Version | None = Field(default=None, description="Tag di rilascio del commit, se c'è.")


class Distribution(_Strict):
    repositories: _Count = Field(description="Repository con almeno un'osservazione.")
    observations: _Count
    quantiles: list[_Value] = Field(
        min_length=2, max_length=MAX_LEVELS, description="Un valore per ogni livello di `levels`."
    )


class CodeMetric(Distribution):
    engine: Literal["ruff", "eslint"]
    rule_id: _Name


class SmellSize(Distribution):
    rule_id: _Name = Field(description="Regola dello smell di `ca-graph` (ADR-0020).")
    scope: Literal["module", "package"]


class ScoringBenchmark(_Strict):
    version: StrictInt = Field(ge=1, description="Cambia a ogni ricalcolo.")
    created_at: AwareDatetime
    corpus: list[CorpusRepository] = Field(min_length=1)
    levels: list[Annotated[float, Field(ge=0, le=100, strict=True)]] = Field(
        min_length=2, max_length=MAX_LEVELS, description="Livelli dei quantili, in percentuale."
    )
    engines: dict[_Name, _Version] = Field(
        min_length=1,
        description="Versione dei plugin che hanno misurato; ciascuna fissa il suo motore.",
    )
    code_metrics: list[CodeMetric]
    smell_sizes: list[SmellSize]
