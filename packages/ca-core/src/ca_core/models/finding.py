"""Contratto `finding` (§4.1 rivisto da ADR-0008 e ADR-0009). Solo dati."""

import re
from enum import StrEnum
from typing import Annotated, Any, Literal, Self

from pydantic import (
    AfterValidator,
    AwareDatetime,
    BaseModel,
    ConfigDict,
    Field,
    StrictFloat,
    StrictInt,
    model_validator,
)

FINGERPRINT_PATTERN = r"^sha256:[0-9a-f]{64}$"


class Category(StrEnum):
    QUALITY = "quality"
    ARCHITECTURE = "architecture"
    TEST = "test"
    SAST = "sast"
    DEPENDENCY = "dependency"
    LICENSE = "license"
    SECRET = "secret"
    IAC = "iac"
    HEALTH = "health"


class Level(StrEnum):
    CRITICAL = "critico"
    HIGH = "alto"
    MEDIUM = "medio"
    LOW = "basso"


class Status(StrEnum):
    OPEN = "aperto"
    IN_PROGRESS = "in_corso"
    ACCEPTED = "accettato"
    FALSE_POSITIVE = "falso_positivo"
    RESOLVED = "risolto"


class LevelSource(StrEnum):
    """IPOTESI D-0009-A: origine del livello provvisorio. Togliere con il campo `level_source`."""

    TOOL_SEVERITY = "tool_severity"
    POLICY = "policy"
    DEFAULT = "default"
    SCORE = "score"  # Fase 2 (C-01): livello da punteggio, attivo dopo il Gate 2 (D2-10)
    OVERRIDE = "override"  # Fase 2: livello forzato da un override (§6.3)


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Location(_Strict):
    repository: str
    commit: str | None = None  # ADR-0008: cartella non git
    path: str | None = None
    start_line: StrictInt | None = Field(default=None, ge=1)
    end_line: StrictInt | None = Field(
        default=None,
        ge=1,
        description="Non precedente a `start_line` (vincolo del modello, non dello schema).",
    )
    purl: str | None = None  # per le librerie
    dependency_path: list[str] = Field(default_factory=list)  # catena transitiva

    @model_validator(mode="after")
    def _lines_ordered(self) -> Self:
        if (
            self.start_line is not None
            and self.end_line is not None
            and self.end_line < self.start_line
        ):
            raise ValueError("end_line precede start_line")
        return self


class ImpactFactors(_Strict):
    g: StrictFloat = Field(ge=0, le=1)  # gravità
    p: StrictFloat = Field(ge=0, le=1)  # probabilità
    e: StrictFloat = Field(ge=0, le=1)  # esposizione
    c: StrictFloat = Field(ge=0, le=1)  # criticità
    variant: str = Field(pattern=r"^[AB]$")
    evidence: dict[str, Any] = Field(default_factory=dict)  # cvss, epss, kev, pagerank…


class BaselineState(StrEnum):
    """Stato rispetto alla baseline (ADR-0025). Un finding `risolto` non è nel report: sta nella
    sezione `baseline` di `scan-report`. Assente: nessuna baseline valida."""

    NEW = "new"
    EXISTING = "existing"


class RemediationSource(StrEnum):
    TOOL = "tool"  # testo di aiuto della regola nel SARIF del plugin
    RULE = "rule"  # regole proprie del prodotto
    DERIVED = "derived"  # frase a schema fisso dal nucleo, per esempio la versione corretta


_CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")  # a capo e tabulazione ammessi
_URL = r"^https?://[^\s\x00-\x1f\x7f]{1,2040}$"
MAX_REMEDIATION_TEXT = 4000
MAX_REFERENCES = 10


def _no_control(value: str) -> str:
    if _CONTROL.search(value):
        raise ValueError("carattere di controllo nel testo")
    return value


# Come `RelativePath` di `config` (che importa questo modulo: qui non si può importare) e in più
# nessun carattere di controllo: il percorso arriva in UI, commenti e log.
_NOT_RELATIVE = r"^(?:[/\\]|[A-Za-z]:)|(?:^|[/\\])\.\.(?![^/\\])|[\x00-\x1f\x7f]"


def _relative_file(value: str) -> str:
    if (
        not value
        or value.startswith(("/", "\\"))
        or re.match(r"^[A-Za-z]:", value)
        or ".." in re.split(r"[\\/]", value)
        or re.search(r"[\x00-\x1f\x7f]", value)
    ):
        raise ValueError(f"percorso non relativo al workspace: {value!r}")
    return value


RelativeFilePath = Annotated[
    str,
    Field(min_length=1, max_length=4096, json_schema_extra={"not": {"pattern": _NOT_RELATIVE}}),
    AfterValidator(_relative_file),
]


class Remediation(_Strict):
    """I passi per risolvere un finding (ADR-0029). Sempre testo semplice: né l'API né la UI lo
    interpretano come HTML o Markdown. È della regola, non del risultato: nessun contenuto del
    repository analizzato. Nessun testo generato (gli LLM sono della Fase 3)."""

    text: Annotated[str, Field(min_length=1, max_length=MAX_REMEDIATION_TEXT)]
    references: list[Annotated[str, Field(pattern=_URL)]] = Field(
        default_factory=list, max_length=MAX_REFERENCES, json_schema_extra={"uniqueItems": True}
    )
    source: RemediationSource

    @model_validator(mode="after")
    def _plain_text(self) -> Self:
        _no_control(self.text)
        if len(set(self.references)) != len(self.references):
            raise ValueError("riferimenti duplicati")
        return self


class VariantScore(_Strict):
    """Punteggio in ombra di una variante (D2-10, ADR-0018): si calcolano A e B insieme, e ciascuna
    porta i suoi fattori con la loro evidenza. La forma esatta dei fattori è di ADR-0021 (A-06,
    ancora da scrivere): qui solo ciò che ADR-0018 già fissa."""

    variant: Literal["A", "B"]
    score: StrictFloat = Field(ge=0, le=100)
    level: Level  # livello da punteggio: attivo solo dopo il Gate 2
    impact: ImpactFactors

    @model_validator(mode="after")
    def _factors_of_the_same_variant(self) -> Self:
        if self.impact.variant != self.variant:
            raise ValueError("i fattori sono di un'altra variante")
        return self


class Finding(_Strict):
    id: str  # senza database uguale al fingerprint; opaco per i consumatori
    fingerprint: str = Field(pattern=FINGERPRINT_PATTERN)  # stabile tra scansioni
    category: Category
    rule_id: str
    tool: str = Field(
        description="Primo di `tools` in ordine lessicografico (vincolo del modello, non dello "
        "schema)."
    )
    tools: list[str] = Field(
        min_length=1,
        json_schema_extra={"uniqueItems": True},
        description="Tutti i tool di origine.",
    )
    title: str
    message: str
    location: Location
    cwe: list[str] = Field(default_factory=list)
    cve: list[str] = Field(default_factory=list)
    license_spdx: str | None = None
    # Raggruppata per tool; ulteriori percorsi e versioni in `evidence.occurrences`.
    evidence: dict[str, Any] = Field(default_factory=dict)
    impact: ImpactFactors | None = None  # null in Fase 1
    score: StrictFloat | None = Field(default=None, ge=0, le=100)  # null in Fase 1
    level: Level | None = None
    level_source: LevelSource | None = None  # IPOTESI D-0009-A
    variant_scores: list[VariantScore] = Field(
        default_factory=list,
        max_length=2,
        description="Punteggi in ombra di A e B (D2-10). Varianti uniche (vincolo del modello).",
    )
    baseline_state: BaselineState | None = None
    previous_path: RelativeFilePath | None = Field(
        default=None,
        description="Percorso nella baseline di un finding accoppiato dopo uno spostamento di "
        "file (ADR-0025, secondo passaggio). Solo con `baseline_state` `existing`.",
    )
    pathless_key: str | None = Field(
        default=None,
        pattern=FINGERPRINT_PATTERN,
        description="Impronta degli ingredienti del fingerprint senza il percorso (ADR-0025): "
        "serve ad accoppiare un finding dopo un cambio di percorso. Non è un identificativo.",
    )
    remediation: Remediation | None = None
    correlation: str | None = Field(
        default=None,
        pattern=r"^cg1:[0-9a-f]{16}$",
        description="Gruppo di correlazione (K-21, ADR-0026): finding di strumenti diversi sullo "
        "stesso problema nello stesso file. Non cambia fingerprint, livello né esito del gate.",
    )
    status: Status = Status.OPEN
    owner: str | None = None
    due_date: AwareDatetime | None = None
    first_seen: AwareDatetime  # senza database: ora della scansione
    last_seen: AwareDatetime

    @model_validator(mode="after")
    def _tool_is_first_of_tools(self) -> Self:
        variants = [s.variant for s in self.variant_scores]
        if len(set(variants)) != len(variants):
            raise ValueError("punteggi in ombra duplicati per variante")
        if self.previous_path is not None and self.baseline_state is not BaselineState.EXISTING:
            raise ValueError("previous_path solo con baseline_state existing")
        if len(set(self.tools)) != len(self.tools):
            raise ValueError("tools contiene duplicati")
        if self.tool != min(self.tools):
            raise ValueError("tool deve essere il primo di tools in ordine lessicografico")
        return self
