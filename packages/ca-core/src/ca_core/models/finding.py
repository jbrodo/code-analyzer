"""Contratto `finding` (§4.1 rivisto da ADR-0008 e ADR-0009). Solo dati."""

from enum import StrEnum
from typing import Any, Self

from pydantic import (
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
    # Fase 2: SCORE = "score", OVERRIDE = "override" (aggiunte compatibili).


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
    status: Status = Status.OPEN
    owner: str | None = None
    due_date: AwareDatetime | None = None
    first_seen: AwareDatetime  # senza database: ora della scansione
    last_seen: AwareDatetime

    @model_validator(mode="after")
    def _tool_is_first_of_tools(self) -> Self:
        if len(set(self.tools)) != len(self.tools):
            raise ValueError("tools contiene duplicati")
        if self.tool != min(self.tools):
            raise ValueError("tool deve essere il primo di tools in ordine lessicografico")
        return self
