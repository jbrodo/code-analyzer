"""Contratto `code-analyzer-config` (§8 più `paths.exclude`, ADR-0014).

Il file sta nel repository analizzato: input non fidato. Nessuna chiave per immagine, digest,
firma, isolamento, rete, montaggi, comando o origine dei feed: `extra="forbid"` le rifiuta.
Chiavi aggiunte in futuro dentro la versione 1 devono restare compatibili (ADR-0003).
"""

import re
from datetime import date
from enum import StrEnum
from typing import Annotated, Literal, Self

from pydantic import AfterValidator, BaseModel, ConfigDict, Field, model_validator

from ca_core.models.finding import FINGERPRINT_PATTERN, Level


def _relative_posix(value: str) -> str:
    """Rifiuta percorsi assenti, assoluti o che risalgono; il contenimento vero è a runtime."""
    if (
        not value
        or value.startswith(("/", "\\"))
        or re.match(r"^[A-Za-z]:", value)
        or ".." in re.split(r"[\\/]", value)
    ):
        raise ValueError(f"percorso non relativo al workspace: {value!r}")
    return value


RelativePath = Annotated[str, AfterValidator(_relative_posix)]


class GateMode(StrEnum):
    """IPOTESI D-0009-A: in Fase 1 `new-findings-only` è valutato come `all`. Togliere con essa."""

    ALL = "all"
    NEW_FINDINGS_ONLY = "new-findings-only"


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Service(_Strict):  # inerte in Fase 1
    catalog_id: str | None = None
    tier: int | None = Field(default=None, ge=1)
    internet_facing: bool | None = None


class Scoring(_Strict):  # inerte in Fase 1
    variant: Literal["A", "B"] = "A"


class Paths(_Strict):
    exclude: list[RelativePath] = Field(default_factory=list)  # glob relativi


class Gate(_Strict):
    mode: GateMode = GateMode.ALL
    # Assenti: decide il gate (flag CLI, poi critico/alto, ADR-0009); niente default qui.
    block_on: list[Level] | None = None
    warn_on: list[Level] | None = None


class Licenses(_Strict):
    forbidden: list[str] = Field(default_factory=list)  # identificatori SPDX
    require_approval: list[str] = Field(default_factory=list)
    distributed_product: bool | None = None


class SemgrepOptions(_Strict):
    rules: list[RelativePath] = Field(default_factory=list)


class Plugins(_Strict):
    disable: list[str] = Field(default_factory=list)
    semgrep: SemgrepOptions | None = None  # unico plugin con opzioni in §8


class ConfigException(_Strict):
    fingerprint: str = Field(pattern=FINGERPRINT_PATTERN)
    reason: str = Field(min_length=1)
    expires: date
    approved_by: str = Field(min_length=1)  # dichiarazione, non autenticata


class Agents(_Strict):  # inerte in Fase 1
    enabled: bool | None = None
    max_phase: int | None = Field(default=None, ge=1, le=8)
    llm_provider: str | None = None


class CodeAnalyzerConfig(_Strict):
    version: Literal[1]
    languages: list[str] = Field(default_factory=list)
    paths: Paths = Field(default_factory=Paths)
    service: Service | None = None
    scoring: Scoring | None = None
    gate: Gate = Field(default_factory=Gate)
    licenses: Licenses = Field(default_factory=Licenses)
    plugins: Plugins = Field(default_factory=Plugins)
    exceptions: list[ConfigException] = Field(default_factory=list)
    agents: Agents | None = None

    @model_validator(mode="after")
    def _levels_not_in_both(self) -> Self:
        both = set(self.gate.block_on or []) & set(self.gate.warn_on or [])
        if both:
            raise ValueError(f"livelli sia in block_on sia in warn_on: {sorted(both)}")
        return self
