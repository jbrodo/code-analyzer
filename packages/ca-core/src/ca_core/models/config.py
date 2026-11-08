"""Contratto `code-analyzer-config` (§8 più `paths.exclude`, ADR-0014).

Il file sta nel repository analizzato: input non fidato. Nessuna chiave per immagine, digest,
firma, isolamento, rete, montaggi, comando o origine dei feed: `extra="forbid"` le rifiuta.
Chiavi aggiunte in futuro dentro la versione 1 devono restare compatibili (ADR-0003).
"""

import re
from datetime import date
from enum import StrEnum
from typing import Annotated, Literal, Self

from pydantic import (
    AfterValidator,
    BaseModel,
    BeforeValidator,
    ConfigDict,
    Field,
    JsonValue,
    StrictBool,
    StrictInt,
    model_validator,
)

from ca_core.models.finding import FINGERPRINT_PATTERN, Level

# Equivalente di `_relative_posix` per lo schema: iniziale `/` o `\\`, lettera di unità, segmento
# `..` tra `/` e `\\`. Il lookahead al posto di `$` evita il caso di un `\n` finale.
_NOT_RELATIVE = r"^(?:[/\\]|[A-Za-z]:)|(?:^|[/\\])\.\.(?![^/\\])"


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


RelativePath = Annotated[
    str,
    Field(min_length=1, json_schema_extra={"not": {"pattern": _NOT_RELATIVE}}),
    AfterValidator(_relative_posix),
]


class GateMode(StrEnum):
    """IPOTESI D-0009-A: in Fase 1 `new-findings-only` è valutato come `all`. Togliere con essa."""

    ALL = "all"
    NEW_FINDINGS_ONLY = "new-findings-only"


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Service(_Strict):  # inerte in Fase 1
    catalog_id: str | None = None
    tier: StrictInt | None = Field(default=None, ge=1)
    internet_facing: StrictBool | None = None


class Scoring(_Strict):  # inerte in Fase 1
    variant: Literal["A", "B"] = "A"


class Paths(_Strict):
    exclude: list[RelativePath] = Field(default_factory=list)  # glob relativi


def _level_rules() -> list[JsonValue]:
    """Per ogni livello: se è in `block_on`, non può essere in `warn_on` (generato da `Level`)."""
    return [
        {
            "if": {
                "properties": {"block_on": {"type": "array", "contains": {"const": level.value}}},
                "required": ["block_on"],
            },
            "then": {
                "properties": {
                    "warn_on": {"not": {"type": "array", "contains": {"const": level.value}}}
                }
            },
        }
        for level in Level
    ]


class Gate(_Strict):
    model_config = ConfigDict(extra="forbid", json_schema_extra={"allOf": _level_rules()})

    mode: GateMode = GateMode.ALL
    # Assenti: decide il gate (flag CLI, poi critico/alto, ADR-0009); niente default qui.
    block_on: list[Level] | None = None
    warn_on: list[Level] | None = None


class Licenses(_Strict):
    forbidden: list[str] = Field(default_factory=list)  # identificatori SPDX
    require_approval: list[str] = Field(default_factory=list)
    distributed_product: StrictBool | None = None


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
    enabled: StrictBool | None = None
    max_phase: StrictInt | None = Field(default=None, ge=1, le=8)
    llm_provider: str | None = None


def _not_bool(value: object) -> object:
    if isinstance(value, bool):  # `True == 1`: `Literal[1]` lo accetterebbe, lo schema no
        raise ValueError("deve essere l'intero 1")
    return value


SchemaVersion1 = Annotated[Literal[1], BeforeValidator(_not_bool)]


class CodeAnalyzerConfig(_Strict):
    version: SchemaVersion1
    languages: list[str] = Field(default_factory=list)
    paths: Paths = Field(default_factory=Paths)
    service: Service | None = None
    scoring: Scoring | None = None
    gate: Gate = Field(default_factory=Gate)
    licenses: Licenses | None = None  # assente (None) diverso da vuota: ADR-0013
    plugins: Plugins = Field(default_factory=Plugins)
    exceptions: list[ConfigException] = Field(default_factory=list)
    agents: Agents | None = None

    @model_validator(mode="after")
    def _levels_not_in_both(self) -> Self:
        both = set(self.gate.block_on or []) & set(self.gate.warn_on or [])
        if both:
            raise ValueError(f"livelli sia in block_on sia in warn_on: {sorted(both)}")
        return self
