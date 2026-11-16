"""Contratto `code-analyzer-config` (§8 più `paths.exclude`, ADR-0014).

Il file sta nel repository analizzato: input non fidato. Nessuna chiave per immagine, digest,
firma, isolamento, rete, montaggi, comando o origine dei feed: `extra="forbid"` le rifiuta.
Chiavi aggiunte in futuro dentro la versione 1 devono restare compatibili (ADR-0003).

Fase 2 (C-05, versione 1.1): opzioni per i plugin di qualità, IaC e coverage (ADR-0026) e `tier`
limitato a 1..3 (ADR-0028). Il repository può solo disattivare regole e indicare dove stanno i
report di copertura: non può attivare regole, cambiare soglie o pesi, né indicare un file di
configurazione dei motori.
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


# Identificativo di una regola di un motore: `F401`, `CKV_DOCKER_3`, `max-params`,
# `@typescript-eslint/no-explicit-any`. Nessuno spazio, nessun carattere di shell o di glob.
RULE_ID_PATTERN = r"^[A-Za-z0-9@][A-Za-z0-9_./@-]{0,127}$"
MAX_DISABLED_RULES = 500
MAX_COVERAGE_REPORTS = 20


class GateMode(StrEnum):
    """Modo richiesto. Quello effettivo lo registra il report (ADR-0009, ADR-0025):
    `new-findings-only` vale come `all` su una scansione completa o senza baseline valida.
    """

    ALL = "all"
    NEW_FINDINGS_ONLY = "new-findings-only"


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Service(_Strict):
    """Dichiarazione non verificata: vale solo se manca il file di contesto (ADR-0028)."""

    catalog_id: str | None = None
    tier: StrictInt | None = Field(default=None, ge=1, le=3)
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


class LinterOptions(_Strict):
    """ADR-0026: il repository può solo spegnere regole; il report le elenca."""

    disable_rules: list[Annotated[str, Field(pattern=RULE_ID_PATTERN)]] = Field(
        default_factory=list, max_length=MAX_DISABLED_RULES
    )


class CoverageFormat(StrEnum):
    LCOV = "lcov"
    COBERTURA = "cobertura"


class CoverageReport(_Strict):
    """Un report prodotto dalla CI prima della scansione, come file del workspace."""

    path: RelativePath
    format: CoverageFormat
    # Cartella in cui sono girati i test: i percorsi nel report sono relativi a questa (V-03).
    # Assente: la radice del workspace.
    base_dir: RelativePath | None = None


class CoverageOptions(_Strict):
    reports: list[CoverageReport] = Field(default_factory=list, max_length=MAX_COVERAGE_REPORTS)


class Plugins(_Strict):
    disable: list[str] = Field(default_factory=list)
    semgrep: SemgrepOptions | None = None
    ruff: LinterOptions | None = None
    eslint: LinterOptions | None = None
    checkov: LinterOptions | None = None
    hadolint: LinterOptions | None = None
    coverage: CoverageOptions | None = None


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
