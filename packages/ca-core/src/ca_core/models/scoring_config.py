"""Contratto `scoring-config`: pesi, soglie, mappe e override (C-03, ADR-0021). Solo dati.

Nessun campo ha un valore predefinito nel modello: i valori sono nel file predefinito del pacchetto
(`ca_core/scoring/default.json`), così nessun valore di scoring sta nel codice (regola 3). Il file
non viene mai da `.code-analyzer.yml` (ADR-0014): lo cambia il tenant o chi lancia la CLI da fuori
dal repository. Un file di sovrascrittura è completo, mai fuso con il predefinito.

Non c'è un campo per l'override «segreto valido esposto»: non si applica (ADR-0012, ADR-0021).
I parametri della Variante B sono di ADR-0023 e per ora non esistono.
"""

from enum import StrEnum
from typing import Annotated, Literal, Self

from pydantic import BaseModel, ConfigDict, Field, StrictFloat, StrictInt, model_validator

from ca_core.models.finding import Level

Fraction = Annotated[StrictFloat, Field(ge=0, le=1)]
Percentile = Annotated[StrictInt, Field(ge=1, le=100)]


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class LevelSourceChoice(StrEnum):
    """Quale livello decide il gate (D2-10): il provvisorio di ADR-0009 o quello da punteggio."""

    PROVISIONAL = "provisional"
    SCORE = "score"


class Thresholds(_Strict):
    """Limiti inferiori inclusi dei livelli; il basso è tutto ciò che sta sotto `medio`."""

    critico: StrictFloat = Field(gt=0, le=100)
    alto: StrictFloat = Field(gt=0, le=100)
    medio: StrictFloat = Field(gt=0, le=100)


class LevelsConfig(_Strict):
    source: LevelSourceChoice
    thresholds: Thresholds


class SeverityMap(_Strict):
    """Severità della regola → G. Le chiavi sono i nomi del SARIF e degli scanner."""

    critical: Fraction
    high: Fraction
    medium: Fraction
    low: Fraction
    error: Fraction
    warning: Fraction
    note: Fraction
    missing: Fraction = Field(description="Regola senza severità.")


class GLicense(_Strict):
    forbidden_distributed: Fraction
    forbidden: Fraction
    require_approval: Fraction
    unknown: Fraction
    attribution: Fraction


class GConfig(_Strict):
    severity: SeverityMap
    dependency_without_cvss: Fraction
    license: GLicense
    secret: Fraction
    health: Fraction


class ChurnConfig(_Strict):
    window_days: StrictInt = Field(ge=1, le=3650)
    floor: Fraction = Field(description="Minimo di P con il percentile di churn.")
    unknown: Fraction = Field(description="P senza churn (storia superficiale o assente).")


class SastP(_Strict):
    confirmed: Fraction
    unconfirmed: Fraction


class PConfig(_Strict):
    kev: Fraction
    epss_floor: Fraction
    feed_missing: Fraction = Field(description="P di una dipendenza senza snapshot EPSS e KEV.")
    sast: SastP
    iac: Fraction
    secret: Fraction
    license: Fraction
    health: Fraction
    churn: ChurnConfig


class EConfig(_Strict):
    """Valori di E secondo ADR-0022."""

    reachable_exposed: Fraction
    reachable_internal: Fraction
    reachable_exposure_unknown: Fraction
    unknown: Fraction
    not_reachable_or_test: Fraction


class CConfig(_Strict):
    """C dal tier del servizio (ADR-0028)."""

    tier_1: Fraction
    tier_2: Fraction
    tier_3: Fraction
    missing: Fraction


class LevelFloor(_Strict):
    level: Level


class EpssOverride(_Strict):
    level: Level
    epss_min: Fraction


class HotspotOverride(_Strict):
    level: Level
    churn_percentile_min: Percentile


class CoverageOverride(_Strict):
    level: Level
    churn_percentile_min: Percentile
    coverage_below_percent: StrictInt = Field(ge=1, le=100)


class OverridesConfig(_Strict):
    """Override di §6.3: alzano il livello a un minimo, mai il punteggio (ADR-0021)."""

    kev_reachable: LevelFloor
    license_forbidden_distributed: LevelFloor
    epss_reachable: EpssOverride
    sast_confirmed_exposed: LevelFloor
    architecture_smell_hotspot: HotspotOverride
    low_coverage_critical_code: CoverageOverride


class ScoringConfig(_Strict):
    version: StrictInt = Field(ge=1, description="Versione del contenuto: la alza chi lo cambia.")
    variant: Literal["A", "B"] = Field(description="Variante attiva di default (ADR-0021).")
    levels: LevelsConfig
    g: GConfig
    p: PConfig
    e: EConfig
    c: CConfig
    overrides: OverridesConfig

    @model_validator(mode="after")
    def _consistent(self) -> Self:
        t = self.levels.thresholds
        if not t.critico > t.alto > t.medio:
            raise ValueError("le soglie devono essere critico > alto > medio")
        s = self.g.severity
        if not s.critical >= s.high >= s.medium >= s.low:
            raise ValueError("la mappa di severità non è monotona")
        if not s.error >= s.warning >= s.note:
            raise ValueError("la mappa dei livelli SARIF non è monotona")
        if not self.c.tier_1 >= self.c.tier_2 >= self.c.tier_3:
            raise ValueError("C deve scendere con il tier")
        e = self.e
        if not e.reachable_exposed >= e.reachable_internal >= e.unknown >= e.not_reachable_or_test:
            raise ValueError("E deve scendere con la raggiungibilità")
        return self
