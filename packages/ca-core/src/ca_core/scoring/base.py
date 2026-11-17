"""Interfaccia di scoring (K-01, §6, ADR-0021). Solo libreria standard e i modelli, nessun I/O.

Un fattore restituisce il valore e la sua evidenza: quale regola, quale fallback, da quale fonte.
Nessun valore numerico sta qui: arrivano dalla configurazione di scoring (regola 3).
"""

from dataclasses import dataclass, field
from decimal import ROUND_HALF_UP, Decimal
from typing import Any, Protocol

from ca_core.models.finding import Finding, ImpactFactors
from ca_core.models.scan_report import ServiceContext, ServiceValue
from ca_core.models.scoring_config import ScoringConfig
from ca_core.ports import EnrichmentFeeds
from ca_core.scoring.churn import ChurnIndex
from ca_core.scoring.reach import NoReachability, Reachability


@dataclass(frozen=True)
class ScoringContext:
    """Ciò che un modello può leggere oltre al finding. Cresce con i task che portano i dati
    (feed EPSS e KEV, raggiungibilità, servizio): K-03, K-04 e K-05."""

    config: ScoringConfig
    service: ServiceContext = field(
        default_factory=lambda: ServiceContext(
            tier=ServiceValue(value=None, source="default"),
            internet_facing=ServiceValue(value=None, source="default"),
        )
    )
    reachability: Reachability = field(default_factory=NoReachability)
    feeds: EnrichmentFeeds | None = None  # EPSS e KEV; `None`: nessuno snapshot
    churn: ChurnIndex | None = None  # `None`: nessun grafo


@dataclass(frozen=True)
class Factor:
    value: float
    evidence: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if isinstance(self.value, bool) or not 0.0 <= self.value <= 1.0:
            raise ValueError("un fattore sta in [0,1]: configurazione o calcolo non validi")


class ScoringModel(Protocol):
    name: str  # "A" | "B"

    def factors(self, finding: Finding, context: ScoringContext) -> ImpactFactors: ...


def round_score(value: float) -> float:
    """Due decimali, metà verso l'alto, partendo dalla rappresentazione più breve del numero."""
    return float(Decimal(repr(value)).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP))


def impact(g: float, p: float, e: float, c: float) -> float:
    """`100·G·P·E·C` arrotondato a due decimali. Ogni fattore deve stare in [0,1]."""
    for factor in (g, p, e, c):
        if isinstance(factor, bool) or not 0.0 <= factor <= 1.0:
            raise ValueError("un fattore sta in [0,1]")
    return round_score(100.0 * g * p * e * c)
