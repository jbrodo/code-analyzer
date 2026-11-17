"""Override di §6.3 (K-13, ADR-0021): alzano il livello a un minimo, mai il punteggio.

Ogni override è un dato della configurazione di scoring (livello minimo e soglie). Un override non
si applica mai su un dato assente: senza raggiungibilità provata (`ignota`), senza snapshot, senza
churn o senza esposizione dichiarata dal catalogo o dal repository non scatta. Il «segreto valido
esposto» di §6.3 non c'è: provarlo richiede rete (ADR-0006, ADR-0012) e la configurazione non ha un
posto dove attivarlo.
"""

import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

from ca_core.models.finding import Category, Finding, Level
from ca_core.ports import CVE_PATTERN, FeedStatus
from ca_core.scoring.base import ScoringContext
from ca_core.scoring.exposure import _members, reach_of
from ca_core.scoring.levels import level_rank
from ca_core.scoring.reach import ReachState

_CVE = re.compile(CVE_PATTERN)
KEV_REACHABLE = "kev-reachable"
LICENSE_FORBIDDEN_DISTRIBUTED = "license-forbidden-distributed"
EPSS_REACHABLE = "epss-reachable"
SAST_CONFIRMED_EXPOSED = "sast-confirmed-exposed"
ARCHITECTURE_HOTSPOT = "architecture-smell-hotspot"
LOW_COVERAGE_CRITICAL_CODE = "low-coverage-critical-code"


@dataclass(frozen=True)
class Override:
    name: str
    level: Level
    evidence: dict[str, Any] = field(default_factory=dict)


def _cves(finding: Finding) -> list[str]:
    return sorted({c for c in finding.cve if _CVE.fullmatch(c)})


def _tool_values(finding: Finding, key: str) -> list[Any]:
    return [e[key] for e in finding.evidence.values() if isinstance(e, Mapping) and key in e]


def _dependency_overrides(finding: Finding, context: ScoringContext) -> list[Override]:
    feeds, table = context.feeds, context.config.overrides
    if feeds is None or finding.category is not Category.DEPENDENCY:
        return []
    cves = _cves(finding)
    if not cves:
        return []
    _, reach = reach_of(finding, context)
    if reach.state is not ReachState.REACHABLE:
        return []
    found: list[Override] = []
    kev = [c for c in cves if feeds.kev(c).status is FeedStatus.FOUND]
    if kev:
        found.append(Override(KEV_REACHABLE, table.kev_reachable.level, {"cves": kev}))
    scores = {c: a.score for c in cves if (a := feeds.epss(c)).score is not None}
    high = {c: s for c, s in scores.items() if s is not None and s >= table.epss_reachable.epss_min}
    if high:
        found.append(
            Override(
                EPSS_REACHABLE,
                table.epss_reachable.level,
                {"cves": sorted(high), "epss_min": table.epss_reachable.epss_min},
            )
        )
    return found


def _license_override(finding: Finding, context: ScoringContext) -> list[Override]:
    if finding.category is not Category.LICENSE:
        return []
    for evidence in finding.evidence.values():
        if (
            isinstance(evidence, Mapping)
            and evidence.get("verdict") == "forbidden"
            and evidence.get("distributed") is not False
        ):
            level = context.config.overrides.license_forbidden_distributed.level
            return [Override(LICENSE_FORBIDDEN_DISTRIBUTED, level)]
    return []


def _sast_override(finding: Finding, context: ScoringContext) -> list[Override]:
    if finding.category is not Category.SAST:
        return []
    confirmed = any(v is True for v in _tool_values(finding, "path_confirmed"))
    exposure = context.service.internet_facing
    declared = exposure.value is True and exposure.source in ("catalog", "repository")
    if confirmed and declared:
        level = context.config.overrides.sast_confirmed_exposed.level
        return [Override(SAST_CONFIRMED_EXPOSED, level, {"exposure_source": exposure.source})]
    return []


def _churn_percentile(finding: Finding, context: ScoringContext) -> float | None:
    index = context.churn
    if index is None or not index.known:
        return None
    return index.percentile_of(_members(finding))


def _hotspot_override(finding: Finding, context: ScoringContext) -> list[Override]:
    if finding.category is not Category.ARCHITECTURE:
        return []
    rule = context.config.overrides.architecture_smell_hotspot
    percentile = _churn_percentile(finding, context)
    if percentile is not None and percentile * 100 >= rule.churn_percentile_min:
        evidence = {"churn_percentile": percentile, "min": rule.churn_percentile_min}
        return [Override(ARCHITECTURE_HOTSPOT, rule.level, evidence)]
    return []


def _coverage_override(finding: Finding, context: ScoringContext) -> list[Override]:
    if finding.category is not Category.TEST:
        return []
    rule = context.config.overrides.low_coverage_critical_code
    metrics = [m for m in _tool_values(finding, "metric") if isinstance(m, Mapping)]
    values = [m["value"] for m in metrics if isinstance(m.get("value"), int)]
    if not values or min(values) >= rule.coverage_below_percent:
        return []
    percentile = _churn_percentile(finding, context)
    if percentile is None or percentile * 100 < rule.churn_percentile_min:
        return []
    _, reach = reach_of(finding, context)
    if reach.state is not ReachState.REACHABLE:
        return []
    evidence = {"coverage": min(values), "churn_percentile": percentile}
    return [Override(LOW_COVERAGE_CRITICAL_CODE, rule.level, evidence)]


def applicable_overrides(finding: Finding, context: ScoringContext) -> list[Override]:
    """Tutti gli override che scattano, dal livello minimo più grave."""
    found = [
        *_dependency_overrides(finding, context),
        *_license_override(finding, context),
        *_sast_override(finding, context),
        *_hotspot_override(finding, context),
        *_coverage_override(finding, context),
    ]
    return sorted(found, key=lambda o: (level_rank(o.level), o.name))


def floor_of(finding: Finding, context: ScoringContext) -> Override | None:
    """L'override che impone il livello minimo più alto, o `None`."""
    found = applicable_overrides(finding, context)
    return found[0] if found else None
