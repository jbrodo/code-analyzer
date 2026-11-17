"""Variante A, fattori G e P (K-02, K-03, §6.1, ADR-0021). E è in `exposure`, C in `service`.

Tutti i valori vengono dalla configurazione di scoring. Un dato mancante non diventa un valore
favorevole: il fallback è quello della configurazione e l'evidenza lo dichiara.
"""

import re
from collections.abc import Iterable, Mapping
from typing import Any

from ca_core.models.finding import Category, Finding
from ca_core.models.scoring_config import ScoringConfig
from ca_core.ports import CVE_PATTERN, EpssAnswer, FeedStatus, KevAnswer
from ca_core.scoring.base import Factor, ScoringContext
from ca_core.scoring.exposure import _members
from ca_core.scoring.levels import best_cvss_entry

TOOL_SEVERITIES = ("critical", "high", "medium", "low")
SARIF_LEVELS = ("error", "warning", "note")
_CODE_LIKE = frozenset(
    {Category.SAST, Category.IAC, Category.QUALITY, Category.ARCHITECTURE, Category.TEST}
)


def _tool_evidence(finding: Finding) -> Iterable[Mapping[str, Any]]:
    for tool in finding.tools:
        value = finding.evidence.get(tool)
        if isinstance(value, Mapping):
            yield value


def _severity_g(finding: Finding, config: ScoringConfig) -> Factor:
    """Severità della regola → G. Tra più strumenti vale il G più alto; `tool_severity` e il
    livello SARIF sono due scale della stessa informazione e si leggono entrambe."""
    table = config.g.severity
    found: list[tuple[float, str]] = []
    for evidence in _tool_evidence(finding):
        for key, names in (("tool_severity", TOOL_SEVERITIES), ("sarif_level", SARIF_LEVELS)):
            raw = evidence.get(key)
            if isinstance(raw, str) and raw.lower() in names:
                name = raw.lower()
                found.append((getattr(table, name), name))
    if not found:
        return Factor(table.missing, {"rule": "severity", "severity": "missing", "fallback": True})
    value, name = max(found)
    return Factor(value, {"rule": "severity", "severity": name})


def _dependency_g(finding: Finding, config: ScoringConfig) -> Factor:
    entry = best_cvss_entry(finding)
    if entry is None:
        return Factor(
            config.g.dependency_without_cvss,
            {"rule": "cvss", "cvss": None, "fallback": "cvss-assente"},
        )
    score, version = entry
    return Factor(
        round(score / 10.0, 6), {"rule": "cvss", "cvss": {"score": score, "version": version}}
    )


def _license_g(finding: Finding, config: ScoringConfig) -> Factor:
    table = config.g.license
    policy: Mapping[str, Any] = {}
    for evidence in _tool_evidence(finding):
        policy = evidence
        break
    verdict = policy.get("verdict")
    if verdict == "forbidden":
        distributed = policy.get("distributed") is not False
        key = "forbidden_distributed" if distributed else "forbidden"
    elif verdict == "approval":
        key = "require_approval"
    else:
        key = "unknown"
    return Factor(getattr(table, key), {"rule": "license", "case": key})


def factor_g(finding: Finding, config: ScoringConfig) -> Factor:
    """G della Variante A per ogni categoria (ADR-0021)."""
    category = finding.category
    if category is Category.DEPENDENCY:
        return _dependency_g(finding, config)
    if category is Category.LICENSE:
        return _license_g(finding, config)
    if category is Category.SECRET:
        return Factor(config.g.secret, {"rule": "secret"})
    if category is Category.HEALTH:
        return Factor(config.g.health, {"rule": "health"})
    if category in _CODE_LIKE:
        return _severity_g(finding, config)
    raise ValueError(f"categoria senza G: {category}")


# --- P ----------------------------------------------------------------------------------------

_CVE = re.compile(CVE_PATTERN)
_CHURN_CATEGORIES = frozenset({Category.QUALITY, Category.ARCHITECTURE, Category.TEST})


def _epss_part(answer: EpssAnswer) -> dict[str, Any]:
    out: dict[str, Any] = {"status": answer.status.value}
    if answer.score is not None:
        out["score"] = answer.score
    return out


def _kev_part(answer: KevAnswer) -> dict[str, Any]:
    out: dict[str, Any] = {"status": answer.status.value}
    if answer.date_added is not None:
        out["date_added"] = answer.date_added.isoformat()
    return out


def _dependency_p(finding: Finding, context: ScoringContext) -> Factor:
    """KEV: 1,0. Altrimenti `max(epss, minimo)`. Un feed assente non dà mai un valore favorevole:
    il risultato non scende sotto `feed_missing` e l'evidenza lo dichiara. Più CVE: il massimo."""
    table, feeds = context.config.p, context.feeds
    cves = sorted({c for c in finding.cve if _CVE.fullmatch(c)})
    if not cves:
        return Factor(
            table.feed_missing,
            {"rule": "epss-kev", "fallback": "nessuna-cve", "cves": []},
        )
    best = 0.0
    absent = False
    detail: list[dict[str, Any]] = []
    for cve in cves:
        if feeds is None:
            epss, kev = (EpssAnswer(status=FeedStatus.SNAPSHOT_ABSENT),
                         KevAnswer(status=FeedStatus.SNAPSHOT_ABSENT))  # fmt: skip
        else:
            epss, kev = feeds.epss(cve), feeds.kev(cve)
        absent |= FeedStatus.SNAPSHOT_ABSENT in (epss.status, kev.status)
        if kev.status is FeedStatus.FOUND:
            value = table.kev
        elif epss.status is FeedStatus.FOUND and epss.score is not None:
            value = max(epss.score, table.epss_floor)
        elif epss.status is FeedStatus.NOT_LISTED:
            value = table.epss_floor
        else:
            value = table.feed_missing
        best = max(best, value)
        detail.append({"cve": cve, "epss": _epss_part(epss), "kev": _kev_part(kev)})
    evidence: dict[str, Any] = {"rule": "epss-kev", "cves": detail}
    if absent:
        best = max(best, table.feed_missing)
        evidence["fallback"] = "feed-assente"
    return Factor(best, evidence)


def _sast_p(finding: Finding, context: ScoringContext) -> Factor:
    confirmed = any(e.get("path_confirmed") is True for e in _tool_evidence(finding))
    table = context.config.p.sast
    return Factor(
        table.confirmed if confirmed else table.unconfirmed,
        {"rule": "sast", "path_confirmed": confirmed},
    )


def _churn_p(finding: Finding, context: ScoringContext) -> Factor:
    table = context.config.p.churn
    index = context.churn
    if index is None or not index.known:
        return Factor(table.unknown, {"rule": "churn", "fallback": "churn-ignoto"})
    members = _members(finding)
    percentile = index.percentile_of(members)
    if percentile is None:
        return Factor(table.unknown, {"rule": "churn", "fallback": "percorso-senza-churn"})
    evidence: dict[str, Any] = {
        "rule": "churn",
        "percentile": percentile,
        "window_days": index.window_days,
    }
    if len(members) == 1 and (count := index.churn(members[0])) is not None:
        evidence["commits"] = count
    return Factor(max(percentile, table.floor), evidence)


def factor_p(finding: Finding, context: ScoringContext) -> Factor:
    """P della Variante A per ogni categoria (ADR-0021)."""
    table, category = context.config.p, finding.category
    if category is Category.DEPENDENCY:
        return _dependency_p(finding, context)
    if category is Category.SAST:
        return _sast_p(finding, context)
    if category in _CHURN_CATEGORIES:
        return _churn_p(finding, context)
    fixed = {
        Category.IAC: table.iac,
        Category.SECRET: table.secret,
        Category.LICENSE: table.license,
        Category.HEALTH: table.health,
    }
    if category in fixed:
        return Factor(fixed[category], {"rule": category.value})
    raise ValueError(f"categoria senza P: {category}")
