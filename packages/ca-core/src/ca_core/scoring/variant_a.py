"""Variante A, fattore G (K-02, §6.1, ADR-0021). P, E e C arrivano con K-03, K-04 e K-05.

Tutti i valori vengono dalla configurazione di scoring. Un dato mancante non diventa un valore
favorevole: il fallback è quello della configurazione e l'evidenza lo dichiara.
"""

from collections.abc import Iterable, Mapping
from typing import Any

from ca_core.models.finding import Category, Finding
from ca_core.models.scoring_config import ScoringConfig
from ca_core.scoring.base import Factor
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
    return Factor(score / 10.0, {"rule": "cvss", "cvss": {"score": score, "version": version}})


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
