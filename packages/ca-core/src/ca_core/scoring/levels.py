"""Livelli provvisori e ordinamento (K-11, ADR-0009, ADR-0012). IPOTESI D-0009-A.

Tutto il codice che dipende da D-0009-A sta in questo file: la tabella è dato (`LevelTable`),
la logica la legge soltanto. Se la decisione cambia, si sostituisce la tabella o il file.

Fonti, dai dati lasciati da K-05 in `evidence[tool]`: `cvss`, `tool_severity`, `sarif_level`.
Non si toccano `impact` e `score`, che restano nulli. Un finding che ha già un livello (le
licenze, K-12) non si ricalcola.

Scelte conservative: tra più CVSS (tool diversi) vale il più recente per versione e, a parità,
il punteggio più alto; `tool_severity` ha la precedenza su `sarif_level`; un valore non
riconosciuto si ignora; un CVSS malformato conta come assente (dipendenza: `alto`).
"""

from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

from ca_core.models.finding import Category, Finding, Level, LevelSource


@dataclass(frozen=True)
class LevelTable:
    # (limite inferiore incluso, livello), dal più alto: [9,10] [7,9) [4,7) [0,4)
    cvss_bands: tuple[tuple[float, Level], ...] = (
        (9.0, Level.CRITICAL),
        (7.0, Level.HIGH),
        (4.0, Level.MEDIUM),
        (0.0, Level.LOW),
    )
    dependency_without_cvss: Level = Level.HIGH
    # chiavi in minuscolo; `tool_severity` prima di `sarif_level`
    tool_severity: Mapping[str, Level] = field(
        default_factory=lambda: {
            "critical": Level.CRITICAL,
            "high": Level.HIGH,
            "medium": Level.MEDIUM,
            "low": Level.LOW,
        }
    )
    sarif_level: Mapping[str, Level] = field(
        default_factory=lambda: {
            "error": Level.HIGH,
            "warning": Level.MEDIUM,
            "note": Level.LOW,
        }
    )
    without_severity: Level = Level.MEDIUM  # sast, iac e categorie senza regola
    fixed: Mapping[Category, Level] = field(
        default_factory=lambda: {Category.SECRET: Level.HIGH, Category.HEALTH: Level.MEDIUM}
    )
    code_categories: frozenset[Category] = frozenset({Category.SAST, Category.IAC})


DEFAULT_LEVEL_TABLE = LevelTable()
_RANK = {Level.CRITICAL: 0, Level.HIGH: 1, Level.MEDIUM: 2, Level.LOW: 3}


def _tool_evidence(finding: Finding) -> Iterable[Mapping[str, Any]]:
    for tool in finding.tools:
        value = finding.evidence.get(tool)
        if isinstance(value, Mapping):
            yield value


def best_cvss(finding: Finding) -> float | None:
    """Punteggio del CVSS più recente tra i tool del finding; `None` se non c'è."""
    best: tuple[float, float] | None = None
    for evidence in _tool_evidence(finding):
        cvss = evidence.get("cvss")
        if not isinstance(cvss, Mapping):
            continue
        score, version = cvss.get("score"), cvss.get("version")
        if isinstance(score, bool) or not isinstance(score, int | float):
            continue
        if not 0 <= score <= 10 or not isinstance(version, str):
            continue
        try:
            key = (float(version), float(score))
        except ValueError:
            continue
        best = key if best is None else max(best, key)
    return None if best is None else best[1]


def _from_cvss(score: float, table: LevelTable) -> Level:
    for lower, level in table.cvss_bands:
        if score >= lower:
            return level
    return table.cvss_bands[-1][1]


def _from_severity(finding: Finding, table: LevelTable) -> Level | None:
    # `tool_severity` di qualunque tool prima di `sarif_level`; il livello più alto vince
    for key, mapping in (
        ("tool_severity", table.tool_severity),
        ("sarif_level", table.sarif_level),
    ):
        found = [
            mapping[str(e[key]).lower()]
            for e in _tool_evidence(finding)
            if isinstance(e.get(key), str) and str(e[key]).lower() in mapping
        ]
        if found:
            return min(found, key=_RANK.__getitem__)
    return None


def level_for(
    finding: Finding, table: LevelTable = DEFAULT_LEVEL_TABLE
) -> tuple[Level, LevelSource]:
    if finding.category in table.fixed:
        return table.fixed[finding.category], LevelSource.POLICY
    if finding.category is Category.DEPENDENCY:
        score = best_cvss(finding)
        if score is None:
            return table.dependency_without_cvss, LevelSource.DEFAULT
        return _from_cvss(score, table), LevelSource.TOOL_SEVERITY
    if finding.category in table.code_categories:
        level = _from_severity(finding, table)
        if level is not None:
            return level, LevelSource.TOOL_SEVERITY
    return table.without_severity, LevelSource.DEFAULT


def assign_levels(
    findings: Sequence[Finding], table: LevelTable = DEFAULT_LEVEL_TABLE
) -> list[Finding]:
    """Valorizza `level` e `level_source` dove mancano; `impact` e `score` non si toccano."""
    out = []
    for finding in findings:
        if finding.level is None:
            level, source = level_for(finding, table)
            finding = finding.model_copy(update={"level": level, "level_source": source})
        out.append(finding)
    return out


def sort_findings(findings: Iterable[Finding]) -> list[Finding]:
    """Livello (critico per primo, senza livello in fondo), categoria, fingerprint."""
    return sorted(
        findings,
        key=lambda f: (
            _RANK[f.level] if f.level is not None else len(_RANK),
            f.category.value,
            f.fingerprint,
        ),
    )
