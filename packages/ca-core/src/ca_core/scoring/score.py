"""Passo `score` (K-14, §5 passo 8, ADR-0021): punteggi in ombra e livello attivo. Nessun I/O.

Per ogni finding si calcolano **sempre** A e B, ciascuna con i fattori e la loro evidenza, e si
registrano in `variant_scores`. Il livello che decide il gate dipende da `levels.source` nella
configurazione di scoring (D2-10): con `provisional` resta quello di ADR-0009 e il report è identico
a quello della Fase 1 nei livelli; con `score` è quello della variante attiva, con gli override.
Idempotente: rieseguito sullo stesso finding dà lo stesso risultato, perché parte dai suoi dati e
non da un punteggio calcolato prima.
"""

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Literal

from ca_core.models.finding import Finding, LevelSource, VariantScore
from ca_core.models.scan_report import ScoringInfo
from ca_core.models.scoring_config import LevelSourceChoice
from ca_core.scoring.base import ScoringContext, impact
from ca_core.scoring.levels import level_from_score, level_rank
from ca_core.scoring.models import MODELS
from ca_core.scoring.overrides import Override, floor_of

Variant = Literal["A", "B"]


@dataclass(frozen=True)
class ScoreResult:
    findings: list[Finding]
    info: ScoringInfo
    with_fallback: int  # finding con almeno un fallback in A: copertura ridotta dichiarata


def _score_variant(
    finding: Finding, context: ScoringContext, variant: Variant, floor: Override | None
) -> tuple[VariantScore, bool]:
    factors = MODELS[variant].factors(finding, context)
    score = impact(factors.g, factors.p, factors.e, factors.c)
    level = level_from_score(score, context.config.levels.thresholds)
    raised = floor is not None and level_rank(floor.level) < level_rank(level)
    if raised and floor is not None:
        level = floor.level
        evidence = {
            **factors.evidence,
            "override": {"name": floor.name, "level": floor.level.value, **floor.evidence},
        }
        factors = factors.model_copy(update={"evidence": evidence})
    return VariantScore(variant=variant, score=score, level=level, impact=factors), raised


def score_finding(finding: Finding, context: ScoringContext, active: Variant) -> Finding:
    floor = floor_of(finding, context)
    scored = {v: _score_variant(finding, context, v, floor) for v in ("A", "B")}
    chosen, raised = scored[active]
    update: dict[str, object] = {
        "variant_scores": [scored["A"][0], scored["B"][0]],
        "impact": chosen.impact,
        "score": chosen.score,
    }
    if context.config.levels.source is LevelSourceChoice.SCORE:
        update["level"] = chosen.level
        update["level_source"] = LevelSource.OVERRIDE if raised else LevelSource.SCORE
    return finding.model_copy(update=update)


def sort_scored(findings: Sequence[Finding]) -> list[Finding]:
    """Livello, punteggio decrescente, categoria, fingerprint: deterministico."""
    return sorted(
        findings,
        key=lambda f: (level_rank(f.level), -(f.score or 0.0), f.category.value, f.fingerprint),
    )


def score_findings(
    findings: Sequence[Finding],
    context: ScoringContext,
    *,
    active_variant: Variant,
    config_version: str,
    benchmark_version: str | None = None,
) -> ScoreResult:
    out = [score_finding(f, context, active_variant) for f in findings]
    fallback = sum(
        1 for f in out if f.variant_scores and f.variant_scores[0].impact.evidence.get("fallbacks")
    )
    info = ScoringInfo(
        active_variant=active_variant,
        config_version=config_version,
        shadow=True,
        benchmark_version=benchmark_version,
    )
    return ScoreResult(sort_scored(out), info, fallback)


__all__ = ["ScoreResult", "score_finding", "score_findings", "sort_scored"]
