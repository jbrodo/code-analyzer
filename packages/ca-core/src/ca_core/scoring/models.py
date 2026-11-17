"""Le due varianti dello scoring (K-11, §6, ADR-0021). Le due insieme, sempre, in ombra (D2-10).

La Variante A è completa (G, P, E e C). La Variante B non ha ancora una definizione per qualità e
architettura (ADR-0023, D2-11): finché non c'è coincide con A su quelle categorie e lo dichiara
nell'evidenza, così X-02 non la conta come prova. Per le altre categorie B usa A, come in §6.2.
"""

from typing import Any

from ca_core.models.finding import Category, Finding, ImpactFactors
from ca_core.scoring.base import Factor, ScoringContext
from ca_core.scoring.exposure import factor_e
from ca_core.scoring.service import factor_c
from ca_core.scoring.variant_a import factor_g, factor_p

B_UNDEFINED = "variante-b-non-definita"
_B_CATEGORIES = frozenset({Category.QUALITY, Category.ARCHITECTURE})


def _fallbacks(factors: dict[str, Factor]) -> list[str]:
    found: list[str] = []
    for name, factor in factors.items():
        value = factor.evidence.get("fallback")
        if value:
            found.append(f"{name}:{value if isinstance(value, str) else 'default'}")
    return found


def _impact(variant: str, factors: dict[str, Factor], extra: list[str]) -> ImpactFactors:
    evidence: dict[str, Any] = {name: f.evidence for name, f in factors.items()}
    fallbacks = [*_fallbacks(factors), *extra]
    if fallbacks:
        evidence["fallbacks"] = fallbacks
    return ImpactFactors(
        g=factors["g"].value,
        p=factors["p"].value,
        e=factors["e"].value,
        c=factors["c"].value,
        variant=variant,
        evidence=evidence,
    )


class VariantAModel:
    name = "A"

    def factors(self, finding: Finding, context: ScoringContext) -> ImpactFactors:
        factors = {
            "g": factor_g(finding, context.config),
            "p": factor_p(finding, context),
            "e": factor_e(finding, context),
            "c": factor_c(context.service, context.config),
        }
        return _impact("A", factors, [])


class VariantBModel:
    name = "B"

    def factors(self, finding: Finding, context: ScoringContext) -> ImpactFactors:
        base = VariantAModel().factors(finding, context)
        extra = [B_UNDEFINED] if finding.category in _B_CATEGORIES else []
        evidence = dict(base.evidence)
        if extra:
            evidence["fallbacks"] = [*evidence.get("fallbacks", []), *extra]
        return base.model_copy(update={"variant": "B", "evidence": evidence})


MODELS = {"A": VariantAModel(), "B": VariantBModel()}
