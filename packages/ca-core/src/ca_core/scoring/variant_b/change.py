"""P della Variante B per `quality` e `architecture` (K-09, ADR-0023): churn e violazioni.

    P = max(p.floor, w_churn · pct_churn + w_density · pct_density)

`pct_churn` è il percentile di ADR-0022; `pct_density` quello della densità di violazioni
(`GraphIndex`). Più membri: il massimo di ciascun percentile. Un percentile ignoto prende il valore
della configurazione (`p.churn.unknown` di A, `variant_b.p.density_unknown`) e l'evidenza lo dice.
"""

from typing import Any

from ca_core.models.finding import Finding
from ca_core.scoring.base import Factor, ScoringContext
from ca_core.scoring.exposure import _members
from ca_core.scoring.variant_b.common import rounded


def _max(values: list[float | None]) -> float | None:
    known = [v for v in values if v is not None]
    return max(known) if known else None


def factor_p(finding: Finding, context: ScoringContext) -> Factor:
    config = context.config.variant_b
    assert config is not None
    table, members = config.p, _members(finding)
    index = context.graph
    modules = index.modules_of(members) if index is not None else members
    fallbacks: list[str] = []

    churn = context.churn
    churn_pct = churn.percentile_of(modules) if churn is not None and churn.known else None
    if churn_pct is None:
        fallbacks.append("churn-ignoto")
        churn_value = context.config.p.churn.unknown
    else:
        churn_value = churn_pct

    density_pct = _max([index.density_percentile(m) for m in modules]) if index else None
    if density_pct is None:
        fallbacks.append("densita-ignota")
        density_value = table.density_unknown
    else:
        density_value = density_pct

    value = rounded(max(table.floor, table.w_churn * churn_value + table.w_density * density_value))
    evidence: dict[str, Any] = {
        "rule": "churn-density",
        "churn_percentile": churn_pct,
        "density_percentile": density_pct,
        "w_churn": table.w_churn,
        "w_density": table.w_density,
    }
    if len(modules) == 1 and index is not None and (d := index.density(modules[0])) is not None:
        evidence["violations"] = index.violations(modules[0])
        evidence["density_per_kloc"] = rounded(d)
    if fallbacks:
        evidence["fallback"] = ",".join(fallbacks)
    return Factor(value, evidence)
