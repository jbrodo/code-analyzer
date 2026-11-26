"""G della Variante B per i finding `architecture` (K-08, ADR-0023): tipo e dimensione.

    G = max(g.floor, peso(tipo) · F_dim(tipo, ambito)(dimensione))

`F_dim` è la funzione di ripartizione delle dimensioni di quel tipo e ambito nel benchmark. La
dimensione è il numero di componenti coinvolti: `size` per Cyclic e Unstable Dependency,
`fan_in + fan_out` per Hub-Like (la sua `size` vale sempre 1). Non legge nulla dei code smell
(§6.2: motori separati). Serve anche all'ADI (G-13), che somma questi G per modulo.
"""

from collections.abc import Mapping
from typing import Any

from ca_core.models.finding import Finding
from ca_core.models.scoring_config import VariantBConfig
from ca_core.scoring.base import Factor, ScoringContext
from ca_core.scoring.benchmark import LoadedBenchmark
from ca_core.scoring.variant_a import factor_g as factor_g_a
from ca_core.scoring.variant_b.common import from_a, rounded

TOOL = "ca-graph"
CYCLIC = "ca.arch.cyclic-dependency"
HUB_LIKE = "ca.arch.hub-like-dependency"
UNSTABLE = "ca.arch.unstable-dependency"
_WEIGHT = {
    CYCLIC: "cyclic_dependency",
    HUB_LIKE: "hub_like_dependency",
    UNSTABLE: "unstable_dependency",
}


def _count(value: object) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) and value >= 0 else None


def dimension(rule_id: str, evidence: Mapping[str, Any]) -> int | None:
    if rule_id == HUB_LIKE:
        fan_in, fan_out = _count(evidence.get("fan_in")), _count(evidence.get("fan_out"))
        return None if fan_in is None or fan_out is None else fan_in + fan_out
    return _count(evidence.get("size"))


def smell_g(
    rule_id: str,
    evidence: Mapping[str, Any],
    config: VariantBConfig,
    benchmark: LoadedBenchmark,
) -> tuple[float, dict[str, Any]] | str:
    """(G, evidenza) di uno smell dall'evidenza di `ca-graph`; altrimenti il motivo del ripiego."""
    weight_name = _WEIGHT.get(rule_id)
    scope = evidence.get("scope")
    size = dimension(rule_id, evidence)
    if weight_name is None or not isinstance(scope, str) or size is None:
        return "dimensione-assente"
    distribution = benchmark.smell_size(rule_id, scope)
    if distribution is None:
        return "benchmark-assente"
    weight = getattr(config.g.architecture, weight_name)
    share = benchmark.cdf(distribution, size)
    value = rounded(max(config.g.floor, weight * share))
    return value, {
        "rule": "smell-size",
        "scope": scope,
        "size": size,
        "weight": weight,
        "f_size": rounded(share),
        "benchmark": benchmark.version,
    }


def factor_g(finding: Finding, context: ScoringContext) -> Factor:
    config = context.config.variant_b
    assert config is not None
    if context.benchmark is None:
        return from_a(factor_g_a(finding, context.config), "benchmark-assente")
    evidence = finding.evidence.get(TOOL)
    if not isinstance(evidence, Mapping):
        return from_a(factor_g_a(finding, context.config), "dimensione-assente")
    result = smell_g(finding.rule_id, evidence, config, context.benchmark)
    if isinstance(result, str):
        return from_a(factor_g_a(finding, context.config), result)
    value, detail = result
    engine = context.benchmark.benchmark.engines.get(TOOL)
    seen = context.plugin_versions.get(TOOL)
    if seen is not None and seen != engine:
        detail["warning"] = "benchmark-motore-diverso"
    return Factor(value, detail)
