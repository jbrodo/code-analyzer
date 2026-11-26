"""G della Variante B per i finding `quality` (K-07, ADR-0023): indice di intensità (MTD 2015).

Sia `F` la funzione di ripartizione della metrica nel benchmark, `v` il valore e `t` la soglia del
finding (`properties.metric`, ADR-0026):

    intensità = (F(v) − F(t)) / (1 − F(t))   in [0, 1];   G = max(g.floor, intensità)

Con `F(t) = 1` (soglia oltre ogni valore del benchmark) l'intensità vale 1. Più metriche: la media.
Senza metrica o senza benchmark, G è quello di A e l'evidenza dice perché. Non legge nulla degli
architectural smell (§6.2: motori separati).
"""

from collections.abc import Mapping
from typing import Any

from ca_core.models.finding import Finding
from ca_core.scoring.base import Factor, ScoringContext
from ca_core.scoring.benchmark import LoadedBenchmark
from ca_core.scoring.variant_a import factor_g as factor_g_a
from ca_core.scoring.variant_b.common import clamp, from_a, rounded

ENGINE_MISMATCH = "benchmark-motore-diverso"


def _number(value: object) -> float | None:
    if isinstance(value, bool) or not isinstance(value, int | float):
        return None
    return float(value)


def metrics(finding: Finding) -> list[tuple[str, float, float]]:
    """(strumento, valore, soglia) per ogni strumento del finding che riporta una metrica."""
    found: list[tuple[str, float, float]] = []
    for tool in finding.tools:
        evidence = finding.evidence.get(tool)
        metric = evidence.get("metric") if isinstance(evidence, Mapping) else None
        if not isinstance(metric, Mapping):
            continue
        value, threshold = _number(metric.get("value")), _number(metric.get("threshold"))
        if value is not None and threshold is not None:
            found.append((tool, value, threshold))
    return found


def intensity(
    benchmark: LoadedBenchmark, engine: str, rule_id: str, value: float, threshold: float
) -> dict[str, Any] | None:
    distribution = benchmark.code_metric(engine, rule_id)
    if distribution is None:
        return None
    f_value, f_threshold = (
        benchmark.cdf(distribution, value),
        benchmark.cdf(distribution, threshold),
    )
    share = 1.0 if f_threshold >= 1.0 else clamp((f_value - f_threshold) / (1.0 - f_threshold))
    return {
        "engine": engine,
        "value": value,
        "threshold": threshold,
        "f_value": rounded(f_value),
        "f_threshold": rounded(f_threshold),
        "intensity": rounded(share),
    }


def factor_g(finding: Finding, context: ScoringContext) -> Factor:
    config = context.config.variant_b
    assert config is not None
    benchmark = context.benchmark
    if benchmark is None:
        return from_a(factor_g_a(finding, context.config), "benchmark-assente")
    found = metrics(finding)
    if not found:
        known = any(benchmark.code_metric(t, finding.rule_id) for t in finding.tools)
        reason = "metrica-assente" if known else "regola-senza-metrica"
        return from_a(factor_g_a(finding, context.config), reason)
    parts = [intensity(benchmark, tool, finding.rule_id, v, t) for tool, v, t in found]
    measured = [p for p in parts if p is not None]
    if not measured:
        return from_a(factor_g_a(finding, context.config), "benchmark-assente")
    mean = sum(p["intensity"] for p in measured) / len(measured)
    evidence: dict[str, Any] = {
        "rule": "intensity",
        "metrics": measured,
        "benchmark": benchmark.version,
    }
    engines = benchmark.benchmark.engines
    if any(
        (seen := context.plugin_versions.get(p["engine"])) is not None
        and seen != engines.get(p["engine"])
        for p in measured
    ):
        evidence["warning"] = ENGINE_MISMATCH
    return Factor(rounded(max(config.g.floor, mean)), evidence)
