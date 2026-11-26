"""PageRank sul grafo dei moduli (G-08, ADR-0020, ADR-0023).

Un arco A→B significa «A dipende da B»: la massa di A passa a B, quindi un componente da cui
dipendono in molti ha un PageRank alto (la criticità di Arcelli Fontana et al., ECSA 2019). Solo
archi interni tra i moduli considerati (G-04). I nodi senza dipendenze (pendenti) distribuiscono la
loro massa in parti uguali su tutti i nodi, come nella formulazione standard.

Il risultato grezzo somma a 1. `normalized` lo porta in [0, 1] dividendo per il massimo: il modulo
più critico vale 1 e gli altri stanno nella stessa proporzione. Un grafo senza archi dà a tutti i
moduli lo stesso valore, cioè 1. Parametri (smorzamento, tolleranza, iterazioni) in configurazione,
mai nel codice. Il calcolo è deterministico: nodi e vicini in ordine lessicografico.
"""

from dataclasses import dataclass

from ca_core.models.graph import Graph
from ca_graph.deps import DependencyGraph, Options, build, with_metrics


@dataclass(frozen=True)
class PageRankConfig:
    damping: float = 0.85
    tolerance: float = 1e-10
    max_iterations: int = 200

    def __post_init__(self) -> None:
        if not 0.0 <= self.damping < 1.0:
            raise ValueError("damping in [0, 1)")
        if self.tolerance <= 0 or self.max_iterations < 1:
            raise ValueError("tolleranza e iterazioni positive")


def pagerank(deps: DependencyGraph, config: PageRankConfig | None = None) -> dict[str, float]:
    """PageRank grezzo dei moduli considerati: valori non negativi che sommano a 1."""
    config = config or PageRankConfig()
    nodes = deps.modules
    if not nodes:
        return {}
    count = len(nodes)
    rank = {n: 1.0 / count for n in nodes}
    for _ in range(config.max_iterations):
        dangling = sum(rank[n] for n in nodes if not deps.module_out[n])
        base = (1.0 - config.damping) / count + config.damping * dangling / count
        fresh = dict.fromkeys(nodes, base)
        for node in nodes:
            targets = deps.module_out[node]
            if targets:
                share = config.damping * rank[node] / len(targets)
                for target in targets:
                    fresh[target] += share
        total = sum(fresh.values())
        fresh = {n: v / total for n, v in fresh.items()}  # contro la deriva numerica
        delta = sum(abs(fresh[n] - rank[n]) for n in nodes)
        rank = fresh
        if delta < config.tolerance:
            break
    return rank


def normalized(raw: dict[str, float]) -> dict[str, float]:
    """Divide per il massimo: valori in [0, 1], il più alto vale 1."""
    if not raw:
        return {}
    top = max(raw.values())
    return {n: (v / top if top > 0 else 0.0) for n, v in raw.items()}


def with_pagerank(
    graph: Graph, options: Options | None = None, config: PageRankConfig | None = None
) -> Graph:
    """Copia del grafo con `metrics` e `packages` (G-04) e il `pagerank` dei moduli considerati."""
    base = with_metrics(graph, options)
    scores = normalized(pagerank(build(graph, options), config))
    modules = []
    for module in base.modules:
        if module.metrics is None or module.path not in scores:
            modules.append(module)
            continue
        metrics = module.metrics.model_copy(update={"pagerank": scores[module.path]})
        modules.append(module.model_copy(update={"metrics": metrics}))
    return base.model_copy(update={"modules": modules})
