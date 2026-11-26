"""C della Variante B per `quality` e `architecture` (K-10, ADR-0023): posizione del PageRank.

C è la quota di moduli non di test con PageRank minore o uguale a quello del modulo del finding,
con un minimo `c.floor`; più membri: il massimo. Senza grafo, o per un file senza PageRank (fuori
dal grafo, di test), C è quello di A (tier del servizio) e l'evidenza lo dice.
"""

from typing import Any

from ca_core.models.finding import Finding
from ca_core.scoring.base import Factor, ScoringContext
from ca_core.scoring.exposure import _members
from ca_core.scoring.service import factor_c as factor_c_a
from ca_core.scoring.variant_b.common import from_a, rounded


def factor_c(finding: Finding, context: ScoringContext) -> Factor:
    config = context.config.variant_b
    assert config is not None
    index = context.graph
    if index is None:
        return from_a(factor_c_a(context.service, context.config), "grafo-assente")
    modules = index.modules_of(_members(finding))
    ranked = [(r, m) for m in modules if (r := index.rank(m)) is not None]
    if not ranked:
        return from_a(factor_c_a(context.service, context.config), "fuori-dal-grafo")
    rank, module = max(ranked)
    evidence: dict[str, Any] = {
        "rule": "pagerank-rank",
        "rank": rounded(rank),
        "pagerank": index.pagerank(module),
        "module": module,
    }
    return Factor(rounded(max(config.c.floor, rank)), evidence)
