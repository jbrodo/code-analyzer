"""Smell architetturali: Cyclic, Hub-Like, Unstable Dependency (G-05..G-07, ADR-0020).

Sull'host, sui dati del grafo: nessun parser, nessuna lettura del workspace.
"""

from ca_graph.deps import DependencyGraph
from ca_graph.smells.cycles import find_cycles
from ca_graph.smells.hub import find_hubs
from ca_graph.smells.model import CYCLIC, HUB_LIKE, UNSTABLE, Smell, SmellConfig
from ca_graph.smells.unstable import find_unstable

__all__ = [
    "CYCLIC",
    "HUB_LIKE",
    "UNSTABLE",
    "Smell",
    "SmellConfig",
    "detect",
    "find_cycles",
    "find_hubs",
    "find_unstable",
]


def detect(deps: DependencyGraph, config: SmellConfig | None = None) -> list[Smell]:
    """Tutti gli smell, in un ordine stabile: regola, ambito, ancora."""
    config = config or SmellConfig()
    smells = [*find_cycles(deps, config), *find_hubs(deps, config), *find_unstable(deps, config)]
    return sorted(smells, key=lambda s: (s.rule_id, s.scope, s.anchor, s.members))
