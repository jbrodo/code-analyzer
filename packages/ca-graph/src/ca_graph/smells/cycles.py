"""Cyclic Dependency (G-05, ADR-0020): componenti fortemente connesse del grafo.

Definizione: un ciclo è una componente fortemente connessa con almeno `cycle_min_size` nodi
(predefinito 2; un modulo che importa se stesso non è un ciclo, `deps` scarta quegli archi). Si
cerca a livello di modulo e di pacchetto. Ancora: il primo membro in ordine lessicografico, quindi
il fingerprint non cambia quando il ciclo cresce (limite accettato, ADR-0020).

L'algoritmo è quello di Tarjan in forma iterativa: nessuna ricorsione, quindi nessun limite sulla
lunghezza di una catena (S-02).
"""

from collections.abc import Mapping, Sequence

from ca_graph.deps import DependencyGraph
from ca_graph.smells.model import CYCLIC, Scope, Smell, SmellConfig, listed


def strongly_connected(
    nodes: Sequence[str], successors: Mapping[str, Sequence[str]]
) -> list[tuple[str, ...]]:
    """Componenti fortemente connesse, ciascuna ordinata, nell'ordine del primo membro."""
    index: dict[str, int] = {}
    low: dict[str, int] = {}
    on_stack: set[str] = set()
    stack: list[str] = []
    components: list[tuple[str, ...]] = []
    counter = 0
    for root in nodes:
        if root in index:
            continue
        work: list[tuple[str, int]] = [(root, 0)]
        while work:
            node, position = work.pop()
            if position == 0:
                index[node] = low[node] = counter
                counter += 1
                stack.append(node)
                on_stack.add(node)
            neighbours = successors.get(node, ())
            descended = False
            while position < len(neighbours):
                target = neighbours[position]
                position += 1
                if target not in index:
                    work.append((node, position))
                    work.append((target, 0))
                    descended = True
                    break
                if target in on_stack:
                    low[node] = min(low[node], index[target])
            if descended:
                continue
            if low[node] == index[node]:
                members = []
                while True:
                    member = stack.pop()
                    on_stack.discard(member)
                    members.append(member)
                    if member == node:
                        break
                components.append(tuple(sorted(members)))
            if work:
                parent = work[-1][0]
                low[parent] = min(low[parent], low[node])
    return sorted(components)


def _smell(scope: Scope, members: tuple[str, ...], deps: DependencyGraph) -> Smell:
    inside = set(members)
    if scope == "module":
        edges = sum(1 for m in members for t in deps.module_out[m] if t in inside)
    else:
        edges = sum(deps.package_edges.get((a, b), 0) for a in members for b in members if a != b)
    return Smell(
        rule_id=CYCLIC,
        scope=scope,
        anchor=members[0],
        members=members,
        evidence={"level": scope, "edges": edges, **listed(members)},
    )


def find_cycles(deps: DependencyGraph, config: SmellConfig | None = None) -> list[Smell]:
    config = config or SmellConfig()
    found: list[Smell] = []
    if "module" in config.cycle_scopes:
        for members in strongly_connected(deps.modules, deps.module_out):
            if len(members) >= config.cycle_min_size:
                found.append(_smell("module", members, deps))
    if "package" in config.cycle_scopes:
        for members in strongly_connected(tuple(deps.packages), deps.package_out):
            if len(members) >= config.cycle_min_size:
                found.append(_smell("package", members, deps))
    return found
