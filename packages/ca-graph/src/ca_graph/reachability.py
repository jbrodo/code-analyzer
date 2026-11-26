"""Raggiungibilità dei moduli e uso delle dipendenze dal grafo (G-12, ADR-0022).

Lavora sul grafo del container di estrazione (`ca_core.models.graph.Graph`): dati, niente I/O.
Granularità: il modulo, cioè il file. Si parte dagli entrypoint e si seguono gli archi interni;
gli archi di soli tipi non si seguono (non esistono a tempo di esecuzione), quelli dinamici sì.

Un modulo non raggiunto è `non-raggiungibile` solo se il grafo del suo linguaggio è completo.
La regola è prudente di proposito, perché è l'unico stato che abbassa E affermando qualcosa che il
grafo non può sempre provare. Diventa `ignota` se: nessun entrypoint per quel linguaggio; il grafo
ha import non risolti (i conteggi di `stats.unresolved` sono per tutto il grafo, non per
linguaggio); un file del linguaggio è stato letto solo in parte. Il motivo è un codice in `reason`.
"""

from collections import deque
from collections.abc import Mapping

from ca_core.models.graph import Graph, Language, ParseStatus
from ca_core.scoring.reach import ReachResult, ReachState, best
from ca_graph import import_names

_JS = frozenset({Language.JAVASCRIPT, Language.TYPESCRIPT, Language.TSX})


def _family(language: Language) -> str:
    return "js" if language in _JS else "python"


def _bfs(starts: list[str], out: Mapping[str, list[str]]) -> dict[str, str]:
    """Modulo raggiunto -> entrypoint di partenza più vicino (a parità, il primo in ordine)."""
    reached: dict[str, str] = {}
    queue: deque[str] = deque()
    for start in sorted(starts):
        if start not in reached:
            reached[start] = start
            queue.append(start)
    while queue:
        node = queue.popleft()
        for target in out.get(node, ()):
            if target not in reached:
                reached[target] = reached[node]
                queue.append(target)
    return reached


class GraphReachability:
    def __init__(self, graph: Graph) -> None:
        self._graph = graph
        modules = {m.path: m for m in graph.modules}
        out: dict[str, list[str]] = {}
        for edge in graph.edges:
            if edge.external or edge.type_only:
                continue
            out.setdefault(edge.source, []).append(edge.target)
        for targets in out.values():
            targets.sort()
        entrypoints = sorted(
            {e.path for e in graph.entrypoints if not modules[e.path].test},
        )
        from_entry = _bfs(entrypoints, out)
        from_tests = _bfs(sorted(p for p, m in modules.items() if m.test), out)
        families_with_entry = {_family(modules[p].language) for p in entrypoints}
        unresolved = graph.stats.unresolved
        has_unresolved = (
            unresolved.computed
            + unresolved.missing
            + unresolved.outside_workspace
            + unresolved.config_extends
            + unresolved.entrypoint_missing
        ) > 0
        partial_families = {
            _family(m.language) for m in graph.modules if m.parse is ParseStatus.PARTIAL
        }
        self._modules: dict[str, ReachResult] = {}
        for path, module in modules.items():
            family = _family(module.language)
            if module.test:
                result = ReachResult(ReachState.TEST_ONLY)
            elif path in from_entry:
                result = ReachResult(ReachState.REACHABLE, entrypoint=from_entry[path])
            elif path in from_tests:
                result = ReachResult(ReachState.TEST_ONLY)
            elif family not in families_with_entry:
                result = ReachResult(ReachState.UNKNOWN, reason="nessun-entrypoint")
            elif has_unresolved:
                result = ReachResult(ReachState.UNKNOWN, reason="import-non-risolti")
            elif family in partial_families:
                result = ReachResult(ReachState.UNKNOWN, reason="file-analizzato-in-parte")
            else:
                result = ReachResult(ReachState.NOT_REACHABLE)
            self._modules[path] = result
        self._importers: dict[tuple[str, str], list[str]] = {}
        ecosystems = {e.name: e.ecosystem.value for e in graph.externals}
        for edge in graph.edges:
            if edge.external:
                self._importers.setdefault((ecosystems[edge.target], edge.target), []).append(
                    edge.source
                )

    def module(self, path: str) -> ReachResult | None:
        return self._modules.get(path)

    def package(self, path: str) -> ReachResult | None:
        prefix = "" if path in (".", "") else path.rstrip("/") + "/"
        found = [r for p, r in self._modules.items() if p.startswith(prefix)]
        return best(found) if found else None

    def dependency(self, ecosystem: str, name: str) -> ReachResult:
        """Stato migliore tra i moduli che importano il pacchetto; nessuno: `ignota`."""
        users: list[ReachResult] = []
        for (eco, import_name), sources in self._importers.items():
            if eco == ecosystem and import_names.matches(ecosystem, import_name, name):
                users += [self._modules[s] for s in sources]
        if not users:
            return ReachResult(ReachState.UNKNOWN, reason="nessun-import-corrispondente")
        return best(users)
