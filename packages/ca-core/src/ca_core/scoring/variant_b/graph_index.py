"""Dati del grafo per P e C della Variante B (K-09, K-10, ADR-0023). Nessun I/O.

Popolazione dei percentili: i moduli non di test del grafo (i percorsi esclusi sono già tolti); un
file di test ha comunque il suo valore, misurato su quella popolazione. Un membro di un finding che
è una cartella (smell a livello di pacchetto) vale per i moduli che contiene direttamente, come i
pacchetti di ADR-0020.

- **Densità di violazioni**: finding `quality` del file per mille righe; un modulo senza violazioni
  ha densità 0; senza `lines` è ignota. Percentile: quota di moduli con densità **strettamente
  minore**, come il churn (ADR-0022).
- **Posizione del PageRank**: quota di moduli con PageRank **minore o uguale**; il più critico vale
  1. Un modulo senza PageRank non ha posizione.
"""

import posixpath
from bisect import bisect_left, bisect_right
from collections import Counter, defaultdict
from collections.abc import Iterable, Sequence

from ca_core.models.finding import Category, Finding
from ca_core.models.graph import Graph

PER_LINES = 1000


def _directory(path: str) -> str:
    return posixpath.dirname(path) or "."


class GraphIndex:
    def __init__(self, graph: Graph, findings: Sequence[Finding]) -> None:
        self._known = {m.path for m in graph.modules}
        self._by_directory: dict[str, list[str]] = defaultdict(list)
        for m in graph.modules:
            self._by_directory[_directory(m.path)].append(m.path)
        self._violations = Counter(
            f.location.path for f in findings if f.category is Category.QUALITY and f.location.path
        )
        self._density: dict[str, float] = {}
        self._pagerank: dict[str, float] = {}
        for m in graph.modules:
            if m.lines is not None:
                count = self._violations[m.path]
                self._density[m.path] = count * PER_LINES / m.lines if m.lines > 0 else 0.0
            if m.metrics is not None and m.metrics.pagerank is not None:
                self._pagerank[m.path] = m.metrics.pagerank
        population = [m.path for m in graph.modules if not m.test]
        self._densities = sorted(self._density[p] for p in population if p in self._density)
        self._ranks = sorted(self._pagerank[p] for p in population if p in self._pagerank)

    def modules_of(self, members: Iterable[str]) -> list[str]:
        """I moduli del grafo che i membri indicano: il modulo stesso o i moduli della cartella."""
        found: list[str] = []
        for member in members:
            if member in self._known:
                found.append(member)
            else:
                found.extend(self._by_directory.get(member, ()))
        return sorted(set(found))

    def violations(self, path: str) -> int:
        return self._violations[path]

    def density(self, path: str) -> float | None:
        return self._density.get(path)

    def density_percentile(self, path: str) -> float | None:
        value = self._density.get(path)
        if value is None or not self._densities:
            return None
        return bisect_left(self._densities, value) / len(self._densities)

    def pagerank(self, path: str) -> float | None:
        return self._pagerank.get(path)

    def rank(self, path: str) -> float | None:
        value = self._pagerank.get(path)
        if value is None or not self._ranks:
            return None
        return min(1.0, bisect_right(self._ranks, value) / len(self._ranks))
