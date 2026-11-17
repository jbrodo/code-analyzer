"""Percentile di churn dei file (G-11, ADR-0022). Sull'host, sui dati del grafo: nessun I/O.

Per un file: la quota di file sorgente del repository con un churn **strettamente minore**. La
popolazione esclude i file di test (i percorsi esclusi da `paths.exclude` sono già tolti dal
grafo). Un file mai toccato nella finestra ha percentile 0. Più moduli nello stesso finding:
il massimo. Con storia `superficiale` o `assente` il churn è ignoto per tutti i file: nessun
percentile, mai un valore inventato (P usa la costante `p.churn.unknown` della configurazione).
"""

from bisect import bisect_left
from collections.abc import Iterable

from ca_core.models.graph import Graph, HistoryStatus


class ChurnIndex:
    def __init__(self, graph: Graph) -> None:
        self.status = graph.history.status
        self.window_days = graph.history.window_days
        self._churn: dict[str, int] = {}
        if self.status is HistoryStatus.COMPLETE:
            self._churn = {m.path: m.churn or 0 for m in graph.modules}
        population = sorted(
            self._churn[m.path] for m in graph.modules if not m.test and m.path in self._churn
        )
        self._population = population

    @property
    def known(self) -> bool:
        return self.status is HistoryStatus.COMPLETE

    def churn(self, path: str) -> int | None:
        return self._churn.get(path)

    def percentile(self, path: str) -> float | None:
        """In [0, 1]; `None` se il churn è ignoto o il percorso non è un modulo del grafo."""
        value = self._churn.get(path)
        if value is None or not self._population:
            return None
        return bisect_left(self._population, value) / len(self._population)

    def percentile_of(self, paths: Iterable[str]) -> float | None:
        """Il massimo tra i membri che hanno un percentile; `None` se nessuno ce l'ha."""
        values = [p for p in (self.percentile(x) for x in paths) if p is not None]
        return max(values) if values else None
