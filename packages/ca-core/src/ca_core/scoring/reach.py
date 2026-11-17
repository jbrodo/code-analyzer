"""Raggiungibilità: tipi e porta usati dallo scoring (G-12, K-04, ADR-0022). Nessun I/O.

Chi calcola la raggiungibilità dal grafo sta in `ca-graph`, che dipende da `ca-core`: qui ci sono
solo gli stati, il risultato e il protocollo che `ca-graph` realizza e lo scoring consuma.
"""

from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol


class ReachState(StrEnum):
    REACHABLE = "raggiungibile"
    TEST_ONLY = "solo-test"
    NOT_REACHABLE = "non-raggiungibile"
    UNKNOWN = "ignota"


# Dal migliore al peggiore per E (ADR-0022): `ignota` vale 0,3, `solo-test` e `non-raggiungibile`
# 0,2. Più membri nello stesso finding valgono lo stato migliore.
_RANK = {
    ReachState.REACHABLE: 3,
    ReachState.UNKNOWN: 2,
    ReachState.TEST_ONLY: 1,
    ReachState.NOT_REACHABLE: 0,
}


@dataclass(frozen=True)
class ReachResult:
    state: ReachState
    entrypoint: str | None = None  # il più vicino, solo con `raggiungibile`
    reason: str | None = None  # perché `ignota`: un codice, mai un contenuto del repository


def best(results: list[ReachResult]) -> ReachResult:
    """Il risultato migliore; a parità il primo in ordine di percorso dell'entrypoint."""
    if not results:
        return ReachResult(ReachState.UNKNOWN, reason="nessun-membro")
    return max(
        results,
        key=lambda r: (
            _RANK[r.state],
            -len(r.entrypoint or ""),
        ),
    )


class Reachability(Protocol):
    """Stato di raggiungibilità di un percorso e di un pacchetto esterno."""

    def module(self, path: str) -> ReachResult | None:
        """`None` se il percorso non è un modulo del grafo (IaC, segreti, licenze su file)."""
        ...

    def package(self, path: str) -> ReachResult | None:
        """Stato migliore tra i moduli sotto una cartella (`.` per tutti); `None` se non ce n'è."""
        ...

    def dependency(self, ecosystem: str, name: str) -> ReachResult:
        """Uso di un pacchetto: `raggiungibile`, `solo-test` o `ignota`, mai «non usata»."""
        ...


class NoReachability:
    """Grafo assente o fallito: tutto `ignota`, dichiarato (ADR-0022)."""

    def module(self, path: str) -> ReachResult | None:
        return ReachResult(ReachState.UNKNOWN, reason="grafo-assente")

    def package(self, path: str) -> ReachResult | None:
        return ReachResult(ReachState.UNKNOWN, reason="grafo-assente")

    def dependency(self, ecosystem: str, name: str) -> ReachResult:
        return ReachResult(ReachState.UNKNOWN, reason="grafo-assente")
