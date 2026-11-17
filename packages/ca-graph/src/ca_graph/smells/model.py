"""Modello comune degli smell architetturali (G-05..G-07, ADR-0020).

Uno smell è un dato: regola, ambito, ancora e prova. Diventa un `Finding` con `category:
architecture` in G-10, che sceglie fingerprint e testi. Le soglie stanno in una configurazione
esplicita (`SmellConfig`), mai nella logica (`AGENTS.md`, regola 3); i valori predefiniti sono
quelli di ADR-0020 e li sostituirà la configurazione di scoring (C-03).
"""

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any, Literal

Scope = Literal["module", "package"]

CYCLIC = "ca.arch.cyclic-dependency"
HUB_LIKE = "ca.arch.hub-like-dependency"
UNSTABLE = "ca.arch.unstable-dependency"

MAX_MEMBERS = 20  # elementi elencati nell'evidenza; il totale è sempre in `size`


@dataclass(frozen=True)
class SmellConfig:
    # Cyclic Dependency: dimensione minima di una componente fortemente connessa e livelli attivi.
    cycle_min_size: int = 2
    cycle_scopes: tuple[Scope, ...] = ("module", "package")
    # Hub-Like Dependency: sbilanciamento massimo `|Ca - Ce| / (Ca + Ce)` e guardia sul grado
    # totale minimo. La guardia vale 0 (spenta) come in ADR-0020; X-02 la tara sui dati reali.
    hub_balance: float = 0.25
    hub_min_degree: int = 0
    # Unstable Dependency: quota minima di dipendenze verso pacchetti meno stabili e guardia sulle
    # dipendenze uscenti minime (spenta a 0).
    unstable_min_degree: float = 0.3
    unstable_min_outgoing: int = 0

    def __post_init__(self) -> None:
        if self.cycle_min_size < 2:
            raise ValueError("cycle_min_size: almeno 2")
        if not 0 <= self.hub_balance <= 1 or not 0 <= self.unstable_min_degree <= 1:
            raise ValueError("hub_balance e unstable_min_degree stanno in [0, 1]")
        if self.hub_min_degree < 0 or self.unstable_min_outgoing < 0:
            raise ValueError("le guardie non sono negative")


@dataclass(frozen=True)
class Smell:
    rule_id: str
    scope: Scope
    anchor: str  # percorso del modulo o del pacchetto a cui si attacca il finding
    members: tuple[str, ...]  # nodi coinvolti, ordinati
    evidence: Mapping[str, Any] = field(default_factory=dict)

    @property
    def size(self) -> int:
        return len(self.members)


def listed(members: Sequence[str]) -> dict[str, Any]:
    """Elenco con tetto e totale: un ciclo enorme non gonfia l'evidenza."""
    return {"members": list(members[:MAX_MEMBERS]), "size": len(members)}
