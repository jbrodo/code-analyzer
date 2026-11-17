"""Unstable Dependency (G-07, ADR-0020): un pacchetto che dipende da pacchetti meno stabili.

Definizione, a livello di pacchetto: `I = Ce / (Ca + Ce)` (G-04). Il pacchetto P ha una dipendenza
instabile verso D quando `I(D) > I(P)`: dipende da qualcosa che cambia più facilmente di lui. Il
grado è la quota di dipendenze uscenti di P che sono instabili; si segnala se è almeno
`unstable_min_degree` (predefinito 0,3) e P ha almeno `unstable_min_outgoing` dipendenze.

Un'uguaglianza non è instabilità: due pacchetti con la stessa `I`, per esempio in un ciclo, non si
segnalano da questa regola. La definizione è trascritta a memoria da Arcelli Fontana et al.,
ICSME 2016 (nota di ADR-0020).
"""

from ca_graph.deps import DependencyGraph, instability
from ca_graph.smells.model import MAX_MEMBERS, UNSTABLE, Smell, SmellConfig


def find_unstable(deps: DependencyGraph, config: SmellConfig | None = None) -> list[Smell]:
    config = config or SmellConfig()
    value = {
        p: instability(len(deps.package_in[p]), len(deps.package_out[p])) for p in deps.packages
    }
    found = []
    for package, targets in deps.package_out.items():
        outgoing = len(targets)
        if outgoing == 0 or outgoing < config.unstable_min_outgoing:
            continue
        less_stable = tuple(t for t in targets if value[t] > value[package])
        degree = len(less_stable) / outgoing
        if not less_stable or degree < config.unstable_min_degree:
            continue
        found.append(
            Smell(
                rule_id=UNSTABLE,
                scope="package",
                anchor=package,
                members=(package, *less_stable),
                evidence={
                    "instability": round(value[package], 6),
                    "degree": round(degree, 6),
                    "outgoing": outgoing,
                    "less_stable": [
                        {"package": t, "instability": round(value[t], 6)}
                        for t in less_stable[:MAX_MEMBERS]
                    ],
                    "size": len(less_stable) + 1,
                },
            )
        )
    return found
