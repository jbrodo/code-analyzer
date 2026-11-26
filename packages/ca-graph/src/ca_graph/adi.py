"""Architectural Debt Index per modulo (G-13, ADR-0023, §6.2). Sull'host, sui dati: nessun I/O.

    ADI(m) = Σ G_B(s)   su ogni architectural smell s che include il modulo m

`G_B` è il G della Variante B dello smell (motore `arch_smell`), che chi chiama passa come
funzione: l'ADI esiste solo se B è configurata e c'è il benchmark. Uno smell a livello di pacchetto
include i moduli dei suoi pacchetti; l'ADI di un pacchetto è la somma sui suoi moduli. I moduli
senza metriche (di test, per default) non hanno ADI. Due decimali, metà verso l'alto, come i
punteggi.

Non è un fattore del punteggio e non decide livelli; nessun trend (Fase 4, D2-15).
"""

from collections import defaultdict
from collections.abc import Callable

from ca_core.models.graph import Graph
from ca_core.scoring.base import round_score
from ca_graph.deps import Options, build
from ca_graph.smells import Smell


def _covered(smell: Smell, packages: dict[str, list[str]]) -> set[str]:
    if smell.scope == "module":
        return set(smell.members)
    return {m for p in smell.members for m in packages.get(p, ())}


def with_adi(
    graph: Graph,
    smells: list[Smell],
    g_of: Callable[[Smell], float | None],
    options: Options | None = None,
) -> Graph:
    """Copia del grafo con `metrics.adi` su moduli e pacchetti; uno smell senza G non conta."""
    packages = {path: list(members) for path, members in build(graph, options).packages.items()}
    debt: dict[str, float] = defaultdict(float)
    for smell in smells:
        value = g_of(smell)
        if value is None:
            continue
        for module in _covered(smell, packages):
            debt[module] += value
    modules = [
        m.model_copy(
            update={"metrics": m.metrics.model_copy(update={"adi": round_score(debt[m.path])})}
        )
        if m.metrics is not None
        else m
        for m in graph.modules
    ]
    package_list = [
        p.model_copy(
            update={
                "metrics": p.metrics.model_copy(
                    update={"adi": round_score(sum(debt[m] for m in packages.get(p.path, ())))}
                )
            }
        )
        for p in graph.packages
    ]
    return graph.model_copy(update={"modules": modules, "packages": package_list})


__all__ = ["with_adi"]
