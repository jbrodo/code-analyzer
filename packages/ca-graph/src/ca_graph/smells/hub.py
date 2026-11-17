"""Hub-Like Dependency (G-06, ADR-0020): moduli con molte dipendenze entranti *e* uscenti.

Definizione, a livello di modulo: fan-in e fan-out **entrambi sopra la mediana** del sistema
(stretta, calcolata su tutti i moduli considerati, isolati compresi), sbilanciamento
`|Ca - Ce| / (Ca + Ce)` sotto `hub_balance` (predefinito 0,25), e grado totale `Ca + Ce` almeno
`hub_min_degree`.

Un modulo molto importato che non importa nulla (una utility) o che importa molto senza essere
importato (un punto d'ingresso) non è un hub: manca uno dei due lati o il bilanciamento. La
definizione è trascritta a memoria da Arcelli Fontana et al., ICSME 2016, e va confrontata con il
testo (nota di ADR-0020).

Avvertenza: con mediana 0, la norma, un modulo con un arco in ingresso e uno in uscita supera la
mediana. Il grado minimo è la guardia contro quel rumore; la tara X-02.
"""

from statistics import median

from ca_graph.deps import DependencyGraph, instability
from ca_graph.smells.model import HUB_LIKE, Smell, SmellConfig


def find_hubs(deps: DependencyGraph, config: SmellConfig | None = None) -> list[Smell]:
    config = config or SmellConfig()
    if not deps.modules:
        return []
    fan_in = {m: len(deps.module_in[m]) for m in deps.modules}
    fan_out = {m: len(deps.module_out[m]) for m in deps.modules}
    median_in, median_out = median(fan_in.values()), median(fan_out.values())
    found = []
    for module in deps.modules:
        ca, ce = fan_in[module], fan_out[module]
        total = ca + ce
        if ca <= median_in or ce <= median_out or total < config.hub_min_degree:
            continue
        imbalance = abs(ca - ce) / total
        if imbalance >= config.hub_balance:
            continue
        found.append(
            Smell(
                rule_id=HUB_LIKE,
                scope="module",
                anchor=module,
                members=(module,),
                evidence={
                    "fan_in": ca,
                    "fan_out": ce,
                    "median_fan_in": median_in,
                    "median_fan_out": median_out,
                    "imbalance": round(imbalance, 6),
                    "instability": round(instability(ca, ce), 6),
                    "size": 1,
                },
            )
        )
    return found
