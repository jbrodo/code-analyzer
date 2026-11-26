"""Grafo delle dipendenze tra moduli e pacchetti, con le metriche di accoppiamento (G-04, ADR-0020).

Lavora sul grafo emesso dal container di estrazione (`ca_core.models.graph.Graph`), cioè su dati:
nessun parser, nessuna lettura del workspace. Solo archi interni al repository; di default i moduli
di test non entrano nel calcolo e gli archi di soli tipi sì (ADR-0020), entrambi opzioni.

Definizioni (ADR-0020, granularità):

- **modulo**: un file sorgente; **pacchetto**: una cartella con almeno un modulo considerato,
  `.` per la radice del workspace. Una sottocartella è un pacchetto distinto dal padre.
- `fan_in` (Ca) e `fan_out` (Ce): numero di nodi *distinti* che dipendono da quel nodo e da cui
  quel nodo dipende. Tra pacchetti un arco A→B esiste se un modulo di A importa un modulo di B
  (con A diverso da B): gli archi interni a un pacchetto non contano.
- instabilità `I = Ce / (Ca + Ce)`, `0` per un nodo isolato.

Determinismo: stesso grafo e stesse opzioni, stessi elenchi e stesso ordine.
"""

import posixpath
from collections.abc import Mapping
from dataclasses import dataclass

from ca_core.models.graph import Graph, Metrics, Package


@dataclass(frozen=True)
class Options:
    include_tests: bool = False
    include_type_only: bool = True


@dataclass(frozen=True)
class DependencyGraph:
    """Adiacenze ordinate di moduli e pacchetti considerati, pronte per gli smell."""

    modules: tuple[str, ...]
    module_out: Mapping[str, tuple[str, ...]]
    module_in: Mapping[str, tuple[str, ...]]
    package_of: Mapping[str, str]
    packages: Mapping[str, tuple[str, ...]]  # pacchetto -> moduli che contiene
    package_out: Mapping[str, tuple[str, ...]]
    package_in: Mapping[str, tuple[str, ...]]
    package_edges: Mapping[tuple[str, str], int]  # (A, B) -> archi tra moduli che lo sostengono


def package_path(module_path: str) -> str:
    return posixpath.dirname(module_path) or "."


def instability(fan_in: int, fan_out: int) -> float:
    total = fan_in + fan_out
    return fan_out / total if total else 0.0


def build(graph: Graph, options: Options | None = None) -> DependencyGraph:
    options = options or Options()
    modules = sorted(m.path for m in graph.modules if options.include_tests or not m.test)
    considered = set(modules)
    out: dict[str, set[str]] = {m: set() for m in modules}
    into: dict[str, set[str]] = {m: set() for m in modules}
    for edge in graph.edges:
        if edge.external or edge.source not in considered or edge.target not in considered:
            continue
        if edge.type_only and not options.include_type_only:
            continue
        out[edge.source].add(edge.target)
        into[edge.target].add(edge.source)

    package_of = {m: package_path(m) for m in modules}
    members: dict[str, list[str]] = {}
    for module in modules:
        members.setdefault(package_of[module], []).append(module)
    package_out: dict[str, set[str]] = {p: set() for p in members}
    package_in: dict[str, set[str]] = {p: set() for p in members}
    package_edges: dict[tuple[str, str], int] = {}
    for source, targets in out.items():
        for target in targets:
            a, b = package_of[source], package_of[target]
            if a == b:
                continue
            package_out[a].add(b)
            package_in[b].add(a)
            package_edges[(a, b)] = package_edges.get((a, b), 0) + 1

    def frozen(mapping: dict[str, set[str]]) -> dict[str, tuple[str, ...]]:
        return {key: tuple(sorted(values)) for key, values in sorted(mapping.items())}

    return DependencyGraph(
        modules=tuple(modules),
        module_out=frozen(out),
        module_in=frozen(into),
        package_of=package_of,
        packages={p: tuple(ms) for p, ms in sorted(members.items())},
        package_out=frozen(package_out),
        package_in=frozen(package_in),
        package_edges=dict(sorted(package_edges.items())),
    )


def with_metrics(graph: Graph, options: Options | None = None) -> Graph:
    """Copia del grafo con `metrics` dei moduli considerati e l'elenco `packages` (G-04).

    I moduli esclusi (di test, per default) tornano senza metriche; un valore già presente non si
    conserva: le metriche dipendono dalle opzioni e le calcola sempre l'host.
    """
    deps = build(graph, options)
    modules = []
    for module in graph.modules:
        if module.path in deps.package_of:
            fan_in, fan_out = len(deps.module_in[module.path]), len(deps.module_out[module.path])
            metrics = Metrics(
                fan_in=fan_in,
                fan_out=fan_out,
                instability=instability(fan_in, fan_out),
                pagerank=module.metrics.pagerank if module.metrics else None,
            )
        else:
            metrics = None
        modules.append(module.model_copy(update={"metrics": metrics}))
    packages = [
        Package(
            path=path,
            modules=len(members),
            metrics=Metrics(
                fan_in=len(deps.package_in[path]),
                fan_out=len(deps.package_out[path]),
                instability=instability(len(deps.package_in[path]), len(deps.package_out[path])),
            ),
        )
        for path, members in deps.packages.items()
    ]
    return graph.model_copy(update={"modules": modules, "packages": packages})
