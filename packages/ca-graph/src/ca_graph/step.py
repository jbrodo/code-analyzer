"""Passo `build_graph` (G-10, ADR-0002, ADR-0008, ADR-0020): dal grafo del plugin ai finding.

Gira sull'host, sui dati: legge `outputs.graph` del plugin `ca-graph` con `SourceReader` (lettura
confinata e con tetto di byte), lo valida contro il contratto `graph`, toglie i moduli esclusi da
`paths.exclude` (ADR-0014), calcola metriche (G-04) e PageRank (G-08), cerca gli smell
(G-05..G-07) e li normalizza in `Finding` con `category: architecture` e un fingerprint stabile
(`kind` `architecture`, ADR-0008): spostare righe, rinominare un membro che non è l'ancora o
aggiungere un membro a un ciclo non lo cambia.

Funzione pura rispetto alle porte: stessi ingressi e stesso `Clock`, stesso risultato (ADR-0002).
Idempotente: rieseguita sullo stesso grafo dà gli stessi finding.

Un grafo mancante o non valido non produce finding di architettura: il plugin diventa `failed`, e il
passo `normalize` lo trasforma in un finding `health` e in una scansione `partial` (ADR-0007). Un
fallimento dell'estrazione non è mai un grafo vuoto.
"""

from pydantic import BaseModel, ConfigDict, ValidationError

from ca_core import fingerprint as fp
from ca_core.models.finding import Category, Finding, Location
from ca_core.models.graph import Graph
from ca_core.models.scan_report import Outcome
from ca_core.pipeline.exclusions import is_excluded
from ca_core.pipeline.run_plugins import PluginExecution, output_name
from ca_core.ports import Clock, SourceError, SourceReader
from ca_graph.deps import Options, build
from ca_graph.pagerank import PageRankConfig, with_pagerank
from ca_graph.smells import CYCLIC, HUB_LIKE, UNSTABLE, Smell, SmellConfig, detect

TOOL = "ca-graph"
_MAX_TEXT = 4096
_NAMED = 5  # membri nominati nel messaggio; l'elenco completo è nell'evidenza


class _Frozen(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, arbitrary_types_allowed=True)


class BuildGraphRequest(_Frozen):
    repository: str
    commit: str | None = None
    executions: list[PluginExecution]
    exclude: list[str]  # `paths.exclude` effettivi (ADR-0014)
    options: Options = Options()
    smells: SmellConfig = SmellConfig()
    pagerank: PageRankConfig = PageRankConfig()


class BuildGraphResult(_Frozen):
    findings: list[Finding]
    executions: list[PluginExecution]  # con il plugin `ca-graph` fallito se il grafo non serve
    graph: Graph | None  # con metriche e PageRank, da conservare come artefatto


def _graph_execution(executions: list[PluginExecution]) -> PluginExecution | None:
    return next((e for e in executions if e.manifest.outputs.graph is not None), None)


def _fail(execution: PluginExecution, reason: str) -> PluginExecution:
    run = execution.run.model_copy(update={"outcome": Outcome.FAILED, "failure": reason})
    return execution.model_copy(update={"run": run})


def _read(execution: PluginExecution, reader: SourceReader) -> Graph:
    """Il grafo del plugin, validato; `ValueError` con un motivo generico altrimenti."""
    manifest, directory = execution.manifest, execution.output_dir
    assert manifest.outputs.graph is not None
    if directory is None:
        raise ValueError("output assente")
    try:
        data = reader.read_file(
            directory, output_name(manifest.outputs.graph), manifest.outputs.max_bytes
        )
    except SourceError as exc:
        raise ValueError("grafo non leggibile o troppo grande") from exc
    try:
        return Graph.model_validate_json(data)
    except (ValidationError, ValueError) as exc:
        raise ValueError("output non utilizzabile: grafo non conforme al contratto") from exc


def _without_excluded(graph: Graph, patterns: list[str]) -> Graph:
    """Toglie nodi e archi dei moduli esclusi prima di ogni calcolo (ADR-0020, ADR-0014)."""
    if not patterns:
        return graph
    dropped = {m.path for m in graph.modules if is_excluded(m.path, patterns)}
    if not dropped:
        return graph
    return graph.model_copy(
        update={
            "modules": [m for m in graph.modules if m.path not in dropped],
            "edges": [
                e for e in graph.edges if e.source not in dropped and e.target not in dropped
            ],
            "entrypoints": [e for e in graph.entrypoints if e.path not in dropped],
        }
    )


def _title_and_message(smell: Smell) -> tuple[str, str]:
    unit = "moduli" if smell.scope == "module" else "pacchetti"
    named = ", ".join(smell.members[:_NAMED]) + (" e altri" if smell.size > _NAMED else "")
    if smell.rule_id == CYCLIC:
        return (
            f"Dipendenza ciclica tra {smell.size} {unit}",
            f"{smell.size} {unit} dipendono l'uno dall'altro in un ciclo: {named}.",
        )
    if smell.rule_id == HUB_LIKE:
        e = smell.evidence
        return (
            "Modulo hub: molte dipendenze in entrata e in uscita",
            f"{smell.anchor} ha {e['fan_in']} dipendenze in entrata e {e['fan_out']} in uscita, "
            "entrambe sopra la mediana del sistema.",
        )
    e = smell.evidence
    return (
        "Dipendenza da pacchetti meno stabili",
        f"{smell.anchor} (instabilità {e['instability']}) dipende da {len(smell.members) - 1} "
        f"pacchetti più instabili: {', '.join(smell.members[1 : _NAMED + 1])}.",
    )


def finding_of(smell: Smell, *, repository: str, commit: str | None, clock: Clock) -> Finding:
    fingerprint = fp.fingerprint_architecture(
        rule_id=smell.rule_id, scope=smell.scope, path=smell.anchor
    )
    title, message = _title_and_message(smell)
    now = clock.now()
    return Finding(
        id=fingerprint,
        fingerprint=fingerprint,
        category=Category.ARCHITECTURE,
        rule_id=smell.rule_id,
        tool=TOOL,
        tools=[TOOL],
        title=title,
        message=message[:_MAX_TEXT],
        location=Location(repository=repository, commit=commit, path=smell.anchor),
        evidence={TOOL: {"scope": smell.scope, **smell.evidence}},
        first_seen=now,
        last_seen=now,
    )


def build_graph(request: BuildGraphRequest, reader: SourceReader, clock: Clock) -> BuildGraphResult:
    execution = _graph_execution(request.executions)
    if execution is None or execution.run.outcome is not Outcome.OK:
        return BuildGraphResult(findings=[], executions=request.executions, graph=None)
    try:
        graph = _read(execution, reader)
    except ValueError as exc:
        failed = [_fail(e, str(exc)) if e is execution else e for e in request.executions]
        return BuildGraphResult(findings=[], executions=failed, graph=None)
    graph = _without_excluded(graph, request.exclude)
    deps = build(graph, request.options)
    findings = [
        finding_of(s, repository=request.repository, commit=request.commit, clock=clock)
        for s in detect(deps, request.smells)
    ]
    enriched = with_pagerank(graph, request.options, request.pagerank)
    return BuildGraphResult(findings=findings, executions=request.executions, graph=enriched)


__all__ = ["BuildGraphRequest", "BuildGraphResult", "UNSTABLE", "build_graph", "finding_of"]
