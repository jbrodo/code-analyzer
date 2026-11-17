"""Comando `scan` (L-04, ADR-0002, 0004, 0005, 0010, 0014): orchestra i passi di `ca-core`.

Scrive sempre `code-analyzer.report.json` e `code-analyzer.sarif` in `--output-dir`; `--format`
governa solo lo stdout. Exit 0 con un report prodotto (anche parziale), 2 senza; mai 1: decide
`gate`. Il repository analizzato non controlla immagini, firma, isolamento né rete: da
`.code-analyzer.yml` si legge solo il modello di `ca_core` (nessuna chiave per quei valori) e
`--min-isolation` viene solo dal flag. Dei repository si leggono solo `HEAD` e i ref di `.git`,
mai con `git` (hook e configurazione sono codice del repository).

Scelte conservative:
- `publish` (K-18) scrive già `code-analyzer.report.json` (`publish.REPORT_NAME`, ADR-0010).
- nessun plugin eseguito (nessun manifest o nessun linguaggio corrispondente): report `partial`
  con avviso `no-plugin-run`, perché un report vuoto e `complete` farebbe passare il gate.
- plugin con `feeds` senza snapshot utilizzabile: esecuzione `failed` (health) senza avviare
  il container; firma `skipped` perché in quel percorso non c'è una verifica propria.
- `inputs.config`: JSON generato qui con la sola parte del plugin, mai il file del repository
  (ADR-0014); oggi solo `plugins.semgrep.rules`, che l'adattatore ricontrolla.
"""

import argparse
import json
import os
import re
import sys
import tempfile
from collections import Counter
from collections.abc import Mapping, Sequence
from pathlib import Path

from ca_cli.composition import Context
from ca_cli.config_validate import (
    CONFIG_NAME,
    MAX_CONFIG_BYTES,
    ConfigFileError,
    parse_config,
    semantic_checks,
)
from ca_core.correlation import TABLE_VERSION
from ca_core.models import CodeAnalyzerConfig, PackagedPluginManifest
from ca_core.models.config import GateMode
from ca_core.models.plugin_manifest import InputMode
from ca_core.models.scan_report import (
    Gate,
    HistoryCoverage,
    InertSection,
    Isolation,
    PluginRun,
    ReportStatus,
    Repository,
    ScanReport,
    Signature,
    Warning_,
)
from ca_core.pipeline import publish as publish_step
from ca_core.pipeline.exclusions import coverage_exclusions, effective_exclusions
from ca_core.pipeline.normalize import NormalizeRequest, normalize
from ca_core.pipeline.publish import publish
from ca_core.pipeline.run_plugins import RunPluginsRequest, run_plugins
from ca_core.pipeline.workspace import PrepareWorkspaceRequest, WorkspaceError, prepare_workspace
from ca_core.ports import (
    ArtifactRef,
    FeedsPurgeRequest,
    FeedsSyncRequest,
    PluginRunRequest,
    PluginRunResult,
    RunOutcome,
    SourceError,
    SourceReader,
)
from ca_graph.step import BuildGraphRequest, build_graph
from ca_plugins.feeds import FeedsError, FeedsOutcome, default_cache_dir, ensure_snapshot
from ca_plugins.runner import require_isolation
from ca_plugins.source import count_skipped_symlinks, count_unreadable

GRAPH_FILE = "code-analyzer.graph.json"  # grafo con metriche e PageRank (G-10)
REPORT_FILE = publish_step.REPORT_NAME  # alias (ADR-0010): `gate.DEFAULT_REPORT` non cambia
_COMMIT = re.compile(r"[0-9a-f]{40}|[0-9a-f]{64}")
_REF = re.compile(r"refs/[A-Za-z0-9._/-]{1,200}")


class ScanError(Exception):
    """Errore atteso: exit 2, nessun report. Il testo non contiene dati del repository."""

    exit_code = 2


def load_config(root: str, source: SourceReader, context: Context) -> CodeAnalyzerConfig:
    if not os.path.lexists(Path(root) / CONFIG_NAME):
        return CodeAnalyzerConfig(version=1)
    try:
        data = source.read_file(root, CONFIG_NAME, MAX_CONFIG_BYTES)
    except SourceError as exc:
        raise ScanError(f"{CONFIG_NAME}: non leggibile") from exc
    try:
        config = parse_config(data)
    except ConfigFileError as exc:
        raise ScanError(f"{CONFIG_NAME}: {exc}") from exc
    errors, warnings = semantic_checks(config, Path(root), context.clock.now().date())
    for message in warnings:
        print(f"avviso: {CONFIG_NAME}: {message}", file=sys.stderr)
    if errors:
        raise ScanError(f"{CONFIG_NAME}: {'; '.join(errors)}")
    return config


def coverage_warnings(root: str, exclude: Sequence[str]) -> list[Warning_]:
    """Avvisi su cio' che i plugin non analizzano, anche su stderr. Mai nomi, solo il numero."""
    try:
        excluded = coverage_exclusions(exclude)
        unreadable = count_unreadable(root, excluded)  # A-02: il plugin gira come 65534
        links = count_skipped_symlinks(root, excluded)  # N-10, N-17, N-18, N-20
    except SourceError as exc:
        raise ScanError("workspace non esaminabile") from exc
    found: list[Warning_] = []
    if unreadable:
        text = f"{unreadable} percorsi non leggibili dai plugin: analisi incompleta"
        found.append(Warning_(code="workspace-unreadable", message=text))
    if links:
        text = f"{links} collegamenti simbolici con contenuto non analizzato: analisi incompleta"
        found.append(Warning_(code="workspace-symlinks", message=text))
    for warning in found:
        print(f"avviso: {warning.message}", file=sys.stderr)
    return found


def _git_state(root: str, source: SourceReader) -> tuple[str | None, HistoryCoverage]:
    """Commit e copertura della storia da `.git`, letti come dati non fidati."""
    if not os.path.lexists(Path(root) / ".git"):
        return None, HistoryCoverage.ABSENT
    commit: str | None = None
    try:
        head = source.read_file(root, ".git/HEAD", 4096).decode("ascii", "replace").strip()
        if _COMMIT.fullmatch(head):
            commit = head
        elif head.startswith("ref: ") and _REF.fullmatch(ref := head[5:]) and ".." not in ref:
            try:
                value = source.read_file(root, f".git/{ref}", 4096).decode("ascii", "replace")
                commit = value.strip() if _COMMIT.fullmatch(value.strip()) else None
            except SourceError:
                packed = source.read_file(root, ".git/packed-refs", 1 << 20).decode(
                    "utf-8", "replace"
                )
                for line in packed.splitlines():
                    sha, _, name = line.partition(" ")
                    if name == ref and _COMMIT.fullmatch(sha):
                        commit = sha
    except SourceError:
        pass
    # `.git` che non è una cartella (worktree) o con `shallow`: non si può garantire la storia.
    full = (Path(root) / ".git").is_dir() and not os.path.lexists(Path(root) / ".git" / "shallow")
    return commit, HistoryCoverage.FULL if full else HistoryCoverage.SHALLOW


class _FeedingExecutor:
    """Aggiunge alle richieste la configurazione del plugin e, con `feeds`, lo snapshot.

    Il resto è delega. Il parallelismo e il verificatore restano dell'esecutore interno; la
    sincronizzazione avviene prima del lotto, solo per i plugin davvero richiesti.
    """

    def __init__(
        self, inner: Context, cache_dir: Path, *, offline: bool, configs: Mapping[str, str]
    ) -> None:
        self._inner = inner.executor
        self._clock = inner.clock
        self._cache = cache_dir
        self._offline = offline
        self._configs = configs
        self.outcomes: dict[str, FeedsOutcome] = {}

    def isolation(self) -> Isolation:
        return self._inner.isolation()

    def sync_feeds(self, request: FeedsSyncRequest) -> PluginRunResult:
        return self._inner.sync_feeds(request)

    def purge_feeds(self, request: FeedsPurgeRequest) -> None:
        self._inner.purge_feeds(request)

    def run(self, request: PluginRunRequest) -> PluginRunResult:
        return self.run_many([request])[0]

    def _snapshot(self, manifest: PackagedPluginManifest) -> FeedsOutcome:
        if manifest.name not in self.outcomes:
            self.outcomes[manifest.name] = ensure_snapshot(
                manifest, self._inner, self._cache, self._clock, offline=self._offline
            )
        return self.outcomes[manifest.name]

    def _with_config(self, request: PluginRunRequest) -> PluginRunRequest:
        path = self._configs.get(request.manifest.name)
        if path is None or request.manifest.inputs.config is InputMode.NONE:
            return request
        return request.model_copy(update={"config": path})

    def run_many(self, requests: Sequence[PluginRunRequest]) -> list[PluginRunResult]:
        requests = [self._with_config(r) for r in requests]
        ready: dict[int, PluginRunRequest] = {}
        failed: dict[int, PluginRunResult] = {}
        for i, request in enumerate(requests):
            if request.manifest.feeds is None:
                ready[i] = request
                continue
            outcome = self._snapshot(request.manifest)  # ScanAborted si propaga
            if outcome.snapshot_dir is None:
                failed[i] = PluginRunResult(
                    outcome=RunOutcome.FAILED,
                    exit_code=None,
                    isolation=self._inner.isolation(),
                    signature=Signature.SKIPPED,
                    duration_seconds=0,
                    output_dir=None,
                    detail=outcome.failure,
                )
            else:
                ready[i] = request.model_copy(update={"feeds_snapshot": outcome.snapshot_dir})
        done = iter(self._inner.run_many(list(ready.values())))
        return [failed[i] if i in failed else next(done) for i in range(len(requests))]


def _plugin_configs(config: CodeAnalyzerConfig, directory: Path) -> dict[str, str]:
    """File `/inputs/config.json` per plugin, con la sola parte che lo riguarda (ADR-0014)."""
    configs: dict[str, str] = {}
    if config.plugins.semgrep is not None and config.plugins.semgrep.rules:
        path = directory / "semgrep.json"
        path.write_text(json.dumps({"rules": config.plugins.semgrep.rules}))
        configs["semgrep"] = str(path)
    # ADR-0026: i linter ricevono solo le regole da spegnere. Il repository non può attivarne.
    for name in ("ruff", "eslint", "checkov", "hadolint"):
        options = getattr(config.plugins, name)
        if options is not None and options.disable_rules:
            path = directory / f"{name}.json"
            path.write_text(json.dumps({"disable_rules": sorted(set(options.disable_rules))}))
            configs[name] = str(path)
    coverage = config.plugins.coverage
    if coverage is not None and coverage.reports:
        path = directory / "coverage.json"
        reports = [
            {"path": r.path, "format": r.format.value, "base_dir": r.base_dir}
            for r in coverage.reports
        ]
        path.write_text(json.dumps({"reports": reports}))
        configs["coverage"] = str(path)
    return configs


class _CapturingSink:
    """Sink che conserva i byte scritti per lo stdout; non rinomina."""

    def __init__(self, inner: Context, output_dir: str) -> None:
        self._sink = inner.artifact_sink(output_dir)
        self.contents: dict[str, bytes] = {}

    def write(self, name: str, content: bytes) -> ArtifactRef:
        self.contents[name] = content
        return self._sink.write(name, content)


def _table(report: ScanReport, refs: Sequence[ArtifactRef]) -> str:
    lines = [f"stato: {report.status.value}"]
    for run in report.plugins:
        extra = f" ({run.failure})" if run.failure else ""
        lines.append(f"plugin {run.name} {run.version}: {run.outcome.value}{extra}")
    for name in report.disabled_plugins:
        lines.append(f"plugin {name}: disattivato")
    levels = Counter(f.level.value if f.level else "senza livello" for f in report.findings)
    lines.append(f"finding: {len(report.findings)}")
    lines += [f"  {level}: {count}" for level, count in sorted(levels.items())]
    lines += [f"avviso {w.code}" for w in report.warnings]
    lines += [f"scritto {ref.location}" for ref in refs]
    return "\n".join(lines)


def handle(args: argparse.Namespace, context: Context) -> int:
    started = context.clock.now()
    root = str(Path(args.path).resolve())
    config = load_config(root, context.source, context)
    try:
        workspace = prepare_workspace(
            PrepareWorkspaceRequest(
                path=root, declared_languages=config.languages, exclude=config.paths.exclude
            ),
            context.source,
        )
    except WorkspaceError as exc:
        raise ScanError(str(exc)) from exc

    # Prima di qualunque container; il minimo viene solo dal flag.
    require_isolation(context.executor.isolation(), args.min_isolation)
    try:
        store = context.schemas()
    except (OSError, ValueError) as exc:
        raise ScanError("schemi fissati non utilizzabili") from exc

    coverage = coverage_warnings(root, config.paths.exclude)

    commit, history = _git_state(root, context.source)
    name = Path(root).name or "workspace"
    cache = context.feeds_cache or default_cache_dir()
    with tempfile.TemporaryDirectory(prefix="ca-config-") as scratch:
        configs = _plugin_configs(config, Path(scratch))
        feeding = _FeedingExecutor(context, cache, offline=args.offline, configs=configs)
        try:
            ran = run_plugins(
                RunPluginsRequest(
                    repository=name,
                    commit=commit,
                    workspace=workspace,
                    manifests=context.manifests(),
                    disabled=config.plugins.disable,
                ),
                feeding,
                context.source,
                store,
                context.clock,
            )
        except FeedsError as exc:
            raise ScanError(str(exc)) from exc
    warnings: list[Warning_] = []
    executions = []
    for execution in ran.executions:
        outcome = feeding.outcomes.get(execution.run.name)
        if outcome is not None:
            warnings += outcome.warnings
            run = execution.run.model_copy(update={"feed": outcome.feed})
            execution = execution.model_copy(update={"run": run})
        executions.append(execution)
    # G-10: dal grafo del plugin `ca-graph` agli smell; se il grafo non serve il plugin diventa
    # fallito e `normalize` ne fa un finding `health` (scansione parziale).
    graph_step = build_graph(
        BuildGraphRequest(
            repository=name,
            commit=commit,
            executions=executions,
            exclude=effective_exclusions(config.paths.exclude),
        ),
        context.source,
        context.clock,
    )
    executions = graph_step.executions
    normalized = normalize(
        NormalizeRequest(
            repository=name,
            commit=commit,
            workspace=root,
            executions=executions,
            config=config,
            extra_findings=graph_step.findings,
        ),
        context.source,
        store,
        context.clock,
    )

    warnings += normalized.warnings
    warnings += [
        Warning_(code="plugin-skipped", message="linguaggio non rilevato", subject=n)
        for n in ran.skipped_by_language
    ]
    status = normalized.status
    if coverage:
        warnings += coverage
        status = ReportStatus.PARTIAL
    if not executions:
        warnings.append(Warning_(code="no-plugin-run", message="nessun plugin eseguito"))
        status = ReportStatus.PARTIAL
    if config.gate.mode.value == "new-findings-only":
        warnings.append(
            Warning_(code="new-findings-only-as-all", message="in Fase 1 equivale a 'all'")
        )
    plugins: list[PluginRun] = normalized.plugins
    report = ScanReport(
        version=1,
        status=status,
        started_at=started,
        duration_seconds=max(0.0, (context.clock.now() - started).total_seconds()),
        repository=Repository(name=name[:500], commit=commit, history=history),
        gate=Gate(
            mode=config.gate.mode,
            effective_mode=GateMode.ALL,
            block_on=config.gate.block_on,
            warn_on=config.gate.warn_on,
        ),
        plugins=plugins,
        disabled_plugins=ran.disabled,
        exclusions=normalized.exclusions,
        correlation_version=TABLE_VERSION,
        exceptions=normalized.exceptions,
        inert_sections=[s for s in InertSection if getattr(config, s.value) is not None],
        warnings=warnings,
        findings=normalized.findings,
    )
    sink = _CapturingSink(context, args.output_dir)
    try:
        result = publish(report, sink, store)
    except ValueError as exc:  # PublishError, SarifError: nulla scritto
        raise ScanError(f"report non valido: {exc.__class__.__name__}") from exc
    except OSError as exc:
        raise ScanError("scrittura degli artefatti non riuscita") from exc
    if graph_step.graph is not None:
        try:
            sink.write(GRAPH_FILE, graph_step.graph.model_dump_json(exclude_none=True).encode())
        except OSError as exc:
            raise ScanError("scrittura degli artefatti non riuscita") from exc

    if args.format == "json":
        sys.stdout.write(sink.contents[REPORT_FILE].decode())
    elif args.format == "sarif":
        sys.stdout.write(sink.contents[publish_step.SARIF_NAME].decode())
    else:
        print(_table(report, [result.report, result.sarif]))
    if args.format != "table":
        print(f"scritti {result.report.location} e {result.sarif.location}", file=sys.stderr)
    return 0
