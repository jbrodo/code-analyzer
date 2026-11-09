"""Passo `run_plugins` a due stadi (K-16, ADR-0002, ADR-0005, ADR-0007).

Primo stadio: i plugin con `outputs.cyclonedx` (ordinati per nome). Secondo stadio: gli altri, che
con `inputs.sbom: optional` ricevono l'SBOM se disponibile. Ogni stadio è una sola chiamata a
`PluginExecutor.run_many`, senza catturare eccezioni; il secondo parte a primo finito, perché
l'SBOM è un suo ingresso. Il parallelismo dentro lo stadio è dell'adattatore (ADR-0002); la
lettura degli SBOM è sequenziale e per nome. Ingresso e uscita sono modelli serializzabili.

Un plugin che non ha successo (`failed`, `timeout`, `invalid_output`, SBOM non valido) non ferma
gli altri: diventa un `PluginRun` con `outcome: failed`, un finding `health`
`ca.scanner-not-run` e un report `partial`. Le eccezioni dell'esecutore (`ScanAborted`: firma
assente o non valida, runtime assente) non si catturano: exit 2 senza report (ADR-0005).

Scelte conservative: dove più plugin del primo stadio producono un SBOM valido, si monta quello
del primo per nome; si filtra per `languages` del manifest sulla lingua rilevata (`languages`
vuoto: sempre); `inputs.config` e i `feeds` non si cablano qui (config per plugin e snapshot sono
della CLI). I testi di fallimento sono codici e cause generiche, mai output dello scanner.
"""

from collections.abc import Callable

from pydantic import BaseModel, ConfigDict, Field

from ca_core.models.finding import Finding
from ca_core.models.plugin_manifest import OUT_DIR, InputMode, PackagedPluginManifest
from ca_core.models.scan_report import Outcome, PluginRun, ReportStatus
from ca_core.normalize import health_finding
from ca_core.pipeline.workspace import Workspace
from ca_core.ports import (
    Clock,
    PluginExecutor,
    PluginRunRequest,
    PluginRunResult,
    RunOutcome,
    SourceError,
    SourceReader,
)
from ca_core.sbom import SbomError, parse_cyclonedx
from ca_core.schema_validation import SchemaStore

_MAX_FAILURE = 500


class _Frozen(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class RunPluginsRequest(_Frozen):
    repository: str
    commit: str | None = None
    workspace: Workspace
    manifests: list[PackagedPluginManifest]
    disabled: list[str] = Field(default_factory=list)  # `plugins.disable` della configurazione


class PluginExecution(_Frozen):
    manifest: PackagedPluginManifest
    run: PluginRun
    output_dir: str | None  # `/out` dell'esecuzione, da leggere con `SourceReader`


class RunPluginsResult(_Frozen):
    executions: list[PluginExecution]  # primo stadio, poi secondo; ciascuno per nome
    disabled: list[str]  # presenti tra i manifest e in `plugins.disable`, ordinati
    skipped_by_language: list[str]
    sbom_from: str | None  # plugin il cui SBOM è stato montato nel secondo stadio
    health: list[Finding]  # un `ca.scanner-not-run` per plugin fallito
    status: ReportStatus


def output_name(path: str) -> str:
    """Nome relativo dentro `/out` di un percorso di `outputs` (`/out/x.json` -> `x.json`)."""
    return path.removeprefix(f"{OUT_DIR}/")


def _digest(manifest: PackagedPluginManifest) -> str:
    return manifest.image.rpartition("@")[2]


def _text(value: str) -> str:
    return "".join(c if c.isprintable() else "?" for c in value)[:_MAX_FAILURE]


def _failure_text(result: PluginRunResult) -> str | None:
    if result.outcome is RunOutcome.INVALID_OUTPUT:
        return _text(result.detail or "output non valido")
    if result.outcome is RunOutcome.TIMEOUT:
        base = "timeout"
    elif result.outcome is RunOutcome.FAILED:
        base = "esecuzione fallita" + (
            f" (exit {result.exit_code})" if result.exit_code is not None else ""
        )
    elif result.output_dir is None:
        base = "output assente"
    else:
        return None
    return _text(f"{base}: {result.detail}" if result.detail else base)


def _run_record(
    manifest: PackagedPluginManifest, result: PluginRunResult, failure: str | None
) -> PluginRun:
    return PluginRun(
        name=manifest.name,
        version=manifest.version,
        digest=_digest(manifest),
        signature=result.signature,
        isolation=result.isolation,
        duration_seconds=float(result.duration_seconds),
        outcome=Outcome.FAILED if failure else Outcome.OK,
        failure=failure,
    )


def _read_sbom(execution: PluginExecution, reader: SourceReader, store: SchemaStore) -> str:
    """Percorso dell'SBOM se valido; `ValueError` con un motivo generico altrimenti."""
    manifest, directory = execution.manifest, execution.output_dir
    assert manifest.outputs.cyclonedx is not None and directory is not None
    name = output_name(manifest.outputs.cyclonedx)
    try:
        data = reader.read_file(directory, name, manifest.outputs.max_bytes)
        parse_cyclonedx(
            data, store, manifest.outputs.cyclonedx_version or "", manifest.outputs.max_bytes
        )
    except SbomError as exc:
        raise ValueError(f"sbom non utilizzabile: {exc.code.value}") from exc
    except SourceError as exc:
        raise ValueError("sbom non leggibile o troppo grande") from exc
    return f"{directory.rstrip('/')}/{name}"


def _fail(execution: PluginExecution, reason: str) -> PluginExecution:
    run = execution.run.model_copy(update={"outcome": Outcome.FAILED, "failure": _text(reason)})
    return execution.model_copy(update={"run": run})


def _execute_stage(
    manifests: list[PackagedPluginManifest],
    request: RunPluginsRequest,
    executor: PluginExecutor,
    sbom_for: Callable[[PackagedPluginManifest], str | None],
) -> list[PluginExecution]:
    requests = [
        PluginRunRequest(manifest=m, workspace=request.workspace.path, sbom=sbom_for(m))
        for m in manifests
    ]
    results = executor.run_many(requests)  # `ScanAborted` si propaga: nessun report
    return [
        PluginExecution(
            manifest=m, run=_run_record(m, r, _failure_text(r)), output_dir=r.output_dir
        )
        for m, r in zip(manifests, results, strict=True)
    ]


def run_plugins(
    request: RunPluginsRequest,
    executor: PluginExecutor,
    reader: SourceReader,
    store: SchemaStore,
    clock: Clock,
) -> RunPluginsResult:
    manifests = sorted(request.manifests, key=lambda m: m.name)
    disabled = [m.name for m in manifests if m.name in request.disabled]
    candidates = [m for m in manifests if m.name not in request.disabled]
    wanted = set(request.workspace.languages)
    selected = [m for m in candidates if not m.languages or wanted & set(m.languages)]
    skipped = [m.name for m in candidates if m not in selected]

    stage_one = [m for m in selected if m.outputs.cyclonedx is not None]
    stage_two = [m for m in selected if m.outputs.cyclonedx is None]

    executions: list[PluginExecution] = []
    sbom: str | None = None
    sbom_from: str | None = None
    for execution in _execute_stage(stage_one, request, executor, lambda _m: None):
        if execution.run.outcome is Outcome.OK:
            try:
                path = _read_sbom(execution, reader, store)
            except ValueError as exc:
                execution = _fail(execution, str(exc))
            else:
                if sbom is None:
                    sbom, sbom_from = path, execution.manifest.name
        executions.append(execution)

    executions += _execute_stage(
        stage_two,
        request,
        executor,
        lambda m: sbom if m.inputs.sbom is InputMode.OPTIONAL else None,
    )

    health = [
        health_finding(
            e.run.name,
            e.run.failure or "",
            repository=request.repository,
            commit=request.commit,
            clock=clock,
        )
        for e in executions
        if e.run.outcome is Outcome.FAILED
    ]
    return RunPluginsResult(
        executions=executions,
        disabled=disabled,
        skipped_by_language=skipped,
        sbom_from=sbom_from,
        health=health,
        status=ReportStatus.PARTIAL if health else ReportStatus.COMPLETE,
    )
