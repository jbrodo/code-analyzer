"""Comando `sbom` (L-03, ADR-0007, 0010): SBOM CycloneDX 1.7 del workspace, solo syft.

Riusa `run_plugins`, che valida il documento contro lo schema fissato della versione dichiarata
dal manifest (K-02, K-03: syft emette gia' 1.7). Exit 0 con l'SBOM scritto, 2 altrimenti. Non c'e'
un report: cio' che i plugin non analizzano si dichiara su stderr. `plugins.disable` non vale qui:
chi lancia `sbom` ha chiesto proprio syft. Il documento va su stdout o in `--output`.
"""

import argparse
import sys
from pathlib import Path

from ca_cli.composition import Context
from ca_cli.scan import ScanError, coverage_warnings, load_config
from ca_core.models.scan_report import Outcome, Signature
from ca_core.pipeline.run_plugins import RunPluginsRequest, output_name, run_plugins
from ca_core.pipeline.workspace import PrepareWorkspaceRequest, WorkspaceError, prepare_workspace
from ca_core.ports import SourceError

PLUGIN = "syft"


def handle(args: argparse.Namespace, context: Context) -> int:
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
    try:
        store = context.schemas()
    except (OSError, ValueError) as exc:
        raise ScanError("schemi fissati non utilizzabili") from exc
    manifests = [m for m in context.manifests() if m.name == PLUGIN]
    if not manifests:
        raise ScanError(f"plugin {PLUGIN} non disponibile")
    coverage_warnings(root, config.paths.exclude)

    ran = run_plugins(
        RunPluginsRequest(
            repository=Path(root).name or "workspace", workspace=workspace, manifests=manifests
        ),
        context.executor,
        context.source,
        store,
        context.clock,
    )
    (execution,) = ran.executions
    if execution.run.outcome is Outcome.FAILED or execution.output_dir is None:
        raise ScanError(f"{PLUGIN} non riuscito: {execution.run.failure}")
    if execution.run.signature is Signature.SKIPPED:
        print("avviso: firma dell'immagine non verificata", file=sys.stderr)
    outputs = execution.manifest.outputs
    assert outputs.cyclonedx is not None  # e' il plugin che lo dichiara
    try:
        data = context.source.read_file(
            execution.output_dir, output_name(outputs.cyclonedx), outputs.max_bytes
        )
    except SourceError as exc:
        raise ScanError("sbom non leggibile") from exc

    if args.output is None:
        sys.stdout.write(data.decode())
        return 0
    target = Path(args.output)
    try:
        ref = context.artifact_sink(str(target.parent)).write(target.name, data)
    except (OSError, ValueError) as exc:
        raise ScanError("scrittura dell'sbom non riuscita") from exc
    print(f"scritto {ref.location}", file=sys.stderr)
    return 0
