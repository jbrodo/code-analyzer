"""Comando `export` (N-06, ADR-0010, ADR-0027): report nativi di GitLab dal report di `scan`.

Non decide nulla e non esegue plugin. Scrive `gl-sast-report.json`, `gl-dependency-scanning-
report.json`, `gl-code-quality-report.json` e, con `--sbom`, `gl-sbom-code-analyzer.cdx.json`
(l'SBOM del prodotto riportato alla 1.6, che GitLab accetta). Ogni file è validato contro lo schema
fissato prima di scrivere: se uno non è valido non se ne scrive nessuno (exit 2, solo il nome del
file nel messaggio). Segreti, licenze, IaC e architettura non hanno posto in questi formati: si
dice quanti sono, e restano nel report e nel SARIF. Exit: 0 fatto, 2 errore.
"""

import argparse
import json
import sys
from importlib import metadata
from pathlib import Path
from typing import Any

from ca_cli.composition import Context
from ca_cli.gate import DEFAULT_REPORT, MAX_REPORT_BYTES, _read_report
from ca_cli.scan import ScanError
from ca_core.schema_validation import SchemaRefusedError, SchemaStore
from ca_integrations.gitlab import ExportError, build_reports, to_cyclonedx_16
from ca_integrations.gitlab.export import CODEQUALITY

SAST_FILE = "gl-sast-report.json"
DEPENDENCY_FILE = "gl-dependency-scanning-report.json"
CODEQUALITY_FILE = "gl-code-quality-report.json"
SBOM_FILE = "gl-sbom-code-analyzer.cdx.json"
_SAST_SCHEMA = "gitlab-sast-15.2.5.schema.json"
_DEPENDENCY_SCHEMA = "gitlab-dependency-scanning-15.2.5.schema.json"


def _version() -> str:
    try:
        return metadata.version("ca-cli")
    except metadata.PackageNotFoundError:
        return "0"


def _read_json(path: Path) -> Any:
    try:
        with path.open("rb") as handle:
            data = handle.read(MAX_REPORT_BYTES + 1)
    except OSError as exc:
        raise ScanError(f"{path.name}: file non leggibile") from exc
    if len(data) > MAX_REPORT_BYTES:
        raise ScanError(f"{path.name}: file troppo grande")
    try:
        return json.loads(data)
    except (ValueError, RecursionError) as exc:
        raise ScanError(f"{path.name}: JSON non valido") from exc


def _dump(document: Any) -> bytes:
    return (json.dumps(document, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode()


def _check(name: str, errors: list[str]) -> None:
    if errors:
        raise ScanError(f"{name}: non valido rispetto allo schema fissato ({len(errors)} errori)")


def handle(args: argparse.Namespace, context: Context) -> int:
    report = _read_report(Path(args.report))
    reports = build_reports(report, version=_version())
    try:
        store = SchemaStore.packaged()
    except SchemaRefusedError as exc:
        raise ScanError("schemi fissati non utilizzabili") from exc
    files: dict[str, bytes] = {}
    _check(SAST_FILE, store.validate_pinned(_SAST_SCHEMA, reports.sast))
    _check(
        DEPENDENCY_FILE,
        store.validate_pinned(_DEPENDENCY_SCHEMA, reports.dependency_scanning),
    )
    files[SAST_FILE] = _dump(reports.sast)
    files[DEPENDENCY_FILE] = _dump(reports.dependency_scanning)
    files[CODEQUALITY_FILE] = _dump(reports.codequality)
    if args.sbom is not None:
        try:
            converted = to_cyclonedx_16(_read_json(Path(args.sbom)))
        except ExportError as exc:
            raise ScanError(f"{Path(args.sbom).name}: {exc}") from exc
        _check(SBOM_FILE, store.validate_cyclonedx_export(converted, "1.6"))
        files[SBOM_FILE] = _dump(converted)
    sink = context.artifact_sink(args.output_dir)
    for name, data in files.items():
        try:
            sink.write(name, data)
        except (OSError, ValueError) as exc:
            raise ScanError(f"scrittura di {name} non riuscita") from exc
    counts = {
        "sast": len(reports.sast["vulnerabilities"]),
        "dependency_scanning": len(reports.dependency_scanning["vulnerabilities"]),
        CODEQUALITY: len(reports.codequality),
    }
    print("esportati: " + ", ".join(f"{k}={v}" for k, v in counts.items()), file=sys.stderr)
    if reports.skipped:
        text = ", ".join(f"{k}={v}" for k, v in sorted(reports.skipped.items()))
        print(f"senza il dato richiesto dal formato, non esportati: {text}", file=sys.stderr)
    if reports.not_exported:
        text = ", ".join(f"{k}={v}" for k, v in sorted(reports.not_exported.items()))
        print(
            f"senza posto nei report di GitLab (restano nel report e nel SARIF): {text}",
            file=sys.stderr,
        )
    return 0


def add_parser(commands: Any) -> None:
    parser = commands.add_parser("export", help="report nativi di GitLab dal report di `scan`")
    parser.add_argument("--format", choices=["gitlab"], default="gitlab")
    parser.add_argument("--report", default=DEFAULT_REPORT, help="report di `scan`")
    parser.add_argument("--sbom", help="SBOM di `sbom` da riportare alla 1.6 per GitLab")
    parser.add_argument("--output-dir", default=".", help="dove scrivere i report")
