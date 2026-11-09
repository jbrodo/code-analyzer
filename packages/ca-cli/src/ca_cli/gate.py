"""Comando `gate` (L-05, ADR-0009, 0010): decide dal report di `scan`, senza altri ingressi.

Il report è un file non fidato: dimensione limitata, validazione con il modello di `ca_core`, e
messaggi senza valori del file. Sono stampati solo fingerprint, livello e categoria dei finding
bloccanti (campi validati), mai testi che vengono dagli scanner. Exit: quello di `evaluate_gate`
(0 superato, 1 fallito, 2 errore o scansione parziale senza `--allow-partial`).
Nessun `--pr` né `--base`. `--fail-on ""` è una scelta esplicita: nulla blocca.
"""

import argparse
import sys
from pathlib import Path

from pydantic import ValidationError

from ca_cli.composition import Context
from ca_cli.scan import REPORT_FILE, ScanError
from ca_core.models.finding import Level
from ca_core.models.scan_report import ScanReport
from ca_core.pipeline.gate import evaluate_gate

DEFAULT_REPORT = REPORT_FILE
MAX_REPORT_BYTES = 256 * 1024 * 1024


def parse_levels(value: str) -> list[Level]:
    """Livelli separati da virgola; `argparse` ne fa un errore di sintassi (exit 2)."""
    try:
        return [Level(item.strip()) for item in value.split(",") if item.strip()]
    except ValueError as exc:
        valid = ", ".join(level.value for level in Level)
        raise argparse.ArgumentTypeError(f"livelli ammessi: {valid}") from exc


def _read_report(path: Path) -> ScanReport:
    try:
        with path.open("rb") as handle:
            data = handle.read(MAX_REPORT_BYTES + 1)
    except OSError as exc:
        raise ScanError(f"{path.name}: report non leggibile") from exc
    if len(data) > MAX_REPORT_BYTES:
        raise ScanError(f"{path.name}: report troppo grande")
    try:
        return ScanReport.model_validate_json(data)
    except ValidationError as exc:
        raise ScanError(f"{path.name}: report non valido ({exc.error_count()} errori)") from exc


def handle(args: argparse.Namespace, context: Context) -> int:
    report = _read_report(Path(args.report))
    result = evaluate_gate(report, fail_on=args.fail_on, allow_partial=args.allow_partial)
    verdict = {0: "superato", 1: "fallito", 2: "errore"}[result.exit_code]
    print(f"gate: {verdict}")
    print(
        f"soglia: {','.join(level.value for level in result.block_on)} ({result.block_on_source})"
    )
    for finding in result.blocking:
        level = finding.level.value if finding.level else "-"
        print(f"bloccante {finding.fingerprint} {level} {finding.category.value}")
    print(f"avvisi: {len(result.warned)}")
    for reason in result.reasons:
        print(f"motivo: {reason}", file=sys.stderr)
    return result.exit_code
