"""Comando `gate` (L-05, ADR-0009, 0010): decide dal report di `scan`, senza altri ingressi.

Il report è un file non fidato: dimensione limitata, validazione con il modello di `ca_core`, e
messaggi senza valori del file. Sono stampati solo fingerprint, livello e categoria dei finding
bloccanti (campi validati), mai testi che vengono dagli scanner. Per i segreti il fingerprint si
omette: nei log CI permetterebbe di forzare offline un valore debole (N-27). Exit: quello di
`evaluate_gate` (0 superato, 1 fallito, 2 errore o scansione parziale senza `--allow-partial`).
Gli avvisi del report vanno su stderr, uno per codice e soggetto, senza cambiare l'exit: una
copertura ridotta resta visibile nel log della CI anche quando il gate è superato (D2-09). Si
stampano il codice (validato dal modello) e il soggetto solo se ha la forma di un nome di plugin.
La modalità PR è di `scan`; qui conta solo `gate.effective_mode` del report.
`--fail-on ""` è una scelta esplicita: nulla blocca.
"""

import argparse
import re
import sys
from pathlib import Path

from pydantic import ValidationError

from ca_cli.composition import Context
from ca_cli.scan import REPORT_FILE, ScanError
from ca_core.models.finding import Category, Level
from ca_core.models.scan_report import ScanReport
from ca_core.pipeline.gate import evaluate_gate

DEFAULT_REPORT = REPORT_FILE
MAX_REPORT_BYTES = 256 * 1024 * 1024
MAX_WARNING_LINES = 50
_PLUGIN_NAME = re.compile(r"[a-z][a-z0-9-]{0,63}")


def warning_lines(report: ScanReport) -> list[str]:
    """Una riga per coppia (codice, soggetto), in ordine, col numero di occorrenze se > 1."""
    counts: dict[tuple[str, str], int] = {}
    for warning in report.warnings:
        subject = warning.subject or ""
        key = (warning.code, subject if _PLUGIN_NAME.fullmatch(subject) else "")
        counts[key] = counts.get(key, 0) + 1
    lines = []
    for (code, subject), count in sorted(counts.items()):
        line = f"avviso del report: {code}" + (f" ({subject})" if subject else "")
        lines.append(line + (f" x{count}" if count > 1 else ""))
    if len(lines) > MAX_WARNING_LINES:
        rest = len(lines) - MAX_WARNING_LINES
        lines = [*lines[:MAX_WARNING_LINES], f"avviso del report: altri {rest} codici"]
    return lines


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
    print(f"modo: {result.mode.value}")
    print(
        f"soglia: {','.join(level.value for level in result.block_on)} ({result.block_on_source})"
    )
    for finding in result.blocking:
        level = finding.level.value if finding.level else "-"
        shown = "-" if finding.category is Category.SECRET else finding.fingerprint
        print(f"bloccante {shown} {level} {finding.category.value}")
    print(f"avvisi: {len(result.warned)}")
    for reason in result.reasons:
        print(f"motivo: {reason}", file=sys.stderr)
    for line in warning_lines(report):
        print(line, file=sys.stderr)
    return result.exit_code
