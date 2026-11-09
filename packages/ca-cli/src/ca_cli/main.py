"""Comando `code-analyzer` (L-01, ADR-0010): scheletro, exit code e gestione degli errori.

Solo `scan`, `sbom`, `gate`, `config validate`. Libreria: `argparse` della libreria standard,
nessuna dipendenza (quattro comandi, nessun completamento automatico).

Exit code: 0 riuscito, 1 gate fallito (solo `gate`), 2 errore. Un'eccezione non prevista è
sempre 2, con un messaggio breve su stderr e senza traceback (i dati analizzati sono ostili).
"""

import argparse
import contextlib
import signal
import sys
import threading
from collections.abc import Callable, Generator, Sequence
from types import FrameType

from ca_cli import config_validate, gate, sbom, scan
from ca_cli.composition import Context, build_context
from ca_core.models.scan_report import Isolation

PROG = "code-analyzer"
Handler = Callable[[argparse.Namespace, Context], int]


# Il gestore di ogni comando si registra qui.
HANDLERS: dict[tuple[str, str | None], Handler] = {
    ("scan", None): scan.handle,
    ("sbom", None): sbom.handle,
    ("gate", None): gate.handle,
    ("config", "validate"): config_validate.handle,
}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog=PROG, description="Code Analyzer")
    commands = parser.add_subparsers(dest="command", metavar="COMMAND", required=True)
    scan_parser = commands.add_parser("scan", help="analizza una directory e scrive il report")
    scan_parser.add_argument("path", nargs="?", default=".", help="directory (predefinito: .)")
    scan_parser.add_argument("--output-dir", default=".", help="dove scrivere gli artefatti")
    scan_parser.add_argument(
        "--format", choices=["table", "json", "sarif"], default="table", help="solo lo stdout"
    )
    scan_parser.add_argument(
        "--min-isolation",
        type=Isolation,
        choices=list(Isolation),
        help="isolamento minimo richiesto (exit 2 se non disponibile)",
    )
    scan_parser.add_argument(
        "--offline", action="store_true", help="non sincronizzare i feed: usa lo snapshot esistente"
    )
    sbom_parser = commands.add_parser("sbom", help="genera l'SBOM CycloneDX")
    sbom_parser.add_argument("path", nargs="?", default=".", help="directory (predefinito: .)")
    sbom_parser.add_argument("--format", choices=["cyclonedx"], default="cyclonedx")
    sbom_parser.add_argument("--output", help="file di uscita (predefinito: stdout)")
    gate_parser = commands.add_parser(
        "gate", help="decide dal report se la scansione supera il gate"
    )
    gate_parser.add_argument("--report", default=gate.DEFAULT_REPORT, help="report di `scan`")
    gate_parser.add_argument(
        "--fail-on", type=gate.parse_levels, help="livelli bloccanti, separati da virgola"
    )
    gate_parser.add_argument(
        "--allow-partial", action="store_true", help="valuta anche una scansione parziale"
    )
    config = commands.add_parser("config", help="strumenti per .code-analyzer.yml")
    config_commands = config.add_subparsers(dest="config_command", metavar="COMMAND", required=True)
    validate = config_commands.add_parser("validate", help="valida .code-analyzer.yml offline")
    validate.add_argument("path", nargs="?", default=".", help="directory o file (predefinito: .)")
    return parser


_SIGNALS = (signal.SIGINT, signal.SIGTERM, signal.SIGHUP)


@contextlib.contextmanager
def _interruptible() -> Generator[None, None, None]:
    """Gestore unico per SIGINT, SIGTERM e SIGHUP (ADR-0004, M-03), solo nel thread principale.

    Alla prima consegna ignora i tre segnali, così un secondo non interrompe la pulizia, poi
    solleva `KeyboardInterrupt`. Ripristina i gestori precedenti alla fine.
    """
    if threading.current_thread() is not threading.main_thread():
        yield
        return

    def on_signal(signum: int, frame: FrameType | None) -> None:
        for sig in _SIGNALS:
            signal.signal(sig, signal.SIG_IGN)
        raise KeyboardInterrupt

    previous = {sig: signal.signal(sig, on_signal) for sig in _SIGNALS}
    try:
        yield
    finally:
        for sig, handler in previous.items():
            signal.signal(sig, handler)


def main(argv: Sequence[str] | None = None, *, context: Context | None = None) -> int:
    args = build_parser().parse_args(argv)  # errori di sintassi: exit 2 (argparse)
    handler = HANDLERS[(args.command, getattr(args, "config_command", None))]
    with _interruptible():
        ctx: Context | None = context
        try:
            ctx = ctx or build_context()
            return handler(args, ctx)
        except KeyboardInterrupt:
            print(f"{PROG}: interrotto", file=sys.stderr)
            return 2
        except Exception as exc:
            # `exit_code` è un attributo dei nostri errori attesi (runtime assente, isolamento).
            print(f"{PROG}: {_message(exc)}", file=sys.stderr)
            return 2
        finally:
            if ctx is not None:
                try:
                    ctx.close()
                except Exception as exc:  # la pulizia non cambia l'esito
                    print(f"{PROG}: pulizia incompleta ({exc.__class__.__name__})", file=sys.stderr)


def _message(exc: Exception) -> str:
    if hasattr(exc, "exit_code"):
        return str(exc)
    return f"errore interno ({exc.__class__.__name__})"
