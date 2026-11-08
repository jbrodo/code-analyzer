"""Comando `code-analyzer` (L-01, ADR-0010): scheletro, exit code e gestione degli errori.

Solo `scan`, `sbom`, `gate`, `config validate`. I gestori sono ancora da scrivere (L-02 e
successivi): finché mancano rispondono con exit 2, mai con un risultato finto. Libreria: `argparse`
della libreria standard, nessuna dipendenza (quattro comandi, nessun completamento automatico).

Exit code: 0 riuscito, 1 gate fallito (solo `gate`), 2 errore. Un'eccezione non prevista è
sempre 2, con un messaggio breve su stderr e senza traceback (i dati analizzati sono ostili).
"""

import argparse
import sys
from collections.abc import Callable, Sequence

from ca_cli.composition import Context, build_context

PROG = "code-analyzer"
Handler = Callable[[argparse.Namespace, Context], int]


def _not_implemented(args: argparse.Namespace, context: Context) -> int:
    name = " ".join(filter(None, [args.command, getattr(args, "config_command", None)]))
    print(f"{PROG}: il comando '{name}' non è ancora disponibile", file=sys.stderr)
    return 2


# Il gestore di ogni comando si registra qui (L-02 e successivi).
HANDLERS: dict[tuple[str, str | None], Handler] = {
    ("scan", None): _not_implemented,
    ("sbom", None): _not_implemented,
    ("gate", None): _not_implemented,
    ("config", "validate"): _not_implemented,
}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog=PROG, description="Code Analyzer")
    commands = parser.add_subparsers(dest="command", metavar="COMMAND", required=True)
    commands.add_parser("scan", help="analizza una directory e scrive il report")
    commands.add_parser("sbom", help="genera l'SBOM CycloneDX")
    commands.add_parser("gate", help="decide dal report se la scansione supera il gate")
    config = commands.add_parser("config", help="strumenti per .code-analyzer.yml")
    config_commands = config.add_subparsers(dest="config_command", metavar="COMMAND", required=True)
    config_commands.add_parser("validate", help="valida .code-analyzer.yml offline")
    return parser


def main(argv: Sequence[str] | None = None, *, context: Context | None = None) -> int:
    args = build_parser().parse_args(argv)  # errori di sintassi: exit 2 (argparse)
    handler = HANDLERS[(args.command, getattr(args, "config_command", None))]
    try:
        return handler(args, context or build_context())
    except KeyboardInterrupt:
        print(f"{PROG}: interrotto", file=sys.stderr)
        return 2
    except Exception as exc:
        # `exit_code` è un attributo dei nostri errori attesi (runtime assente, isolamento).
        print(f"{PROG}: {_message(exc)}", file=sys.stderr)
        return 2


def _message(exc: Exception) -> str:
    if hasattr(exc, "exit_code"):
        return str(exc)
    return f"errore interno ({exc.__class__.__name__})"
