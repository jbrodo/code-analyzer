"""Esporta l'OpenAPI in `schemas/openapi.json` e ne verifica l'allineamento (ADR-0017).

Non avvia il server e non richiede database né rete: costruisce l'applicazione e ne legge lo
schema. Uscita deterministica: chiavi ordinate, indentazione fissa, a capo finale.
"""

import argparse
import json
import sys
from collections.abc import Sequence
from pathlib import Path

from ca_api.app import create_app
from ca_api.config import Settings

FILENAME = "openapi.json"


def render() -> str:
    app = create_app(Settings())  # valori predefiniti: l'ambiente non cambia il contratto
    return json.dumps(app.openapi(), indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="non scrive, verifica soltanto")
    parser.add_argument("--dir", type=Path, default=Path("schemas"))
    args = parser.parse_args(argv)
    path: Path = args.dir / FILENAME
    expected = render()
    if not args.check:
        args.dir.mkdir(parents=True, exist_ok=True)
        path.write_text(expected, encoding="utf-8")
        return 0
    if not path.is_file():
        print(f"{FILENAME}: mancante", file=sys.stderr)
        return 1
    if path.read_text(encoding="utf-8") != expected:
        print(f"{FILENAME}: diverso dall'applicazione", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
