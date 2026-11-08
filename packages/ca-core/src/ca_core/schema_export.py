"""Esporta i contratti Pydantic in `schemas/` e ne verifica l'allineamento (ADR-0003)."""

import argparse
import json
import sys
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

from pydantic import BaseModel

JSON_SCHEMA_DIALECT = "https://json-schema.org/draft/2020-12/schema"
SUFFIX = ".schema.json"


@dataclass(frozen=True)
class Contract:
    name: str
    version: str  # "maggiore.minore": dentro una maggiore solo aggiunte compatibili
    model: type[BaseModel]

    @property
    def filename(self) -> str:
        return f"{self.name}{SUFFIX}"

    def render(self) -> str:
        major = self.version.partition(".")[0]
        schema = {
            "$schema": JSON_SCHEMA_DIALECT,
            "$id": f"urn:code-analyzer:schema:{self.name}:v{major}",
            "x-schema-version": self.version,
            **self.model.model_json_schema(),
        }
        return json.dumps(schema, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


# I task C-01..C-05 registrano qui i contratti.
CONTRACTS: tuple[Contract, ...] = ()


def export(contracts: Sequence[Contract], directory: Path) -> None:
    directory.mkdir(parents=True, exist_ok=True)
    for contract in contracts:
        (directory / contract.filename).write_text(contract.render(), encoding="utf-8")


def check(contracts: Sequence[Contract], directory: Path) -> list[str]:
    """Restituisce le divergenze tra i modelli e i file esportati."""
    problems = []
    for contract in contracts:
        path = directory / contract.filename
        if not path.is_file():
            problems.append(f"{contract.filename}: mancante")
        elif path.read_text(encoding="utf-8") != contract.render():
            problems.append(f"{contract.filename}: diverso dal modello")
    expected = {contract.filename for contract in contracts}
    problems += [
        f"{path.name}: senza contratto"
        for path in sorted(directory.glob(f"*{SUFFIX}"))
        if path.name not in expected
    ]
    return problems


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="non scrive, verifica soltanto")
    parser.add_argument("--dir", type=Path, default=Path("schemas"))
    args = parser.parse_args(argv)
    if not args.check:
        export(CONTRACTS, args.dir)
        return 0
    problems = check(CONTRACTS, args.dir)
    for problem in problems:
        print(problem, file=sys.stderr)
    return 1 if problems else 0


if __name__ == "__main__":
    raise SystemExit(main())
