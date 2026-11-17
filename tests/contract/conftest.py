"""Infrastruttura dei test di contratto (C-07).

Gli schemi si leggono solo da `schemas/`, con `jsonschema` e senza importare `ca_core`: il test
deve fallire se un consumatore esterno vedrebbe un contratto diverso da quello dei modelli.
"""

import copy
import json
import socket
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft202012Validator, FormatChecker
from referencing import Registry, Resource

SCHEMAS_DIR = Path(__file__).resolve().parents[2] / "schemas"
SCHEMA_NAMES = (
    "finding",
    "code-analyzer-config",
    "plugin-manifest",
    "plugin-sarif-properties",
    "scan-report",
    "graph",
    "scoring-config",
)

Json = dict[str, Any]
Mutation = Callable[[Json], None]


def load_schema(name: str) -> Json:
    return json.loads((SCHEMAS_DIR / f"{name}.schema.json").read_text(encoding="utf-8"))


def make_validator(name: str, definition: str | None = None) -> Draft202012Validator:
    """Validatore sul file in `schemas/`; `definition` punta a `$defs/<nome>` dello stesso file."""
    schema = load_schema(name)
    registry: Registry[Any] = Registry().with_resource(
        schema["$id"], Resource.from_contents(schema)
    )
    target = schema if definition is None else {"$ref": f"{schema['$id']}#/$defs/{definition}"}
    return Draft202012Validator(target, registry=registry, format_checker=FormatChecker())


def mutated(base: Json, *mutations: Mutation) -> Json:
    """Copia profonda di `base` con le mutazioni applicate: le istanze base restano intatte."""
    instance = copy.deepcopy(base)
    for mutation in mutations:
        mutation(instance)
    return instance


def errors_of(validator: Draft202012Validator, instance: Any) -> list[str]:
    return [
        f"/{'/'.join(str(p) for p in e.absolute_path)}: {e.message}"
        for e in validator.iter_errors(instance)
    ]


@pytest.fixture(autouse=True)
def no_network(monkeypatch: pytest.MonkeyPatch) -> None:
    """Un `$ref` remoto non risolto non deve mai uscire in rete."""

    def refuse(*args: Any, **kwargs: Any) -> None:
        raise AssertionError("accesso alla rete in un test di contratto")

    monkeypatch.setattr(socket, "socket", refuse)
    monkeypatch.setattr(socket, "getaddrinfo", refuse)


def case_params(cases: dict[str, Any], prefix: str = "") -> list[Any]:
    """Casi con nome come parametri pytest (per i test di equivalenza modello/schema)."""
    return [pytest.param(v, id=f"{prefix}{k}") for k, v in cases.items()]
