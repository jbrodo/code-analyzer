"""Proprietà comuni ai cinque schemi: identità, versione, chiusura."""

import pytest
from conftest import SCHEMA_NAMES, load_schema
from jsonschema import Draft202012Validator

CLOSED_ROOTS = tuple(SCHEMA_NAMES)


@pytest.mark.parametrize("name", SCHEMA_NAMES)
def test_schema_is_valid_draft_2020_12(name: str) -> None:
    schema = load_schema(name)
    assert schema["$schema"] == "https://json-schema.org/draft/2020-12/schema"
    Draft202012Validator.check_schema(schema)


@pytest.mark.parametrize("name", SCHEMA_NAMES)
def test_schema_has_stable_id_and_version(name: str) -> None:
    schema = load_schema(name)
    assert schema["$id"] == f"urn:code-analyzer:schema:{name}:v1"
    assert schema["x-schema-version"] == "1.0"


def test_schema_ids_are_unique() -> None:
    ids = [load_schema(name)["$id"] for name in SCHEMA_NAMES]
    assert len(set(ids)) == len(ids)


@pytest.mark.parametrize("name", CLOSED_ROOTS)
def test_closed_root_rejects_unknown_property(name: str) -> None:
    assert load_schema(name)["additionalProperties"] is False


# Nessuna eccezione: anche le proprietà SARIF dei plugin sono chiuse (ADR-0007).
OPEN_BY_DESIGN: dict[str, set[str]] = {}


@pytest.mark.parametrize("name", SCHEMA_NAMES)
def test_every_object_def_is_closed_except_declared_open_ones(name: str) -> None:
    """Ogni oggetto con `properties` è chiuso, salvo le eccezioni elencate in `OPEN_BY_DESIGN`."""
    schema = load_schema(name)
    open_by_design = OPEN_BY_DESIGN.get(name, set())
    nodes = {"<root>": schema, **schema.get("$defs", {})}
    for key, node in nodes.items():
        if node.get("type") == "object" and "properties" in node and key not in open_by_design:
            assert node.get("additionalProperties") is False, f"{name}:{key} è aperto"
