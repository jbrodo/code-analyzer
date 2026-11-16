"""Proprietà comuni agli schemi: identità, versione, chiusura."""

import pytest
from conftest import SCHEMA_NAMES, load_schema
from jsonschema import Draft202012Validator

CLOSED_ROOTS = tuple(SCHEMA_NAMES)
# Dentro la versione maggiore 1 solo aggiunte compatibili (ADR-0003). Chi cambia uno schema
# aggiorna qui la sua versione minore.
VERSIONS = {
    "finding": "1.0",
    "code-analyzer-config": "1.1",  # C-05 della Fase 2: opzioni dei plugin nuovi
    "plugin-manifest": "1.1",  # C-02 della Fase 2: uscita `graph`
    "plugin-sarif-properties": "1.0",
    "scan-report": "1.0",
    "graph": "1.0",
}


@pytest.mark.parametrize("name", SCHEMA_NAMES)
def test_schema_is_valid_draft_2020_12(name: str) -> None:
    schema = load_schema(name)
    assert schema["$schema"] == "https://json-schema.org/draft/2020-12/schema"
    Draft202012Validator.check_schema(schema)


@pytest.mark.parametrize("name", SCHEMA_NAMES)
def test_schema_has_stable_id_and_version(name: str) -> None:
    schema = load_schema(name)
    assert schema["$id"] == f"urn:code-analyzer:schema:{name}:v1"
    assert schema["x-schema-version"] == VERSIONS[name]


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
