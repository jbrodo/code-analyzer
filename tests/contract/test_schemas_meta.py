"""Proprietà comuni agli schemi: identità, versione, chiusura."""

import pytest
from conftest import SCHEMA_NAMES, load_schema
from jsonschema import Draft202012Validator

CLOSED_ROOTS = tuple(SCHEMA_NAMES)
# Dentro la versione maggiore 1 solo aggiunte compatibili (ADR-0003). Chi cambia uno schema
# aggiorna qui la sua versione minore.
VERSIONS = {
    "finding": "1.2",  # K-21 `correlation`; C-01 baseline, correzione, punteggi in ombra
    "code-analyzer-config": "1.1",  # C-05 della Fase 2: opzioni dei plugin nuovi
    "plugin-manifest": "1.1",  # C-02 della Fase 2: uscita `graph`
    "plugin-sarif-properties": "1.2",  # P-01 della Fase 2: `metric`; K-03: `taint`
    "scan-report": "1.3",  # K-21 `correlation_version`; C-04 baseline, tipo, configurazione
    "graph": "1.1",  # G-02: files_skipped_name
    "scoring-config": "1.0",  # C-03
    "scoring-benchmark": "1.0",  # K-06: distribuzione di benchmark di ADR-0023
    "service-context": "1.0",  # K-05: file di contesto di ADR-0028
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
