"""Validazione SARIF / CycloneDX contro gli schemi fissati in `schemas/vendor/` (ADR-0003).

Senza rete: ogni `$ref` deve risolvere in un documento già caricato dalla directory fissata.
Gli schemi sono dati non fidati quanto le istanze: un riferimento esterno o fuori dal
catalogo viene rifiutato prima di validare.
"""

import hashlib
import itertools
import json
from collections.abc import Iterator, Mapping
from importlib import resources
from pathlib import Path
from typing import Any

from jsonschema.exceptions import ValidationError
from jsonschema.protocols import Validator
from jsonschema.validators import validator_for
from referencing import Registry, Resource
from referencing.exceptions import Unresolvable
from referencing.jsonschema import DRAFT4, DRAFT7

from ca_core.formats import ADMITTED_CYCLONEDX_VERSIONS, EXPORT_CYCLONEDX_VERSIONS

MANIFEST_NAME = "SOURCES.json"
MAX_ERRORS = 20  # l'istanza è non fidata: niente elenchi di errori illimitati
_REF_KEYS = ("$ref", "$dynamicRef", "$recursiveRef")
_SARIF_FILE = "sarif-schema-2.1.0.json"
PACKAGED_DIR = "vendor_schemas"
# Ancora nel codice: SOURCES.json è nella stessa cartella e prova solo la coerenza interna.
# Aggiornare uno schema fissato tocca file, SOURCES.json e questa costante (ADR-0003).
VENDOR_MANIFEST_SHA256 = "82ad8f2e84978094bba46e18204cc08a17357f02303e85ed004d8968e95596db"


class SchemaRefusedError(ValueError):
    """Schema non fissato, alterato o con `$ref` non ammesso."""


def _doc_id(schema: Mapping[str, Any]) -> str:
    value = schema.get("$id", schema.get("id"))  # `id` in draft-04
    return value if isinstance(value, str) else ""


def _walk_refs(node: Any) -> Iterator[str]:
    if isinstance(node, dict):
        for key, value in node.items():
            if key in _REF_KEYS and isinstance(value, str):
                yield value
            else:
                yield from _walk_refs(value)
    elif isinstance(node, list):
        for item in node:
            yield from _walk_refs(item)


def check_refs(schema: Mapping[str, Any], registry: Registry) -> None:
    """Rifiuta ogni `$ref` che non sia un frammento locale o un documento del catalogo."""
    base = _doc_id(schema)
    if base:
        registry = registry.with_resource(base, Resource.from_contents(dict(schema), DRAFT7))
    resolver = registry.resolver(base)
    for ref in _walk_refs(schema):
        if ref.startswith("#"):
            continue
        try:
            resolver.lookup(ref)
        except Unresolvable as exc:
            raise SchemaRefusedError(f"$ref non ammesso: {ref!r}") from exc


def _refuse_retrieval(uri: str) -> Resource:
    raise SchemaRefusedError(f"risoluzione esterna rifiutata: {uri!r}")


class SchemaStore:
    """Catalogo degli schemi fissati; verifica l'integrità dei file all'apertura."""

    def __init__(self, vendor_dir: Path) -> None:
        manifest = json.loads((vendor_dir / MANIFEST_NAME).read_text(encoding="utf-8"))
        expected = {entry["file"]: entry["sha256"] for entry in manifest["files"]}
        present = {p.name for p in vendor_dir.glob("*.json")} - {MANIFEST_NAME}
        if present != expected.keys():
            raise SchemaRefusedError(
                f"file non elencati in {MANIFEST_NAME}: {sorted(present ^ expected.keys())}"
            )
        documents: dict[str, dict[str, Any]] = {}
        for name, digest in expected.items():
            raw = (vendor_dir / name).read_bytes()
            if hashlib.sha256(raw).hexdigest() != digest:
                raise SchemaRefusedError(f"{name}: SHA-256 diverso da {MANIFEST_NAME}")
            schema = json.loads(raw)
            if not _doc_id(schema):
                raise SchemaRefusedError(f"{name}: senza $id")
            documents[_doc_id(schema)] = schema
        self._registry: Registry = Registry(retrieve=_refuse_retrieval)  # type: ignore[call-arg]
        for uri, schema in documents.items():
            spec = DRAFT4 if "draft-04" in str(schema.get("$schema")) else DRAFT7
            self._registry = self._registry.with_resource(uri, spec.create_resource(schema))
        for schema in documents.values():
            check_refs(schema, self._registry)
        self._documents = documents
        self._ids = {
            name: _doc_id(documents[_doc_id(json.loads((vendor_dir / name).read_bytes()))])
            for name in expected
        }
        self._validators: dict[str, Validator] = {}
        self._sarif_id = _doc_id(json.loads((vendor_dir / _SARIF_FILE).read_bytes()))

    @classmethod
    def packaged(cls) -> SchemaStore:
        """Schemi fissati del pacchetto installato; `SchemaRefusedError` se il manifest diverge."""
        with resources.as_file(resources.files("ca_core").joinpath(PACKAGED_DIR)) as vendor_dir:
            try:
                raw = (vendor_dir / MANIFEST_NAME).read_bytes()
            except OSError as exc:
                raise SchemaRefusedError("schemi fissati assenti dal pacchetto") from exc
            if hashlib.sha256(raw).hexdigest() != VENDOR_MANIFEST_SHA256:
                raise SchemaRefusedError(f"{MANIFEST_NAME}: SHA-256 diverso da quello ancorato")
            return cls(vendor_dir)  # carica tutto in memoria: il contesto può chiudersi

    def _validator(self, uri: str) -> Validator:
        if uri not in self._validators:
            schema = self._documents[uri]
            self._validators[uri] = validator_for(schema)(schema, registry=self._registry)
        return self._validators[uri]

    @staticmethod
    def _errors(validator: Validator, instance: Any) -> list[str]:
        try:
            errors: list[ValidationError] = sorted(
                itertools.islice(validator.iter_errors(instance), MAX_ERRORS),
                key=lambda e: [str(p) for p in e.absolute_path],
            )
        except RecursionError:
            return ["documento troppo annidato"]
        return [f"/{'/'.join(str(p) for p in e.absolute_path)}: {e.message[:200]}" for e in errors]

    def validate_sarif(self, instance: Any) -> list[str]:
        """Errori di validazione contro SARIF 2.1.0; lista vuota se valido."""
        return self._errors(self._validator(self._sarif_id), instance)

    def validate_cyclonedx(self, instance: Any, version: str) -> list[str]:
        """Errori di validazione contro CycloneDX `version`, che deve essere ammessa."""
        if version not in ADMITTED_CYCLONEDX_VERSIONS:
            raise SchemaRefusedError(f"versione CycloneDX non ammessa: {version!r}")
        uri = f"http://cyclonedx.org/schema/bom-{version}.schema.json"
        return self._errors(self._validator(uri), instance)

    def validate_pinned(self, file: str, instance: Any) -> list[str]:
        """Errori contro uno schema fissato, per nome di file (es. quelli dei report di GitLab)."""
        if file not in self._ids:
            raise SchemaRefusedError(f"schema non fissato: {file!r}")
        return self._errors(self._validator(self._ids[file]), instance)

    def validate_cyclonedx_export(self, instance: Any, version: str) -> list[str]:
        """Come `validate_cyclonedx`, per le versioni che i nostri export possono scrivere."""
        if version not in EXPORT_CYCLONEDX_VERSIONS:
            raise SchemaRefusedError(f"versione CycloneDX non ammessa in uscita: {version!r}")
        uri = f"http://cyclonedx.org/schema/bom-{version}.schema.json"
        return self._errors(self._validator(uri), instance)

    def validate_with(self, schema: Mapping[str, Any], instance: Any) -> list[str]:
        """Valida contro uno schema fornito (es. uno di `schemas/`), con gli stessi limiti."""
        check_refs(schema, self._registry)
        validator = validator_for(schema)(dict(schema), registry=self._registry)
        return self._errors(validator, instance)
