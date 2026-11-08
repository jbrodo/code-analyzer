"""Lettura CycloneDX per versione (K-02) e scrittura CycloneDX 1.7 (K-03), ADR-0007.

Lettura: la versione è quella dichiarata dal manifest (`outputs.cyclonedx_version`), che deve
essere ammessa; il documento deve dichiarare la stessa `specVersion` ed essere conforme allo
schema di quella versione. Ogni rifiuto è un `SbomError`.

Scrittura: l'SBOM del prodotto è sempre 1.7 (§1). Syft e trivy emettono già 1.7 (V-03): il
passo si riduce a validare e serializzare in modo deterministico, senza toccare i campi.
"""

import json
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from ca_core.formats import ADMITTED_CYCLONEDX_VERSIONS
from ca_core.sarif.reader import DEFAULT_MAX_BYTES, _depth_exceeds, _json_path, _reject_constant
from ca_core.sbom.errors import SbomError, SbomErrorCode
from ca_core.schema_validation import SchemaRefusedError, SchemaStore

OUTPUT_VERSION = "1.7"  # versione dell'SBOM prodotto da Code Analyzer
MAX_DEPTH = 64


@dataclass(frozen=True)
class ParsedSbom:
    document: Mapping[str, Any]
    version: str


def _validate(document: Any, store: SchemaStore, version: str) -> None:
    if version not in ADMITTED_CYCLONEDX_VERSIONS:
        raise SbomError(SbomErrorCode.VERSION, f"versione non ammessa: {version[:20]!r}")
    if _depth_exceeds(document, MAX_DEPTH):
        raise SbomError(SbomErrorCode.TOO_DEEP, f"profondità oltre {MAX_DEPTH}")
    if not isinstance(document, dict) or document.get("specVersion") != version:
        raise SbomError(SbomErrorCode.VERSION_MISMATCH, f"specVersion diversa da {version}")
    try:
        errors = store.validate_cyclonedx(document, version)
    except SchemaRefusedError as exc:  # difesa: l'elenco ammesso è già controllato sopra
        raise SbomError(SbomErrorCode.VERSION, "versione non ammessa") from exc
    if errors:
        raise SbomError(
            SbomErrorCode.SCHEMA,
            f"non conforme a CycloneDX {version}",
            tuple(_json_path(e) for e in errors),
        )


def parse_cyclonedx(
    data: bytes, store: SchemaStore, version: str, max_bytes: int = DEFAULT_MAX_BYTES
) -> ParsedSbom:
    """Valida `data` come CycloneDX `version` (dal manifest); `SbomError` se non utilizzabile."""
    if len(data) > max_bytes:
        raise SbomError(SbomErrorCode.TOO_LARGE, f"oltre {max_bytes} byte")
    try:
        document = json.loads(data, parse_constant=_reject_constant)
    except RecursionError as exc:
        raise SbomError(SbomErrorCode.TOO_DEEP, "documento troppo annidato") from exc
    except ValueError as exc:
        raise SbomError(SbomErrorCode.NOT_JSON, "non è JSON valido") from exc
    _validate(document, store, version)
    return ParsedSbom(document, version)


def serialize_cyclonedx(document: Mapping[str, Any], store: SchemaStore) -> bytes:
    """SBOM del prodotto: solo 1.7, validato prima di scrivere; serializzazione deterministica."""
    _validate(document, store, OUTPUT_VERSION)
    return json.dumps(document, sort_keys=True, separators=(",", ":")).encode()
