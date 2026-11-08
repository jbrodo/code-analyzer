"""Errori tipizzati della lettura e scrittura CycloneDX (K-02, K-03).

Come per SARIF, i messaggi riportano percorsi nel documento e limiti, mai valori letti.
"""

from enum import StrEnum


class SbomErrorCode(StrEnum):
    TOO_LARGE = "too-large"
    NOT_JSON = "not-json"
    TOO_DEEP = "too-deep"
    VERSION = "version"  # versione dichiarata non ammessa
    VERSION_MISMATCH = "version-mismatch"  # `specVersion` del documento diverso dal manifest
    SCHEMA = "schema"  # non conforme allo schema della versione


class SbomError(Exception):
    """L'SBOM di un plugin non è utilizzabile: il plugin va marcato come fallito (ADR-0007)."""

    def __init__(self, code: SbomErrorCode, message: str, details: tuple[str, ...] = ()) -> None:
        super().__init__(f"{code.value}: {message}")
        self.code = code
        self.message = message
        self.details = details  # percorsi JSON Pointer, senza valori
