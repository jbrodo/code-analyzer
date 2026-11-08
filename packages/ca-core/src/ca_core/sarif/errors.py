"""Errori tipizzati della lettura SARIF (K-01).

Il SARIF è input ostile e può contenere un segreto (ADR-0012): i messaggi e i dettagli
dell'errore riportano percorsi nel documento e limiti, mai valori letti dal documento.
"""

from enum import StrEnum


class SarifErrorCode(StrEnum):
    UNREADABLE = "unreadable"  # non è un file regolare leggibile
    TOO_LARGE = "too-large"
    NOT_JSON = "not-json"
    TOO_DEEP = "too-deep"
    TOO_MANY_RUNS = "too-many-runs"
    TOO_MANY_RESULTS = "too-many-results"
    SCHEMA = "schema"  # non conforme a SARIF 2.1.0
    PROPERTIES = "properties"  # `properties` di un result non conformi a C-05
    CHECK = "check"  # rifiutato da un controllo aggiuntivo (K-10)
    URI = "uri"  # `uri` assoluto, fuori dalla radice o non valido (K-05, ADR-0008)
    SOURCE = "source"  # file del workspace non leggibile o fuori confine (K-05)
    MAPPING = "mapping"  # il result non è normalizzabile in un `Finding` (K-05)


class SarifError(Exception):
    """Il SARIF di un plugin non è utilizzabile: il plugin va marcato come fallito (ADR-0007)."""

    def __init__(self, code: SarifErrorCode, message: str, details: tuple[str, ...] = ()) -> None:
        super().__init__(f"{code.value}: {message}")
        self.code = code
        self.message = message
        self.details = details  # percorsi JSON Pointer, senza valori
