"""Lettura della configurazione di scoring (C-03, ADR-0021). Solo libreria standard e il modello.

Il file predefinito è `default.json` nel pacchetto. Un file di sovrascrittura è completo e si valida
per intero; chi lo legge decide da dove viene (mai dal repository analizzato, ADR-0014).
"""

import hashlib
import json
from importlib import resources

from pydantic import ValidationError

from ca_core.models.scoring_config import ScoringConfig

DEFAULT_FILE = "default.json"
MAX_BYTES = 256 * 1024


class ScoringConfigError(ValueError):
    """Il file non è una configurazione di scoring valida; il messaggio non cita il contenuto."""


def parse_config(raw: bytes) -> ScoringConfig:
    if len(raw) > MAX_BYTES:
        raise ScoringConfigError("configurazione di scoring troppo grande")
    try:
        return ScoringConfig.model_validate_json(raw)
    except ValidationError as exc:
        raise ScoringConfigError(
            f"configurazione di scoring non valida ({exc.error_count()} errori)"
        ) from exc


def default_bytes() -> bytes:
    return resources.files("ca_core.scoring").joinpath(DEFAULT_FILE).read_bytes()


def load_default() -> ScoringConfig:
    return parse_config(default_bytes())


def config_version(config: ScoringConfig) -> str:
    """`<version>+<12 caratteri dell'impronta>`: due scansioni sono confrontabili solo se uguali.

    L'impronta è sul contenuto normalizzato, non sui byte del file: spazi e ordine delle chiavi non
    cambiano la versione.
    """
    canonical = json.dumps(config.model_dump(mode="json"), sort_keys=True, separators=(",", ":"))
    digest = hashlib.sha256(canonical.encode()).hexdigest()
    return f"{config.version}+{digest[:12]}"
