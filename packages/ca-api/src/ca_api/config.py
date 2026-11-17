"""Configurazione del server da ambiente (ADR-0016, ADR-0030).

Nessun valore predefinito per un segreto. Ogni variabile ha il prefisso `CA_API_`; un valore non
valido è un errore all'avvio, non un ripiego silenzioso. Qui stanno solo le chiavi che B-01 usa:
database, archivio, emittenti e conservazione si aggiungono con B-02, B-04, B-07.
"""

import os
from collections.abc import Mapping
from dataclasses import dataclass

PREFIX = "CA_API_"
MIB = 1024 * 1024


class ConfigError(ValueError):
    """Variabile d'ambiente non valida. Il messaggio nomina la variabile, mai il suo valore."""


def _int(env: Mapping[str, str], name: str, default: int, *, minimum: int) -> int:
    raw = env.get(PREFIX + name)
    if raw is None:
        return default
    try:
        value = int(raw)
    except ValueError:
        raise ConfigError(f"{PREFIX}{name}: intero atteso") from None
    if value < minimum:
        raise ConfigError(f"{PREFIX}{name}: almeno {minimum}")
    return value


@dataclass(frozen=True)
class Settings:
    """Limiti di dimensione di `POST /v1/scans` (ADR-0016): in configurazione, non nel codice."""

    max_part_bytes: int = 64 * MIB
    max_request_bytes: int = 160 * MIB
    auth_file: str | None = None  # emittenti di ADR-0019; senza, ogni richiesta autenticata è 401
    database_url: str | None = (
        None  # postgresql+pg8000://: può contenere la password, solo da ambiente
    )
    artifacts_dir: str | None = None  # archivio su file system (sviluppo, test, pilota)
    s3_bucket: str | None = None  # archivio S3: con `s3_bucket` si usa S3 e non il file system
    s3_endpoint: str | None = None
    s3_region: str = "us-east-1"
    s3_prefix: str = ""
    default_branches: tuple[str, ...] = ("main", "master")  # branch che contano come principali
    exception_max_days: int = 365  # durata massima di un'eccezione (ADR-0029)

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> "Settings":
        source = os.environ if env is None else env
        part = _int(source, "MAX_PART_BYTES", cls.max_part_bytes, minimum=1)
        request = _int(source, "MAX_REQUEST_BYTES", cls.max_request_bytes, minimum=1)
        if request < part:
            raise ConfigError(f"{PREFIX}MAX_REQUEST_BYTES: non inferiore a MAX_PART_BYTES")
        branches = tuple(
            b.strip()
            for b in source.get(PREFIX + "DEFAULT_BRANCHES", "main,master").split(",")
            if b.strip()
        )
        return cls(
            max_part_bytes=part,
            max_request_bytes=request,
            auth_file=source.get(PREFIX + "AUTH_FILE") or None,
            database_url=source.get(PREFIX + "DATABASE_URL") or None,
            artifacts_dir=source.get(PREFIX + "ARTIFACTS_DIR") or None,
            s3_bucket=source.get(PREFIX + "S3_BUCKET") or None,
            s3_endpoint=source.get(PREFIX + "S3_ENDPOINT") or None,
            s3_region=source.get(PREFIX + "S3_REGION") or "us-east-1",
            s3_prefix=source.get(PREFIX + "S3_PREFIX") or "",
            default_branches=branches or ("main", "master"),
            exception_max_days=_int(
                source, "EXCEPTION_MAX_DAYS", cls.exception_max_days, minimum=1
            ),
        )
