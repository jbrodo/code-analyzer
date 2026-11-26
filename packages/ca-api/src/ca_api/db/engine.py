"""Connessione per richiesta e selezione dello schema del tenant (B-02, ADR-0018).

Una richiesta lavora in **un solo** schema: il nome non lo sceglie il chiamante ma il tenant
dell'identità autenticata (ADR-0019), e qui si valida contro lo schema di nome della tabella
`tenants` (`t_` più minuscole, cifre e trattino basso). Le tabelle del modello non hanno uno
schema esplicito: `schema_translate_map` le porta in quello del tenant, quindi nessuna query può
nominare un altro schema. Il driver è pg8000, puro Python (D2-07).
"""

import re
from collections.abc import Generator
from contextlib import contextmanager

from sqlalchemy import Engine, create_engine
from sqlalchemy.orm import Session

SCHEMA_NAME = re.compile(r"^t_[a-z0-9_]{1,40}$")


class DatabaseError(RuntimeError):
    """Configurazione o schema non validi; mai la stringa di connessione nel messaggio."""


def make_engine(url: str, *, pool_size: int = 5) -> Engine:
    """Engine per `postgresql+pg8000://`. Un altro driver o dialetto è un errore."""
    if not url.startswith("postgresql+pg8000://"):
        raise DatabaseError("URL del database: serve postgresql+pg8000://")
    return create_engine(url, pool_size=pool_size, pool_pre_ping=True)


def check_schema(schema: str) -> str:
    if not SCHEMA_NAME.fullmatch(schema):
        raise DatabaseError("nome dello schema del tenant non valido")
    return schema


@contextmanager
def tenant_session(engine: Engine, schema: str) -> Generator[Session]:
    """Sessione nello schema del tenant, con transazione: commit alla fine, rollback su errore."""
    translated = engine.execution_options(schema_translate_map={None: check_schema(schema)})
    with Session(translated) as session, session.begin():
        yield session
