"""Accesso ai dati del tenant dell'identità e cursori opachi (B-06, B-08, B-10, ADR-0018, ADR-0029).

Il tenant viene dall'identità autenticata (l'emittente o la mappa dei proprietari), mai da un
parametro della richiesta. Una risorsa di un altro tenant non esiste nello schema della richiesta:
`404`, non `403`, così l'esistenza non si rivela. I cursori sono opachi, legati alla stessa
combinazione di filtri e ordinamento (un cursore di un'altra richiesta è `invalid-cursor`) e non
portano dati riservati.
"""

import base64
import hashlib
import json
from collections.abc import Generator
from contextlib import contextmanager
from typing import Any

from fastapi import Request
from sqlalchemy import Engine, select
from sqlalchemy.orm import Session

from ca_api.auth.verify import Identity
from ca_api.db.engine import tenant_session
from ca_api.db.models import Tenant
from ca_api.problem import ApiProblem, ProblemCode


def not_found() -> ApiProblem:
    return ApiProblem(404, ProblemCode.NOT_FOUND)


def engine_of(request: Request) -> Engine:
    engine = request.app.state.engine
    if engine is None:
        raise ApiProblem(500, ProblemCode.INTERNAL_ERROR, detail="database non configurato")
    return engine  # type: ignore[no-any-return]


def schema_of(request: Request, identity: Identity) -> str:
    """Lo schema del tenant dell'identità. Un tenant non configurato è 403 per una pipeline e 404
    per un utente (nulla da mostrare)."""
    cache: dict[str, str] = request.app.state.__dict__.setdefault("tenant_schemas", {})
    if identity.tenant in cache:
        return cache[identity.tenant]
    with Session(engine_of(request)) as session:
        tenant = session.scalar(select(Tenant).where(Tenant.name == identity.tenant))
        schema = tenant.schema if tenant is not None else None
    if schema is None:
        raise ApiProblem(403, ProblemCode.FORBIDDEN, detail="tenant non configurato")
    cache[identity.tenant] = schema
    return schema


@contextmanager
def session_for(request: Request, identity: Identity) -> Generator[Session]:
    """Una sessione nello schema del tenant, con transazione."""
    with tenant_session(engine_of(request), schema_of(request, identity)) as session:
        yield session


def encode_cursor(state: dict[str, Any], binding: str) -> str:
    raw = json.dumps({"b": binding, "s": state}, separators=(",", ":"), default=str).encode()
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def decode_cursor(cursor: str, binding: str) -> dict[str, Any]:
    """Lo stato del cursore; `invalid-cursor` se non è uno di questa richiesta."""
    try:
        padded = cursor + "=" * (-len(cursor) % 4)
        document = json.loads(base64.urlsafe_b64decode(padded.encode()))
        if document["b"] != binding or not isinstance(document["s"], dict):
            raise ValueError
        state: dict[str, Any] = document["s"]
        return state
    except (ValueError, KeyError, TypeError):
        raise ApiProblem(422, ProblemCode.INVALID_CURSOR) from None


def binding_of(*parts: object) -> str:
    """Impronta dei parametri che il cursore deve conservare (filtri, ordinamento, ambito)."""
    raw = json.dumps(parts, sort_keys=True, default=str).encode()
    return hashlib.sha256(raw).hexdigest()[:16]
