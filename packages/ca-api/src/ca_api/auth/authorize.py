"""Autorizzazione: matrice dei ruoli e identità di pipeline (B-05, ADR-0019). Decide il server.

Quattro ruoli: `lettore`, `triage` (include lettore), `approvatore` (include triage),
`amministratore` (include lettore, non approvatore). Un utente autenticato senza ruoli riceve 403
ovunque tranne `GET /v1/me`. Una pipeline (`P`) non ha ruoli: raggiunge solo `POST /v1/scans`,
`GET /v1/service-context` e, per il proprio repository, la lettura di una scansione e del suo SARIF.
Il 403 per ruolo porta il ruolo richiesto nel corpo, che la UI mostra. Una risorsa di un altro
tenant è 404, non 403 (ADR-0019): lo decide il livello dei dati, che qui non esiste ancora.
"""

from collections.abc import Callable
from typing import Annotated

from fastapi import Depends

from ca_api.auth.deps import CurrentIdentity
from ca_api.auth.verify import Identity
from ca_api.models import (
    CreateException,
    RevokeException,
    Role,
    SetOwner,
    SetStatus,
)
from ca_api.problem import ApiProblem, ProblemCode

_INCLUDES: dict[Role, frozenset[Role]] = {
    Role.READER: frozenset(Role),
    Role.TRIAGE: frozenset({Role.TRIAGE, Role.APPROVER}),
    Role.APPROVER: frozenset({Role.APPROVER}),
    Role.ADMIN: frozenset({Role.ADMIN}),
}


def has_role(identity: Identity, required: Role) -> bool:
    return bool(identity.roles & _INCLUDES[required])


def forbidden(required: str) -> ApiProblem:
    return ApiProblem(403, ProblemCode.FORBIDDEN, required_role=required)


def require_user(required: Role) -> Callable[[Identity], Identity]:
    """Un utente con il ruolo richiesto (o uno che lo include). Le pipeline non passano."""

    def check(identity: CurrentIdentity) -> Identity:
        if identity.kind != "user" or not has_role(identity, required):
            raise forbidden(required.value)
        return identity

    return check


def any_user(identity: CurrentIdentity) -> Identity:
    """Qualunque utente autenticato, anche senza ruoli (`GET /v1/me`)."""
    if identity.kind != "user":
        raise forbidden("utente")
    return identity


def pipeline_only(identity: CurrentIdentity) -> Identity:
    """Solo l'identità di una pipeline: `POST /v1/scans` e `GET /v1/service-context`."""
    if identity.kind != "pipeline" or identity.repository is None:
        raise forbidden("pipeline")
    return identity


def reader_or_pipeline(identity: CurrentIdentity) -> Identity:
    """Lettura di una scansione: un lettore, o la pipeline (che il livello dei dati limita al
    proprio repository)."""
    if identity.kind == "pipeline" and identity.repository is not None:
        return identity
    if identity.kind == "user" and has_role(identity, Role.READER):
        return identity
    raise forbidden(Role.READER.value)


def authorize_patch(
    identity: Identity, body: SetStatus | SetOwner | CreateException | RevokeException
) -> None:
    """Ruolo richiesto da una modifica di triage (ADR-0019, matrice).

    Stato `aperto` o `in_corso` e owner: `triage`. Falso positivo, eccezione creata o revocata:
    `approvatore`. `approved_by` non è nel corpo: è l'identità autenticata.
    """
    needs_approver = isinstance(body, CreateException | RevokeException) or (
        isinstance(body, SetStatus) and body.status == "falso_positivo"
    )
    required = Role.APPROVER if needs_approver else Role.TRIAGE
    if identity.kind != "user" or not has_role(identity, required):
        raise forbidden(required.value)


Reader = Annotated[Identity, Depends(require_user(Role.READER))]
Admin = Annotated[Identity, Depends(require_user(Role.ADMIN))]
Triage = Annotated[Identity, Depends(require_user(Role.TRIAGE))]
User = Annotated[Identity, Depends(any_user)]
Pipeline = Annotated[Identity, Depends(pipeline_only)]
ReaderOrPipeline = Annotated[Identity, Depends(reader_or_pipeline)]
