"""Accesso ai dati del tenant (B-02, ADR-0018): funzioni sottili, senza regole di dominio.

Le regole dell'ingestione (stato corrente, `first_seen`, risoluzione, idempotenza completa) sono di
B-03. Ogni funzione lavora nella sessione di una richiesta, già nello schema del tenant
(`ca_api.db.engine.tenant_session`): nessuna nomina uno schema.
"""

import uuid
from datetime import datetime

from sqlalchemy import Engine, literal, select, tuple_
from sqlalchemy.orm import Session

from ca_api.db import migrate
from ca_api.db.models import Repository, Scan, Tenant


def create_tenant(engine: Engine, name: str) -> Tenant:
    """Registra il tenant e crea il suo schema con le tabelle. Idempotente sul nome."""
    with Session(engine) as session, session.begin():
        found = session.scalar(select(Tenant).where(Tenant.name == name))
        if found is None:
            tenant_id = uuid.uuid7()
            schema = f"t_{tenant_id.hex[:12]}"
            found = Tenant(id=tenant_id, name=name, schema=schema)
            session.add(found)
        session.flush()
        schema = found.schema
        session.expunge(found)
    migrate.upgrade_tenant(engine, schema)
    return found


def tenant_by_name(engine: Engine, name: str) -> Tenant | None:
    with Session(engine) as session:
        found = session.scalar(select(Tenant).where(Tenant.name == name))
        if found is not None:
            session.expunge(found)
        return found


def upsert_repository(
    session: Session,
    *,
    provider: str,
    issuer: str,
    external_id: str,
    name: str,
    default_branch: str | None = None,
) -> Repository:
    """Il repository dell'identità esterna `(provider, issuer, identificativo)`: si crea al primo
    caricamento, e il nome (che serve solo alla visualizzazione) si aggiorna a ogni caricamento."""
    found = session.scalar(
        select(Repository).where(
            Repository.provider == provider,
            Repository.issuer == issuer,
            Repository.external_id == external_id,
        )
    )
    if found is None:
        found = Repository(
            provider=provider,
            issuer=issuer,
            external_id=external_id,
            name=name,
            default_branch=default_branch,
        )
        session.add(found)
    else:
        found.name = name
        if default_branch is not None:
            found.default_branch = default_branch
    session.flush()
    return found


def get_repository(session: Session, repository_id: uuid.UUID) -> Repository | None:
    return session.get(Repository, repository_id)


def list_repositories(
    session: Session, *, limit: int, after: uuid.UUID | None = None
) -> list[Repository]:
    """Per `id` crescente (UUID versione 7: l'ordine è quello di creazione), dopo `after`."""
    query = select(Repository).order_by(Repository.id).limit(limit)
    if after is not None:
        query = query.where(Repository.id > after)
    return list(session.scalars(query))


def set_service_context(
    session: Session,
    repository_id: uuid.UUID,
    *,
    tier: int | None,
    internet_facing: bool | None,
    catalog_id: str | None,
    actor: str,
    now: datetime,
) -> Repository | None:
    """Registra tier ed esposizione (ADR-0028) con chi e quando; vale dalla scansione successiva."""
    found = session.get(Repository, repository_id)
    if found is None:
        return None
    found.tier, found.internet_facing, found.catalog_id = tier, internet_facing, catalog_id
    found.updated_by, found.updated_at = actor, now
    session.flush()
    return found


def scan_by_digest(session: Session, repository_id: uuid.UUID, sha256: str) -> Scan | None:
    return session.scalar(
        select(Scan).where(Scan.repository_id == repository_id, Scan.report_sha256 == sha256)
    )


def get_scan(session: Session, scan_id: uuid.UUID) -> Scan | None:
    return session.get(Scan, scan_id)


def list_scans(
    session: Session,
    repository_id: uuid.UUID,
    *,
    limit: int,
    before: tuple[datetime, uuid.UUID] | None = None,
) -> list[Scan]:
    """Dalla più recente per inizio, poi `id`; `before` è l'ultimo della pagina precedente."""
    query = (
        select(Scan)
        .where(Scan.repository_id == repository_id)
        .order_by(Scan.started_at.desc(), Scan.id.desc())
        .limit(limit)
    )
    if before is not None:
        started, last = before
        query = query.where(
            tuple_(Scan.started_at, Scan.id) < tuple_(literal(started), literal(last))
        )
    return list(session.scalars(query))
