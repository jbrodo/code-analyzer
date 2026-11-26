"""Modello relazionale della Fase 2 (C-07, ADR-0018). Solo dati, nessuna logica.

Due basi: `GlobalBase` ha la sola tabella `tenants`, nello schema predefinito; `TenantBase` ha le
tabelle di un tenant, **senza schema esplicito**: la connessione di una richiesta le porta nello
schema del tenant con `schema_translate_map` (`ca_api.db.engine`). Così lo stesso modello serve a
ogni tenant e una richiesta non può nominare un altro schema.

`Finding` e `ScanReport` di `ca_core` restano la fonte dei contratti (ADR-0003): le colonne `data`
(JSONB) conservano il finding come lo ha dichiarato la CLI; tra questo modello e quello Pydantic c'è
una conversione esplicita. Nessuna tabella di Fase 3: né `vex_statements`, né `decisions`,
`agent_runs`, `golden_labels`, `embeddings`.
"""

import uuid
from datetime import date, datetime
from typing import Any

from sqlalchemy import (
    BigInteger,
    Boolean,
    CheckConstraint,
    Date,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    MetaData,
    SmallInteger,
    String,
    Text,
    UniqueConstraint,
    Uuid,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

NAMING = {
    "ix": "ix_%(table_name)s_%(column_0_N_name)s",
    "uq": "uq_%(table_name)s_%(column_0_N_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s",
}


class GlobalBase(DeclarativeBase):
    metadata = MetaData(naming_convention=NAMING)


class TenantBase(DeclarativeBase):
    metadata = MetaData(naming_convention=NAMING)


def _uuid() -> Mapped[uuid.UUID]:
    return mapped_column(Uuid, primary_key=True, default=uuid.uuid7)


def _now() -> Mapped[datetime]:
    return mapped_column(DateTime(timezone=True), server_default=func.now())


def _in(column: str, values: tuple[str, ...], name: str) -> CheckConstraint:
    listed = ", ".join(f"'{v}'" for v in values)
    return CheckConstraint(f"{column} IN ({listed})", name=name)


FINDING_STATES = ("aperto", "in_corso", "accettato", "falso_positivo", "risolto")
SCAN_KINDS = ("pr", "full")
SCAN_STATUSES = ("complete", "partial")
BASELINE_STATES = ("new", "existing")
CONFIDENCES = ("dichiarato", "dedotto", "osservato")
EXCEPTION_ORIGINS = ("server", "repository")
PROVIDERS = ("github", "gitlab")


class Tenant(GlobalBase):
    """Un tenant: il suo schema contiene le tabelle sotto (ADR-0018)."""

    __tablename__ = "tenants"
    __table_args__ = (
        CheckConstraint(r"schema ~ '^t_[a-z0-9_]{1,40}$'", name="schema_name"),
        UniqueConstraint("name"),
        UniqueConstraint("schema"),
    )

    id: Mapped[uuid.UUID] = _uuid()
    name: Mapped[str] = mapped_column(String(100))
    schema: Mapped[str] = mapped_column(String(43))
    created_at: Mapped[datetime] = _now()


class Repository(TenantBase):
    __tablename__ = "repositories"
    __table_args__ = (
        UniqueConstraint("provider", "issuer", "external_id"),
        CheckConstraint("tier BETWEEN 1 AND 3", name="tier"),
        _in("provider", PROVIDERS, "provider"),
    )

    id: Mapped[uuid.UUID] = _uuid()
    provider: Mapped[str] = mapped_column(String(16))
    issuer: Mapped[str] = mapped_column(String(500))
    external_id: Mapped[str] = mapped_column(String(200))  # identificativo numerico del provider
    name: Mapped[str] = mapped_column(String(500))
    default_branch: Mapped[str | None] = mapped_column(String(200))
    tier: Mapped[int | None] = mapped_column(SmallInteger)
    internet_facing: Mapped[bool | None] = mapped_column(Boolean)
    catalog_id: Mapped[str | None] = mapped_column(String(200))
    current_scan_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid
    )  # vedi `scans`: niente ciclo di FK
    updated_by: Mapped[str | None] = mapped_column(String(300))  # ADR-0028: chi e quando
    updated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = _now()


class Scan(TenantBase):
    __tablename__ = "scans"
    __table_args__ = (
        UniqueConstraint("repository_id", "report_sha256"),  # idempotenza (ADR-0016)
        Index("ix_scans_repository_id_started_at", "repository_id", "started_at"),
        _in("kind", SCAN_KINDS, "kind"),
        _in("status", SCAN_STATUSES, "status"),
        CheckConstraint("report_sha256 ~ '^[0-9a-f]{64}$'", name="digest"),
        CheckConstraint("(kind = 'pr') = (base_commit IS NOT NULL)", name="pr_has_base"),
    )

    id: Mapped[uuid.UUID] = _uuid()
    repository_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("repositories.id"))
    commit: Mapped[str] = mapped_column(String(64))
    ref: Mapped[str | None] = mapped_column(String(500))
    kind: Mapped[str] = mapped_column(String(8))
    pull_request: Mapped[int | None] = mapped_column(Integer)
    base_commit: Mapped[str | None] = mapped_column(String(64))
    status: Mapped[str] = mapped_column(String(16))
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    duration_seconds: Mapped[float] = mapped_column(Float)
    report_sha256: Mapped[str] = mapped_column(String(64))
    report_schema_version: Mapped[str] = mapped_column(String(16))
    scoring_config_version: Mapped[str | None] = mapped_column(String(64))
    uploaded_by: Mapped[str] = mapped_column(String(300))
    artifact_keys: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict)
    received_at: Mapped[datetime] = _now()


class Finding(TenantBase):
    """Un finding per `(repository_id, fingerprint)`; `id` opaco, UUID nelle risposte dell'API."""

    __tablename__ = "findings"
    __table_args__ = (
        UniqueConstraint("repository_id", "fingerprint"),
        Index("ix_findings_repository_id_status", "repository_id", "status"),
        _in("status", FINDING_STATES, "status"),
        CheckConstraint("fingerprint ~ '^sha256:[0-9a-f]{64}$'", name="fingerprint"),
    )

    id: Mapped[uuid.UUID] = _uuid()
    repository_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("repositories.id"))
    fingerprint: Mapped[str] = mapped_column(String(71))
    category: Mapped[str] = mapped_column(String(32))
    rule_id: Mapped[str] = mapped_column(String(200))
    title: Mapped[str] = mapped_column(Text)
    data: Mapped[dict[str, Any]] = mapped_column(JSONB)  # il finding dell'ultima occorrenza
    first_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    status: Mapped[str] = mapped_column(String(16), default="aperto")
    owner: Mapped[str | None] = mapped_column(String(200))
    due_date: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = _now()


class FindingOccurrence(TenantBase):
    __tablename__ = "finding_occurrences"
    __table_args__ = (
        UniqueConstraint("finding_id", "scan_id"),
        Index("ix_finding_occurrences_scan_id", "scan_id"),
        CheckConstraint(f"baseline_state IN {BASELINE_STATES}", name="baseline_state"),
    )

    id: Mapped[uuid.UUID] = _uuid()
    finding_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("findings.id"))
    scan_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("scans.id"))
    commit: Mapped[str] = mapped_column(String(64))
    path: Mapped[str | None] = mapped_column(String(4096))
    start_line: Mapped[int | None] = mapped_column(Integer)
    level: Mapped[str | None] = mapped_column(String(16))
    level_source: Mapped[str | None] = mapped_column(String(24))
    evidence: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict)
    report_status: Mapped[str | None] = mapped_column(String(16))  # stato dichiarato dal report
    baseline_state: Mapped[str | None] = mapped_column(String(16))
    a_score: Mapped[float | None] = mapped_column(Float)  # punteggi in ombra (D2-10)
    a_level: Mapped[str | None] = mapped_column(String(16))
    a_factors: Mapped[dict[str, Any] | None] = mapped_column(JSONB)
    b_score: Mapped[float | None] = mapped_column(Float)
    b_level: Mapped[str | None] = mapped_column(String(16))
    b_factors: Mapped[dict[str, Any] | None] = mapped_column(JSONB)


class Component(TenantBase):
    """Pacchetti dell'SBOM della scansione corrente del repository."""

    __tablename__ = "components"
    __table_args__ = (Index("ix_components_scan_id", "scan_id"),)

    id: Mapped[uuid.UUID] = _uuid()
    repository_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("repositories.id"))
    scan_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("scans.id"))
    purl: Mapped[str] = mapped_column(String(2048))
    name: Mapped[str] = mapped_column(String(500))
    version: Mapped[str | None] = mapped_column(String(200))
    licenses: Mapped[list[Any]] = mapped_column(JSONB, default=list)


class GraphNode(TenantBase):
    __tablename__ = "graph_nodes"
    __table_args__ = (UniqueConstraint("scan_id", "path"),)

    id: Mapped[uuid.UUID] = _uuid()
    scan_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("scans.id"))
    path: Mapped[str] = mapped_column(String(4096))
    language: Mapped[str] = mapped_column(String(16))
    parse: Mapped[str] = mapped_column(String(16))
    test: Mapped[bool] = mapped_column(Boolean, default=False)
    churn: Mapped[int | None] = mapped_column(BigInteger)
    metrics: Mapped[dict[str, Any] | None] = mapped_column(JSONB)


class GraphEdge(TenantBase):
    __tablename__ = "graph_edges"
    __table_args__ = (
        UniqueConstraint("scan_id", "source", "external", "target"),
        _in("confidence", CONFIDENCES, "confidence"),
    )

    id: Mapped[uuid.UUID] = _uuid()
    scan_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("scans.id"))
    source: Mapped[str] = mapped_column(String(4096))
    target: Mapped[str] = mapped_column(String(4096))
    external: Mapped[bool] = mapped_column(Boolean, default=False)
    imports: Mapped[int] = mapped_column(Integer)
    dynamic: Mapped[bool] = mapped_column(Boolean, default=False)
    type_only: Mapped[bool] = mapped_column(Boolean, default=False)
    confidence: Mapped[str] = mapped_column(String(16))


class ExceptionRow(TenantBase):
    """Eccezione con la sua origine: `repository` è una dichiarazione, mai verificata (ADR-0018)."""

    __tablename__ = "exceptions"
    __table_args__ = (
        Index("ix_exceptions_finding_id", "finding_id"),
        _in("origin", EXCEPTION_ORIGINS, "origin"),
        CheckConstraint("origin = 'server' OR NOT approved_by_verified", name="repo_not_verified"),
    )

    id: Mapped[uuid.UUID] = _uuid()
    finding_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("findings.id"))
    origin: Mapped[str] = mapped_column(String(16))
    reason: Mapped[str] = mapped_column(Text)
    expires: Mapped[date] = mapped_column(Date)
    approved_by: Mapped[str] = mapped_column(String(300))
    approved_by_verified: Mapped[bool] = mapped_column(Boolean, default=False)
    scan_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("scans.id"))  # solo `repository`
    created_at: Mapped[datetime] = _now()
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class FindingEvent(TenantBase):
    """Registro delle modifiche di triage: chi, quando, da quale stato a quale, perché."""

    __tablename__ = "finding_events"
    __table_args__ = (
        Index("ix_finding_events_finding_id_at", "finding_id", "at"),
        CheckConstraint(f"from_state IN {FINDING_STATES}", name="from_state"),
        CheckConstraint(f"to_state IN {FINDING_STATES}", name="to_state"),
    )

    id: Mapped[uuid.UUID] = _uuid()
    finding_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("findings.id"))
    at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    actor: Mapped[str] = mapped_column(String(300))
    action: Mapped[str] = mapped_column(String(64))
    from_state: Mapped[str | None] = mapped_column(String(16))
    to_state: Mapped[str | None] = mapped_column(String(16))
    reason: Mapped[str | None] = mapped_column(Text)


TENANT_TABLES = tuple(sorted(TenantBase.metadata.tables))
