"""Letture di repository, scansioni e artefatti (B-06, B-10, B-11, ADR-0029). Solo lettura.

Funzioni sul modello relazionale che restituiscono i modelli dell'API. Una risorsa che non esiste
nello schema del tenant, o che una pipeline non possiede, è `404`.
"""

import json
import uuid
from datetime import UTC, datetime
from typing import Any, BinaryIO

from pydantic import ValidationError
from sqlalchemy import literal, select, tuple_
from sqlalchemy.orm import Session

from ca_api.access import binding_of, decode_cursor, encode_cursor, not_found
from ca_api.auth.verify import Identity
from ca_api.db.models import Repository, Scan
from ca_api.models import (
    RepositoryPage,
    RepositorySummary,
    ScanDetail,
    ScanPage,
    ScanSummary,
)
from ca_api.problem import ApiProblem, ProblemCode
from ca_core.models.graph import Graph
from ca_core.models.scan_report import ScanReport
from ca_core.ports import ArtifactNotFound, ArtifactStore


def scan_summary(scan: Scan) -> ScanSummary:
    return ScanSummary(
        id=scan.id,
        repository_id=scan.repository_id,
        kind=scan.kind,  # type: ignore[arg-type]
        ref=scan.ref,
        pull_request=scan.pull_request,
        commit=scan.commit,
        status=scan.status,  # type: ignore[arg-type]
        started_at=scan.started_at,
        duration_seconds=scan.duration_seconds,
    )


def repository_summary(session: Session, row: Repository) -> RepositorySummary:
    current = session.get(Scan, row.current_scan_id) if row.current_scan_id else None
    return RepositorySummary(
        id=row.id,
        provider="github" if row.provider == "github" else "gitlab",
        name=row.name,
        default_branch=row.default_branch,
        tier=row.tier,
        internet_facing=row.internet_facing,
        catalog_id=row.catalog_id,
        current_scan=scan_summary(current) if current else None,
    )


def owns(identity: Identity, repository: Repository) -> bool:
    """Una pipeline raggiunge solo il proprio repository (identità `(provider, issuer, id)`)."""
    token = identity.repository
    return (
        identity.kind == "pipeline"
        and token is not None
        and (repository.provider, repository.issuer, repository.external_id)
        == (token.provider, identity.issuer, token.external_id)
    )


def list_repositories(session: Session, *, limit: int, cursor: str | None) -> RepositoryPage:
    binding = binding_of("repositories")
    query = select(Repository).order_by(Repository.id).limit(limit + 1)
    if cursor is not None:
        state = decode_cursor(cursor, binding)
        try:
            query = query.where(Repository.id > uuid.UUID(state["id"]))
        except (KeyError, ValueError):
            raise ApiProblem(422, ProblemCode.INVALID_CURSOR) from None
    rows = list(session.scalars(query))
    page = rows[:limit]
    more = encode_cursor({"id": str(page[-1].id)}, binding) if len(rows) > limit else None
    return RepositoryPage(items=[repository_summary(session, r) for r in page], next_cursor=more)


def get_repository(session: Session, repository_id: uuid.UUID) -> Repository:
    row = session.get(Repository, repository_id)
    if row is None:
        raise not_found()
    return row


def list_scans(
    session: Session, repository_id: uuid.UUID, *, limit: int, cursor: str | None
) -> ScanPage:
    get_repository(session, repository_id)
    binding = binding_of("scans", str(repository_id))
    query = (
        select(Scan)
        .where(Scan.repository_id == repository_id)
        .order_by(Scan.started_at.desc(), Scan.id.desc())
        .limit(limit + 1)
    )
    if cursor is not None:
        state = decode_cursor(cursor, binding)
        try:
            marker = (datetime.fromisoformat(state["at"]), uuid.UUID(state["id"]))
        except (KeyError, ValueError):
            raise ApiProblem(422, ProblemCode.INVALID_CURSOR) from None
        query = query.where(
            tuple_(Scan.started_at, Scan.id) < tuple_(literal(marker[0]), literal(marker[1]))
        )
    rows = list(session.scalars(query))
    page = rows[:limit]
    more = (
        encode_cursor({"at": page[-1].started_at.isoformat(), "id": str(page[-1].id)}, binding)
        if len(rows) > limit
        else None
    )
    return ScanPage(items=[scan_summary(s) for s in page], next_cursor=more)


def visible_scan(session: Session, scan_id: uuid.UUID, identity: Identity) -> Scan:
    scan = session.get(Scan, scan_id)
    if scan is None:
        raise not_found()
    if identity.kind == "pipeline":
        repository = session.get(Repository, scan.repository_id)
        if repository is None or not owns(identity, repository):
            raise not_found()
    return scan


def _artifact(store: ArtifactStore, scan: Scan, kind: str) -> BinaryIO:
    entry = scan.artifact_keys.get(kind)
    if not isinstance(entry, dict) or "key" not in entry:
        raise not_found()
    try:
        return store.open(entry["key"])
    except ArtifactNotFound:
        raise not_found() from None


def scan_detail(
    session: Session, store: ArtifactStore, scan_id: uuid.UUID, identity: Identity
) -> ScanDetail:
    """I campi del report che non sono finding, dal report conservato (ADR-0029)."""
    scan = visible_scan(session, scan_id, identity)
    with _artifact(store, scan, "report") as handle:
        raw = handle.read()
    try:
        report = ScanReport.model_validate_json(raw)
    except (ValidationError, ValueError):
        raise ApiProblem(500, ProblemCode.INTERNAL_ERROR) from None
    return ScanDetail(
        summary=scan_summary(scan),
        plugins=report.plugins,
        warnings=report.warnings,
        gate=report.gate,
        scoring=report.scoring,
        enrichment=report.enrichment,
        baseline=report.baseline,
    )


def scan_sarif(
    session: Session, store: ArtifactStore, scan_id: uuid.UUID, identity: Identity
) -> bytes:
    scan = visible_scan(session, scan_id, identity)
    with _artifact(store, scan, "sarif") as handle:
        return handle.read()


def current_scan(session: Session, repository_id: uuid.UUID) -> Scan:
    repository = get_repository(session, repository_id)
    if repository.current_scan_id is None:
        raise not_found()
    scan = session.get(Scan, repository.current_scan_id)
    if scan is None:
        raise not_found()
    return scan


def repository_sbom(session: Session, store: ArtifactStore, repository_id: uuid.UUID) -> bytes:
    with _artifact(store, current_scan(session, repository_id), "sbom") as handle:
        return handle.read()


def repository_graph(session: Session, store: ArtifactStore, repository_id: uuid.UUID) -> Graph:
    with _artifact(store, current_scan(session, repository_id), "graph") as handle:
        try:
            return Graph.model_validate_json(handle.read())
        except (ValidationError, ValueError):
            raise ApiProblem(500, ProblemCode.INTERNAL_ERROR) from None


def service_context_of(session: Session, identity: Identity) -> dict[str, Any]:
    """Il contesto registrato per il repository del token; 404 se non è ancora noto (ADR-0028)."""
    token = identity.repository
    assert token is not None
    row = session.scalar(
        select(Repository).where(
            Repository.provider == token.provider,
            Repository.issuer == identity.issuer,
            Repository.external_id == token.external_id,
        )
    )
    if row is None:
        raise not_found()
    context: dict[str, Any] = {"version": 1, "origin": "code-analyzer-server"}
    for name in ("tier", "internet_facing", "catalog_id"):
        value = getattr(row, name)
        if value is not None:
            context[name] = value
    return context


def now_utc() -> datetime:
    return datetime.now(UTC)


def to_json(value: Any) -> bytes:
    return json.dumps(value, separators=(",", ":")).encode()
