"""Ingestione di una scansione (B-03, ADR-0016, ADR-0018, ADR-0019): `POST /v1/scans`.

Il server registra una scansione già eseguita dalla CLI: non clona, non esegue plugin, non
ricalcola i finding. Ogni parte è un input non fidato, validata con gli stessi lettori difensivi del
nucleo; un artefatto non valido respinge l'intera richiesta. Idempotente per `(repository, SHA-256
dei byte del report)`. Gli artefatti grezzi vanno nell'`ArtifactStore` prima del commit, con una
chiave derivata da valori che il server controlla: una richiesta interrotta lascia al più un
oggetto orfano, mai una scansione senza artefatti.

Stato che appartiene al server (ADR-0018): `first_seen`, `last_seen`, occorrenze, stato di triage.
Una scansione di PR, o di un branch non principale, crea occorrenze ma non sposta `first_seen`,
`last_seen` né lo stato; un report più vecchio della scansione corrente si registra senza cambiare
la scansione corrente né gli stati; `risolto` lo assegna solo l'ingestione, e solo da una scansione
`complete`.
"""

import hashlib
import io
import json
import uuid
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from pydantic import ValidationError
from sqlalchemy import Engine, delete, select
from sqlalchemy.exc import DBAPIError
from sqlalchemy.orm import Session

from ca_api.auth.verify import Identity
from ca_api.config import Settings
from ca_api.db import stores
from ca_api.db.engine import tenant_session
from ca_api.db.models import (
    Component,
    ExceptionRow,
    Finding,
    FindingEvent,
    FindingOccurrence,
    GraphEdge,
    GraphNode,
    Repository,
    Scan,
    Tenant,
)
from ca_api.problem import ApiProblem, ProblemCode, ProblemError
from ca_core.models.finding import Finding as FindingModel
from ca_core.models.graph import Graph
from ca_core.models.scan_report import ScanKind, ScanReport
from ca_core.ports import ArtifactStore, ArtifactTooLarge
from ca_core.sbom.errors import SbomError
from ca_core.sbom.reader import parse_cyclonedx
from ca_core.schema_validation import SchemaStore

KINDS = ("report", "sarif", "sbom", "graph")
MAX_COMPONENTS = 200_000
CHUNK = 500
SYSTEM_ACTOR = "code-analyzer"
_MAX_DEPTH = 200


@dataclass(frozen=True)
class IngestResult:
    id: uuid.UUID
    created: bool


@dataclass(frozen=True)
class Parts:
    """I byte delle parti ricevute; `report` è obbligatoria."""

    report: bytes
    sarif: bytes | None = None
    sbom: bytes | None = None
    graph: bytes | None = None

    def present(self) -> dict[str, bytes]:
        found = {"report": self.report}
        for kind in ("sarif", "sbom", "graph"):
            value = getattr(self, kind)
            if value is not None:
                found[kind] = value
        return found


def _invalid(kind: str, errors: list[ProblemError] | None = None) -> ApiProblem:
    return ApiProblem(
        422,
        ProblemCode.REPORT_SCHEMA_INVALID,
        detail=f"artefatto non valido: {kind}",
        errors=errors,
    )


def _errors(exc: ValidationError) -> list[ProblemError]:
    """Dove e cosa non va, mai il valore ricevuto."""
    return [
        ProblemError(pointer="/" + "/".join(str(p) for p in e["loc"]), message=e["type"])
        for e in exc.errors()[:50]
    ]


def _depth_ok(node: Any, limit: int = _MAX_DEPTH) -> bool:
    stack = [(node, 0)]
    while stack:
        value, depth = stack.pop()
        if depth > limit:
            return False
        if isinstance(value, dict):
            stack.extend((v, depth + 1) for v in value.values())
        elif isinstance(value, list):
            stack.extend((v, depth + 1) for v in value)
    return True


def validate_parts(
    parts: Parts, schemas: SchemaStore
) -> tuple[ScanReport, Graph | None, dict[str, Any] | None]:
    """Valida ogni parte come input non fidato. Restituisce report, grafo e documento SBOM."""
    try:
        report = ScanReport.model_validate_json(parts.report)
    except ValidationError as exc:
        raise _invalid("report", _errors(exc)) from None
    except ValueError, RecursionError:
        raise _invalid("report") from None
    if report.repository.commit is None:
        raise ApiProblem(
            422,
            ProblemCode.REPORT_SCHEMA_INVALID,
            detail="il report non ha un commit: una cartella non git non si carica",
        )
    if parts.sarif is not None:
        try:
            document = json.loads(parts.sarif)
        except ValueError, RecursionError:
            raise _invalid("sarif") from None
        if not _depth_ok(document) or schemas.validate_sarif(document):
            raise _invalid("sarif")
    sbom: dict[str, Any] | None = None
    if parts.sbom is not None:
        try:
            sbom = dict(
                parse_cyclonedx(parts.sbom, schemas, "1.7", max_bytes=len(parts.sbom)).document
            )
        except SbomError:
            raise _invalid("sbom") from None
    graph: Graph | None = None
    if parts.graph is not None:
        try:
            graph = Graph.model_validate_json(parts.graph)
        except ValidationError as exc:
            raise _invalid("graph", _errors(exc)) from None
        except ValueError, RecursionError:
            raise _invalid("graph") from None
    return report, graph, sbom


def check_repository(report: ScanReport, identity: Identity) -> None:
    """Il report deve dichiarare lo stesso repository e lo stesso commit del token (ADR-0016).

    Il report porta il nome della cartella analizzata, il token il nome del repository del provider:
    coincidono se il report è l'ultimo segmento del nome del token (o il nome intero). Una scansione
    di una sottocartella ha un altro nome e si rifiuta: si lancia dalla radice. Il commit si
    confronta solo se il token lo porta.
    """
    token = identity.repository
    assert token is not None
    if token.name is not None:
        tail = token.name.rsplit("/", 1)[-1]
        if report.repository.name not in (token.name, tail):
            raise ApiProblem(403, ProblemCode.REPOSITORY_MISMATCH)
    if token.sha is not None and token.sha != report.repository.commit:
        raise ApiProblem(403, ProblemCode.REPOSITORY_MISMATCH)


def _branch(ref: str | None) -> str | None:
    if ref is None:
        return None
    return (
        ref.removeprefix("refs/heads/")
        if not ref.startswith("refs/") or ref.startswith("refs/heads/")
        else None
    )


def _is_main_branch(ref: str | None, repository: Repository, settings: Settings) -> bool:
    branch = _branch(ref)
    if branch is None:
        return False
    if repository.default_branch is not None:
        return branch == repository.default_branch
    return branch in settings.default_branches


def _components(sbom: dict[str, Any]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for item in sbom.get("components", [])[:MAX_COMPONENTS]:
        if not isinstance(item, dict) or not isinstance(item.get("name"), str):
            continue
        licenses: list[str] = []
        for entry in item.get("licenses", []):
            if not isinstance(entry, dict):
                continue
            inner = entry.get("license")
            value = (
                (inner or {}).get("id") or (inner or {}).get("name")
                if inner
                else entry.get("expression")
            )
            if isinstance(value, str):
                licenses.append(value[:200])
        out.append(
            {
                "purl": str(item.get("purl") or item["name"])[:2048],
                "name": item["name"][:500],
                "version": item["version"][:200] if isinstance(item.get("version"), str) else None,
                "licenses": licenses,
            }
        )
    return out


def _digests(parts: Parts) -> dict[str, str]:
    return {k: hashlib.sha256(v).hexdigest() for k, v in parts.present().items()}


def _same_artifacts(stored: dict[str, Any], incoming: dict[str, str]) -> bool:
    return {k: v.get("sha256") for k, v in stored.items()} == incoming


def _scores(finding: FindingModel) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for variant in finding.variant_scores:
        prefix = variant.variant.lower()
        out[f"{prefix}_score"] = variant.score
        out[f"{prefix}_level"] = variant.level.value
        out[f"{prefix}_factors"] = variant.impact.model_dump(mode="json")
    return out


def _event(
    finding_id: uuid.UUID, action: str, before: str | None, after: str | None, reason: str
) -> FindingEvent:
    return FindingEvent(
        finding_id=finding_id,
        actor=SYSTEM_ACTOR,
        action=action,
        from_state=before,
        to_state=after,
        reason=reason,
    )


def _chunks(items: list[str]) -> Iterable[list[str]]:
    for i in range(0, len(items), CHUNK):
        yield items[i : i + CHUNK]


def _record(
    session: Session,
    *,
    scan: Scan,
    repository: Repository,
    report: ScanReport,
    graph: Graph | None,
    sbom: dict[str, Any] | None,
    main_branch: bool,
    now: datetime,
) -> None:
    started = scan.started_at
    previous = session.get(Scan, repository.current_scan_id) if repository.current_scan_id else None
    eligible = scan.kind == "full" and main_branch
    becomes_current = eligible and (previous is None or started >= previous.started_at)
    if eligible and repository.default_branch is None:
        repository.default_branch = _branch(scan.ref)

    fingerprints = [f.fingerprint for f in report.findings]
    existing: dict[str, Finding] = {}
    for part in _chunks(fingerprints):
        for row in session.scalars(
            select(Finding).where(
                Finding.repository_id == repository.id, Finding.fingerprint.in_(part)
            )
        ):
            existing[row.fingerprint] = row
    rows: dict[str, Finding] = {}
    for item in report.findings:
        row = existing.get(item.fingerprint)
        data = item.model_dump(mode="json", exclude_none=True)
        if row is None:
            row = Finding(
                repository_id=repository.id,
                fingerprint=item.fingerprint,
                category=item.category.value,
                rule_id=item.rule_id,
                title=item.title,
                data=data,
                status="aperto",
            )
            session.add(row)
        elif becomes_current:
            row.category, row.rule_id, row.title, row.data = (
                item.category.value,
                item.rule_id,
                item.title,
                data,
            )
        rows[item.fingerprint] = row
    session.flush()

    for item in report.findings:
        row = rows[item.fingerprint]
        session.add(
            FindingOccurrence(
                finding_id=row.id,
                scan_id=scan.id,
                commit=report.repository.commit,
                path=item.location.path,
                start_line=item.location.start_line,
                level=item.level.value if item.level else None,
                level_source=item.level_source.value if item.level_source else None,
                evidence=item.evidence,
                report_status=item.status.value,
                baseline_state=item.baseline_state.value if item.baseline_state else None,
                **_scores(item),
            )
        )

    for exc in report.exceptions:
        row = rows.get(exc.fingerprint)
        if row is not None:
            session.add(
                ExceptionRow(
                    finding_id=row.id,
                    origin="repository",
                    reason=exc.reason,
                    expires=exc.expires,
                    approved_by=exc.approved_by[:300],
                    approved_by_verified=False,  # dichiarazione del repository, mai verificata
                    scan_id=scan.id,
                )
            )

    if becomes_current:
        present = set(rows)
        for row in rows.values():
            if row.first_seen is None:
                row.first_seen = started
            row.last_seen = started
            if row.status == "risolto":
                session.add(
                    _event(row.id, "reopened", "risolto", "aperto", "ricomparso nella scansione")
                )
                row.status = "aperto"
        if previous is not None and report.status.value == "complete":
            previous_ids = session.scalars(
                select(FindingOccurrence.finding_id).where(FindingOccurrence.scan_id == previous.id)
            )
            by_id = {r.id: r for r in rows.values()}
            gone = [fid for fid in previous_ids if fid not in by_id]
            for part in [gone[i : i + CHUNK] for i in range(0, len(gone), CHUNK)]:
                for row in session.scalars(select(Finding).where(Finding.id.in_(part))):
                    if row.fingerprint not in present and row.status != "risolto":
                        session.add(
                            _event(
                                row.id, "resolved", row.status, "risolto", "assente dalla scansione"
                            )
                        )
                        row.status = "risolto"
        for model, scan_column in ((Component, Component.scan_id), (GraphNode, GraphNode.scan_id)):
            if previous is not None:
                session.execute(delete(model).where(scan_column == previous.id))
        if previous is not None:
            session.execute(delete(GraphEdge).where(GraphEdge.scan_id == previous.id))
        if sbom is not None:
            for component in _components(sbom):
                session.add(Component(repository_id=repository.id, scan_id=scan.id, **component))
        if graph is not None:
            for module in graph.modules:
                session.add(
                    GraphNode(
                        scan_id=scan.id,
                        path=module.path,
                        language=module.language.value,
                        parse=module.parse.value,
                        test=module.test,
                        churn=module.churn,
                        metrics=module.metrics.model_dump(mode="json") if module.metrics else None,
                    )
                )
            for edge in graph.edges:
                session.add(
                    GraphEdge(
                        scan_id=scan.id,
                        source=edge.source,
                        target=edge.target,
                        external=edge.external,
                        imports=edge.imports,
                        dynamic=edge.dynamic,
                        type_only=edge.type_only,
                        confidence=edge.confidence.value,
                    )
                )
        repository.current_scan_id = scan.id
    session.flush()


def ingest(
    engine: Engine,
    store: ArtifactStore,
    schemas: SchemaStore,
    settings: Settings,
    identity: Identity,
    parts: Parts,
    *,
    now: datetime,
) -> IngestResult:
    report, graph, sbom = validate_parts(parts, schemas)
    check_repository(report, identity)
    token = identity.repository
    assert token is not None
    with Session(engine) as session:
        tenant = session.scalar(select(Tenant).where(Tenant.name == identity.tenant))
        schema = tenant.schema if tenant is not None else None
    if schema is None:
        raise ApiProblem(403, ProblemCode.FORBIDDEN, detail="tenant non configurato")

    digests = _digests(parts)
    with tenant_session(engine, schema) as session:
        repository = stores.upsert_repository(
            session,
            provider=token.provider,
            issuer=identity.issuer,
            external_id=token.external_id,
            name=token.name or report.repository.name,
        )
        known = stores.scan_by_digest(session, repository.id, digests["report"])
        if known is not None:
            if not _same_artifacts(known.artifact_keys, digests):
                raise ApiProblem(409, ProblemCode.ARTIFACTS_CONFLICT)
            return IngestResult(known.id, False)
        repository_id = repository.id

    scan_id = uuid.uuid7()
    keys: dict[str, dict[str, str]] = {}
    try:
        for kind, data in parts.present().items():
            key = f"{schema}/{scan_id}/{kind}"
            try:
                store.put(key, io.BytesIO(data), max_bytes=max(len(data), 1), sha256=digests[kind])
            except ArtifactTooLarge:  # non può accadere: il tetto è la lunghezza ricevuta
                raise ApiProblem(413, ProblemCode.PAYLOAD_TOO_LARGE) from None
            keys[kind] = {"key": key, "sha256": digests[kind]}
        try:
            with tenant_session(engine, schema) as session:
                repository = session.get(Repository, repository_id)
                assert repository is not None
                scan = Scan(
                    id=scan_id,
                    repository_id=repository_id,
                    commit=report.repository.commit,
                    ref=token.ref,
                    kind=report.scan.kind.value,
                    pull_request=report.scan.pull_request,
                    base_commit=report.scan.base_commit
                    if report.scan.kind is ScanKind.PR
                    else None,
                    status=report.status.value,
                    started_at=report.started_at,
                    duration_seconds=report.duration_seconds,
                    report_sha256=digests["report"],
                    report_schema_version=f"{report.version}",
                    scoring_config_version=report.scoring.config_version
                    if report.scoring
                    else None,
                    uploaded_by=identity.actor,
                    artifact_keys=keys,
                )
                session.add(scan)
                session.flush()
                _record(
                    session,
                    scan=scan,
                    repository=repository,
                    report=report,
                    graph=graph,
                    sbom=sbom,
                    main_branch=_is_main_branch(token.ref, repository, settings),
                    now=now,
                )
        except DBAPIError:
            # Una ripetizione in corsa: la stessa esecuzione inviata due volte insieme.
            with tenant_session(engine, schema) as session:
                known = stores.scan_by_digest(session, repository_id, digests["report"])
                if known is None:
                    raise
                if not _same_artifacts(known.artifact_keys, digests):
                    raise ApiProblem(409, ProblemCode.ARTIFACTS_CONFLICT) from None
                return IngestResult(known.id, False)
    except BaseException:
        for entry in keys.values():  # al più un orfano: si prova a non lasciarne
            store.delete(entry["key"])
        raise
    return IngestResult(scan_id, True)


__all__ = ["IngestResult", "Parts", "ingest", "validate_parts"]
