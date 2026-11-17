"""Elenco, dettaglio e triage dei finding (B-08, B-09, ADR-0018, ADR-0019, ADR-0029).

Lo stato effettivo di un finding è `accettato` se è `aperto` o `in_corso` e vale almeno una
eccezione: una del server non scaduta né revocata, oppure una dichiarata dal repository e applicata
nella scansione corrente (ADR-0018). Le due origini non si fondono: il dettaglio le mostra distinte,
e quella del repository porta un approvatore dichiarato e non verificato. `risolto` lo assegna solo
l'ingestione: l'API non lo rende assegnabile.
"""

import uuid
from datetime import date, datetime, timedelta
from typing import Any

from sqlalchemy import (
    ColumnElement,
    String,
    and_,
    case,
    cast,
    exists,
    func,
    literal,
    or_,
    select,
    tuple_,
)
from sqlalchemy.orm import Session, aliased

from ca_api.access import binding_of, decode_cursor, encode_cursor, not_found
from ca_api.auth.verify import Identity
from ca_api.db.models import ExceptionRow, Finding, FindingEvent, FindingOccurrence, Repository
from ca_api.db.models import Scan as ScanRow
from ca_api.models import (
    CreateException,
    ExceptionOrigin,
    ExceptionRecord,
    FindingDetail,
    FindingListItem,
    FindingPage,
    FindingPatch,
    Occurrence,
    RevokeException,
    SetOwner,
    SetStatus,
    SortKey,
)
from ca_api.models import FindingEvent as EventModel
from ca_api.problem import ApiProblem, ProblemCode, ProblemError
from ca_core.models.finding import (
    Category,
    ImpactFactors,
    Level,
    Status,
    VariantScore,
)
from ca_core.models.finding import (
    Finding as FindingModel,
)

LEVEL_RANK = {"critico": 0, "alto": 1, "medio": 2, "basso": 3}
EFFECTIVE_OPEN = ("aperto", "in_corso")


def _scope_scan(
    session: Session, repository: Repository, scan: uuid.UUID | None
) -> uuid.UUID | None:
    if scan is None:
        return repository.current_scan_id
    row = session.get(ScanRow, scan)
    if row is None or row.repository_id != repository.id:
        raise not_found()
    return row.id


def _active_exception(finding: Any, scope: uuid.UUID | None, today: date) -> ColumnElement[bool]:
    return exists().where(
        ExceptionRow.finding_id == finding.id,
        ExceptionRow.revoked_at.is_(None),
        ExceptionRow.expires >= today,
        or_(ExceptionRow.origin == "server", ExceptionRow.scan_id == scope),
    )


def list_findings(
    session: Session,
    repository: Repository,
    *,
    scan: uuid.UUID | None,
    level: list[Level] | None,
    category: list[Category] | None,
    status: list[Status] | None,
    tool: list[str] | None,
    new: bool | None,
    q: str | None,
    sort: SortKey,
    limit: int,
    cursor: str | None,
    today: date,
) -> FindingPage:
    scope = _scope_scan(session, repository, scan)
    scope_row = session.get(ScanRow, scope) if scope is not None else None
    f, o = Finding, aliased(FindingOccurrence)
    wanted_status = {s.value for s in status or []}
    active = _active_exception(f, scope, today)
    effective = case((and_(f.status.in_(EFFECTIVE_OPEN), active), "accettato"), else_=f.status)
    level_expr = func.coalesce(o.level, f.data["level"].astext)

    conditions: list[ColumnElement[bool]] = [f.repository_id == repository.id]
    in_scope = o.id.is_not(None)
    if "risolto" in wanted_status:
        in_scope = or_(in_scope, f.status == "risolto")  # i risolti solo se il filtro li chiede
    conditions.append(in_scope)
    if level:
        conditions.append(level_expr.in_([item.value for item in level]))
    if category:
        conditions.append(f.category.in_([item.value for item in category]))
    if wanted_status:
        conditions.append(effective.in_(wanted_status))
    if tool:
        conditions.append(or_(*[f.data["tools"].contains([t]) for t in tool]))
    is_new = _is_new(f, o, scope_row)
    if new is not None:
        conditions.append(is_new if new else ~is_new)
    if q:
        conditions.append(
            or_(
                f.title.icontains(q, autoescape=True),
                f.rule_id.icontains(q, autoescape=True),
                o.path.icontains(q, autoescape=True),
                f.data["location"]["purl"].astext.icontains(q, autoescape=True),
            )
        )

    rank = case(*[(level_expr == name, value) for name, value in LEVEL_RANK.items()], else_=4)
    first_seen_key = -func.coalesce(func.extract("epoch", f.first_seen), 0.0)
    keys: dict[SortKey, list[ColumnElement[Any]]] = {
        SortKey.IMPACT: [
            rank,
            case((is_new, 0), else_=1),
            first_seen_key,
            cast(f.id, String),
        ],
        SortKey.FIRST_SEEN: [first_seen_key, cast(f.id, String)],
        SortKey.PATH: [func.coalesce(o.path, ""), cast(f.id, String)],
        SortKey.SCORE_A: [-func.coalesce(o.a_score, -1.0), cast(f.id, String)],
        SortKey.SCORE_B: [-func.coalesce(o.b_score, -1.0), cast(f.id, String)],
    }
    order = keys[sort]
    labels = [expr.label(f"k{i}") for i, expr in enumerate(order)]
    binding = binding_of(
        str(repository.id),
        str(scope),
        sorted(x.value for x in level or []),
        sorted(x.value for x in category or []),
        sorted(wanted_status),
        sorted(tool or []),
        new,
        q,
        sort.value,
    )

    page_conditions = list(conditions)
    if cursor is not None:
        state = decode_cursor(cursor, binding)
        try:
            values = [state["k"][i] for i in range(len(order))]
        except (KeyError, IndexError, TypeError):
            raise ApiProblem(422, ProblemCode.INVALID_CURSOR) from None
        page_conditions.append(tuple_(*order) > tuple_(*[literal(v) for v in values]))

    base = (
        select(f, o, effective.label("eff"), active.label("has_exc"), *labels)
        .select_from(f)
        .outerjoin(o, and_(o.finding_id == f.id, o.scan_id == scope))
    )
    rows = session.execute(base.where(*page_conditions).order_by(*order).limit(limit + 1)).all()
    counted = (
        select(func.count())
        .select_from(f)
        .outerjoin(o, and_(o.finding_id == f.id, o.scan_id == scope))
    )
    total = session.scalar(counted.where(*conditions)) or 0
    total_new = session.scalar(counted.where(*conditions, is_new)) or 0

    page = rows[:limit]
    items = [_list_item(session, row, scope, scope_row) for row in page]
    next_cursor = None
    if len(rows) > limit:
        last = page[-1]
        marker = [getattr(last, f"k{i}") for i in range(len(order))]
        next_cursor = encode_cursor(
            {"k": [m if isinstance(m, int | float | str) else float(m) for m in marker]}, binding
        )
    return FindingPage(items=items, next_cursor=next_cursor, total=total, total_new=total_new)


def _is_new(f: Any, o: Any, scope_row: ScanRow | None) -> ColumnElement[bool]:
    """Nuovo: in una scansione di PR è lo stato rispetto alla baseline; altrimenti la prima
    rilevazione è la scansione in esame (ADR-0025, ADR-0018)."""
    if scope_row is not None and scope_row.kind == "pr":
        return o.baseline_state == "new"
    if scope_row is None:
        return literal(False)
    return and_(o.id.is_not(None), f.first_seen == scope_row.started_at)


def _item_is_new(
    finding: Finding, occurrence: FindingOccurrence | None, scope_row: ScanRow | None
) -> bool | None:
    if occurrence is None or scope_row is None:
        return None
    if scope_row.kind == "pr":
        return None if occurrence.baseline_state is None else occurrence.baseline_state == "new"
    return finding.first_seen == scope_row.started_at


def _list_item(
    session: Session, row: Any, scope: uuid.UUID | None, scope_row: ScanRow | None
) -> FindingListItem:
    finding: Finding = row[0]
    occurrence: FindingOccurrence | None = row[1]
    data = finding.data
    location = data.get("location", {}) if isinstance(data.get("location"), dict) else {}
    origin: ExceptionOrigin | None = None
    if row.eff == "accettato":
        origin = _exception_origin(session, finding.id, scope)
    return FindingListItem(
        id=finding.id,
        fingerprint=finding.fingerprint,
        level=(occurrence.level if occurrence else data.get("level")),
        level_source=(occurrence.level_source if occurrence else data.get("level_source")),
        title=finding.title[:500],
        rule_id=finding.rule_id,
        category=finding.category,  # type: ignore[arg-type]
        tools=list(data.get("tools", [])),
        path=(occurrence.path if occurrence else location.get("path")),
        start_line=(occurrence.start_line if occurrence else location.get("start_line")),
        status=row.eff,
        exception_origin=origin,
        new=_item_is_new(finding, occurrence, scope_row),
        first_seen=finding.first_seen,
        last_seen=finding.last_seen,
        owner=finding.owner,
        score_a=occurrence.a_score if occurrence else None,
        level_a=occurrence.a_level if occurrence else None,
        score_b=occurrence.b_score if occurrence else None,
        level_b=occurrence.b_level if occurrence else None,
    )


def _exception_origin(
    session: Session, finding_id: uuid.UUID, scope: uuid.UUID | None
) -> ExceptionOrigin | None:
    rows = session.scalars(
        select(ExceptionRow.origin).where(
            ExceptionRow.finding_id == finding_id,
            ExceptionRow.revoked_at.is_(None),
            or_(ExceptionRow.origin == "server", ExceptionRow.scan_id == scope),
        )
    ).all()
    if "server" in rows:
        return ExceptionOrigin.SERVER
    return ExceptionOrigin.REPOSITORY if rows else None


# --- dettaglio -----------------------------------------------------------------------------------


def _variant(occurrence: FindingOccurrence, prefix: str) -> VariantScore | None:
    score, level, factors = (
        getattr(occurrence, f"{prefix}_{n}") for n in ("score", "level", "factors")
    )
    if score is None or level is None or factors is None:
        return None
    return VariantScore(
        variant="A" if prefix == "a" else "B",
        score=score,
        level=Level(level),
        impact=ImpactFactors.model_validate(factors),
    )


def get_finding(session: Session, finding_id: uuid.UUID, *, today: date) -> FindingDetail:
    row = session.get(Finding, finding_id)
    if row is None:
        raise not_found()
    repository = session.get(Repository, row.repository_id)
    assert repository is not None
    scope = repository.current_scan_id
    occurrence = None
    if scope is not None:
        occurrence = session.scalar(
            select(FindingOccurrence).where(
                FindingOccurrence.finding_id == row.id, FindingOccurrence.scan_id == scope
            )
        )
    if occurrence is None:
        from ca_api.db.models import Scan

        occurrence = session.scalar(
            select(FindingOccurrence)
            .join(Scan, Scan.id == FindingOccurrence.scan_id)
            .where(FindingOccurrence.finding_id == row.id)
            .order_by(Scan.started_at.desc())
            .limit(1)
        )
    exceptions = list(
        session.scalars(
            select(ExceptionRow)
            .where(ExceptionRow.finding_id == row.id)
            .order_by(ExceptionRow.created_at.desc())
        )
    )
    active = any(
        e.revoked_at is None and e.expires >= today and (e.origin == "server" or e.scan_id == scope)
        for e in exceptions
    )
    effective = "accettato" if row.status in EFFECTIVE_OPEN and active else row.status
    data = dict(row.data)
    data.update(
        {
            "id": str(row.id),
            "status": effective,
            "owner": row.owner,
            "due_date": row.due_date.isoformat() if row.due_date else None,
        }
    )
    for name in ("first_seen", "last_seen"):  # i valori del server, se ci sono (ADR-0018)
        value = getattr(row, name)
        if value is not None:
            data[name] = value.isoformat()
    finding = FindingModel.model_validate({k: v for k, v in data.items() if v is not None})
    scores: list[VariantScore] = []
    if occurrence is not None:
        scores = [
            v for v in (_variant(occurrence, "a"), _variant(occurrence, "b")) if v is not None
        ]
    events = session.scalars(
        select(FindingEvent)
        .where(FindingEvent.finding_id == row.id)
        .order_by(FindingEvent.at.desc())
    )
    return FindingDetail(
        finding=finding,
        occurrence=(
            Occurrence(scan_id=occurrence.scan_id, commit=occurrence.commit, variant_scores=scores)
            if occurrence is not None
            else None
        ),
        exceptions=[
            ExceptionRecord(
                id=e.id,
                origin=ExceptionOrigin(e.origin),
                reason=e.reason,
                expires=e.expires,
                approved_by=e.approved_by,
                approved_by_verified=e.approved_by_verified,
                revoked_at=e.revoked_at,
            )
            for e in exceptions
        ],
        events=[
            EventModel(
                at=e.at,
                actor=e.actor,
                action=e.action,
                from_state=Status(e.from_state) if e.from_state else None,
                to_state=Status(e.to_state) if e.to_state else None,
                reason=e.reason,
            )
            for e in events
        ],
    )


# --- triage ---------------------------------------------------------------------------------------


def _bad(pointer: str, message: str) -> ApiProblem:
    return ApiProblem(
        422, ProblemCode.VALIDATION_FAILED, errors=[ProblemError(pointer=pointer, message=message)]
    )


def patch_finding(
    session: Session,
    finding_id: uuid.UUID,
    body: SetStatus | SetOwner | CreateException | RevokeException,
    identity: Identity,
    *,
    now: datetime,
    max_exception_days: int,
) -> None:
    """Una modifica di triage con il suo evento. `approved_by` è l'identità autenticata."""
    row = session.scalars(select(Finding).where(Finding.id == finding_id).with_for_update()).first()
    if row is None:
        raise not_found()
    before = row.status
    actor = identity.actor
    if isinstance(body, SetStatus):
        if row.status == "risolto":
            raise ApiProblem(409, ProblemCode.STATE_CONFLICT, detail="il finding è risolto")
        if body.status == "falso_positivo" and not body.reason:
            raise _bad("/reason", "obbligatoria per falso_positivo")
        row.status = body.status
        session.add(
            FindingEvent(
                finding_id=row.id,
                actor=actor,
                action="set-status",
                from_state=before,
                to_state=row.status,
                reason=body.reason,
            )
        )
    elif isinstance(body, SetOwner):
        previous = row.owner
        row.owner = body.owner
        session.add(
            FindingEvent(
                finding_id=row.id,
                actor=actor,
                action="set-owner",
                from_state=before,
                to_state=before,
                reason=f"{previous or '-'} -> {body.owner or '-'}"[:500],
            )
        )
    elif isinstance(body, CreateException):
        today = now.date()
        if body.expires <= today:
            raise _bad("/expires", "deve essere futura")
        if body.expires > today + timedelta(days=max_exception_days):
            raise _bad("/expires", f"oltre il massimo di {max_exception_days} giorni")
        if row.status == "risolto":
            raise ApiProblem(409, ProblemCode.STATE_CONFLICT, detail="il finding è risolto")
        session.add(
            ExceptionRow(
                finding_id=row.id,
                origin="server",
                reason=body.reason,
                expires=body.expires,
                approved_by=actor,
                approved_by_verified=True,  # identità autenticata, non una dichiarazione
            )
        )
        session.add(
            FindingEvent(
                finding_id=row.id,
                actor=actor,
                action="create-exception",
                from_state=before,
                to_state="accettato",
                reason=body.reason,
            )
        )
    else:
        exception = session.get(ExceptionRow, body.exception_id)
        if exception is None or exception.finding_id != row.id:
            raise not_found()
        if exception.origin != "server":
            raise ApiProblem(
                409,
                ProblemCode.STATE_CONFLICT,
                detail="un'eccezione del repository non si revoca da qui",
            )
        if exception.revoked_at is not None:
            raise ApiProblem(409, ProblemCode.STATE_CONFLICT, detail="già revocata")
        exception.revoked_at = now
        session.add(
            FindingEvent(
                finding_id=row.id,
                actor=actor,
                action="revoke-exception",
                from_state="accettato",
                to_state=before,
                reason=exception.reason[:500],
            )
        )
    session.flush()


__all__ = ["FindingPatch", "get_finding", "list_findings", "patch_finding"]
