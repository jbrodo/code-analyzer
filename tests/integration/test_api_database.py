"""C-07, B-02: migrazioni, schema per tenant e vincoli, su un PostgreSQL vero in container.

`CA_TEST_DOCKER=1`. Il container è PostgreSQL 16 (§2); nessun servizio esterno.
"""

import os
import uuid
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import Engine, inspect, text
from sqlalchemy.exc import DBAPIError

from ca_api.db import migrate, stores
from ca_api.db.engine import DatabaseError, make_engine, tenant_session
from ca_api.db.models import (
    ExceptionRow,
    Finding,
    FindingEvent,
    Repository,
    Scan,
    TenantBase,
)

pytestmark = pytest.mark.skipif(
    os.environ.get("CA_TEST_DOCKER") != "1", reason="richiede Docker (CA_TEST_DOCKER=1)"
)
SHA = "a" * 40
NOW = datetime(2026, 11, 17, 12, 0, tzinfo=UTC)


@pytest.fixture(scope="module")
def engine() -> Iterator[Engine]:
    from testcontainers.community.postgres import PostgresContainer

    with PostgresContainer("postgres:16", driver="pg8000") as postgres:
        created = make_engine(postgres.get_connection_url())
        migrate.upgrade_global(created)
        yield created
        created.dispose()


@pytest.fixture(scope="module")
def acme(engine: Engine) -> str:
    return stores.create_tenant(engine, "acme").schema


@pytest.fixture(scope="module")
def globex(engine: Engine) -> str:
    return stores.create_tenant(engine, "globex").schema


def repo(session, external: str = "1", name: str = "acme/shop") -> Repository:
    return stores.upsert_repository(
        session,
        provider="github",
        issuer="https://token.actions.example",
        external_id=external,
        name=name,
    )


def scan_for(
    session, repository: Repository, digest: str, *, kind: str = "full", at: datetime = NOW
) -> Scan:
    scan = Scan(
        repository_id=repository.id,
        commit=SHA,
        ref="refs/heads/main",
        kind=kind,
        base_commit=SHA if kind == "pr" else None,
        status="complete",
        started_at=at,
        duration_seconds=1.5,
        report_sha256=digest,
        report_schema_version="1.3",
        uploaded_by="pipeline",
    )
    session.add(scan)
    session.flush()
    return scan


def finding(session, repository: Repository, fingerprint: str = "sha256:" + "f" * 64) -> Finding:
    row = Finding(
        repository_id=repository.id,
        fingerprint=fingerprint,
        category="sast",
        rule_id="B602",
        title="t",
        data={"title": "t"},
    )
    session.add(row)
    session.flush()
    return row


# --- migrazioni ---------------------------------------------------------------------------------


def test_the_tenant_schema_has_exactly_the_phase_2_tables(engine: Engine, acme: str) -> None:
    tables = set(inspect(engine).get_table_names(schema=acme)) - {"alembic_version"}
    assert tables == set(TenantBase.metadata.tables)
    assert "tenants" in inspect(engine).get_table_names()
    assert "findings" not in inspect(engine).get_table_names()  # mai nello schema pubblico


def test_upgrading_twice_is_a_no_op(engine: Engine, acme: str) -> None:
    migrate.upgrade_tenant(engine, acme)
    migrate.upgrade_global(engine)


def test_a_tenant_migration_can_be_undone_and_redone_without_touching_another(
    engine: Engine, acme: str, globex: str
) -> None:
    with tenant_session(engine, globex) as session:
        repo(session, "keep")
    temp = stores.create_tenant(engine, "temp").schema
    migrate.downgrade_tenant(engine, temp)
    assert set(inspect(engine).get_table_names(schema=temp)) <= {"alembic_version"}
    migrate.upgrade_tenant(engine, temp)
    assert "findings" in inspect(engine).get_table_names(schema=temp)
    with tenant_session(engine, globex) as session:
        assert [r.external_id for r in stores.list_repositories(session, limit=10)] == ["keep"]


def test_the_global_chain_can_be_undone_and_redone(engine: Engine) -> None:
    migrate.downgrade_global(engine)
    assert "tenants" not in inspect(engine).get_table_names()
    migrate.upgrade_global(engine)
    assert "tenants" in inspect(engine).get_table_names()


def test_tenant_creation_is_idempotent_on_the_name(engine: Engine) -> None:
    first = stores.create_tenant(engine, "idem")
    second = stores.create_tenant(engine, "idem")
    assert first.schema == second.schema and first.schema.startswith("t_")


# --- isolamento -----------------------------------------------------------------------------------


def test_two_tenants_never_see_each_others_rows_even_with_raw_sql(
    engine: Engine, acme: str, globex: str
) -> None:
    with tenant_session(engine, acme) as session:
        repo(session, "iso-a", "acme/only-a")
    with tenant_session(engine, globex) as session:
        repo(session, "iso-b", "globex/only-b")
        names = {r.name for r in stores.list_repositories(session, limit=50)}
        assert "acme/only-a" not in names and "globex/only-b" in names
    with tenant_session(engine, globex) as session:
        # SQL grezzo non passa dalla traduzione dello schema: non raggiunge nessun tenant
        with pytest.raises(DBAPIError), session.begin_nested():
            session.execute(text("SELECT name FROM repositories")).all()


def test_the_same_external_identity_is_allowed_in_two_tenants(
    engine: Engine, acme: str, globex: str
) -> None:
    with tenant_session(engine, acme) as session:
        a = repo(session, "shared-id").id
    with tenant_session(engine, globex) as session:
        b = repo(session, "shared-id").id
    assert a != b


def test_a_schema_name_that_is_not_a_tenant_schema_never_reaches_the_database(
    engine: Engine,
) -> None:
    """Il nome lo sceglie il tenant dell'identità, e `check_schema` lo valida prima di ogni SQL.

    Limite dichiarato: non c'è un ruolo di database per tenant in Fase 2, quindi un SQL grezzo con
    uno schema qualificato raggiungerebbe un altro tenant. Per questo il codice dell'app
    non usa SQL grezzo con identificativi, e uno senza schema non trova le tabelle (sopra).
    """
    for bad in ('public"; DROP SCHEMA t_x; --', "public", "pg_catalog", ""):
        with pytest.raises(DatabaseError):
            with tenant_session(engine, bad):
                pass


# --- vincoli --------------------------------------------------------------------------------------


def test_the_unique_index_on_repository_and_fingerprint_holds(engine: Engine, acme: str) -> None:
    with tenant_session(engine, acme) as session:
        r = repo(session, "uniq-fp")
        finding(session, r)
        with pytest.raises(DBAPIError):
            with session.begin_nested():
                finding(session, r)
        other = repo(session, "uniq-fp-2")
        assert finding(
            session, other
        ).id  # lo stesso fingerprint in un altro repository è un altro finding


def test_the_same_report_digest_cannot_be_stored_twice_for_a_repository(
    engine: Engine, acme: str
) -> None:
    with tenant_session(engine, acme) as session:
        r = repo(session, "uniq-scan")
        scan_for(session, r, "c" * 64)
        with pytest.raises(DBAPIError):
            with session.begin_nested():
                scan_for(session, r, "c" * 64)
        assert stores.scan_by_digest(session, r.id, "c" * 64) is not None
        assert stores.scan_by_digest(session, r.id, "d" * 64) is None


@pytest.mark.parametrize(
    "build",
    [
        lambda s, r: setattr(r, "tier", 4),
        lambda s, r: s.add(
            Finding(
                repository_id=r.id,
                fingerprint="sha256:" + "f" * 64,
                category="sast",
                rule_id="x",
                title="t",
                data={},
                status="resolved",
            )
        ),
        lambda s, r: s.add(
            Finding(
                repository_id=r.id,
                fingerprint="not-a-fingerprint",
                category="sast",
                rule_id="x",
                title="t",
                data={},
            )
        ),
        lambda s, r: scan_for(s, r, "bad", kind="full"),
        lambda s, r: scan_for(s, r, "e" * 64, kind="weird"),
    ],
    ids=[
        "tier-4",
        "state-outside-vocabulary",
        "malformed-fingerprint",
        "malformed-digest",
        "unknown-kind",
    ],
)
def test_the_closed_vocabularies_and_shapes_are_enforced_by_the_database(
    engine: Engine, acme: str, build
) -> None:
    with pytest.raises(DBAPIError):
        with tenant_session(engine, acme) as session:
            r = repo(session, f"ck-{uuid.uuid4().hex[:6]}")
            build(session, r)
            session.flush()


def test_a_pr_scan_needs_a_base_commit_and_a_full_one_must_not_have_it(
    engine: Engine, acme: str
) -> None:
    with tenant_session(engine, acme) as session:
        r = repo(session, "pr-base")
        scan_for(session, r, "1" * 64, kind="pr")  # con base: ammessa
    with pytest.raises(DBAPIError):
        with tenant_session(engine, acme) as session:
            r = repo(session, "pr-base")
            bad = scan_for(session, r, "2" * 64, kind="pr")
            bad.base_commit = None
            session.flush()


def test_a_repository_exception_can_never_be_marked_verified(engine: Engine, acme: str) -> None:
    with tenant_session(engine, acme) as session:
        r = repo(session, "exc")
        f = finding(session, r, "sha256:" + "1" * 64)
        session.add(
            ExceptionRow(
                finding_id=f.id,
                origin="server",
                reason="ok",
                expires=NOW.date(),
                approved_by="ada",
                approved_by_verified=True,
            )
        )
        session.add(
            ExceptionRow(
                finding_id=f.id,
                origin="repository",
                reason="ok",
                expires=NOW.date(),
                approved_by="chiunque",
                approved_by_verified=False,
            )
        )
        session.flush()
    with pytest.raises(DBAPIError):
        with tenant_session(engine, acme) as session:
            r = repo(session, "exc")
            f = finding(session, r, "sha256:" + "2" * 64)
            session.add(
                ExceptionRow(
                    finding_id=f.id,
                    origin="repository",
                    reason="x",
                    expires=NOW.date(),
                    approved_by="x",
                    approved_by_verified=True,
                )
            )
            session.flush()


def test_events_keep_who_when_and_from_to(engine: Engine, acme: str) -> None:
    with tenant_session(engine, acme) as session:
        r = repo(session, "events")
        f = finding(session, r, "sha256:" + "3" * 64)
        session.add(
            FindingEvent(
                finding_id=f.id,
                actor="https://idp|ada",
                action="set-status",
                from_state="aperto",
                to_state="in_corso",
            )
        )
        session.flush()
        assert session.query(FindingEvent).filter_by(finding_id=f.id).one().at is not None


def test_deleting_a_repository_with_findings_is_refused(engine: Engine, acme: str) -> None:
    with pytest.raises(DBAPIError):
        with tenant_session(engine, acme) as session:
            r = repo(session, "del-guard")
            finding(session, r, "sha256:" + "4" * 64)
            session.flush()
            session.delete(r)
            session.flush()


# --- accesso --------------------------------------------------------------------------------------


def test_upsert_is_idempotent_and_refreshes_only_the_display_name(
    engine: Engine, acme: str
) -> None:
    with tenant_session(engine, acme) as session:
        first = repo(session, "ups", "acme/old-name")
        second = repo(session, "ups", "acme/new-name")
        assert first.id == second.id and second.name == "acme/new-name"
        assert (second.tier, second.internet_facing) == (None, None)  # nessun valore inventato


def test_service_context_records_who_and_when(engine: Engine, acme: str) -> None:
    with tenant_session(engine, acme) as session:
        r = repo(session, "svc")
        done = stores.set_service_context(
            session,
            r.id,
            tier=2,
            internet_facing=True,
            catalog_id="shop",
            actor="https://idp|root",
            now=NOW,
        )
        assert done is not None and (done.tier, done.updated_by, done.updated_at) == (
            2,
            "https://idp|root",
            NOW,
        )
        assert (
            stores.set_service_context(
                session,
                uuid.uuid4(),
                tier=1,
                internet_facing=None,
                catalog_id=None,
                actor="x",
                now=NOW,
            )
            is None
        )


def test_repositories_page_by_creation_order(engine: Engine) -> None:
    schema = stores.create_tenant(engine, "paging").schema
    with tenant_session(engine, schema) as session:
        ids = [repo(session, f"p{i}", f"r{i}").id for i in range(5)]
    with tenant_session(engine, schema) as session:
        first = stores.list_repositories(session, limit=2)
        second = stores.list_repositories(session, limit=2, after=first[-1].id)
        rest = stores.list_repositories(session, limit=10, after=second[-1].id)
        assert [r.id for r in first + second + rest] == ids


def test_scans_come_most_recent_first_with_a_stable_cursor(engine: Engine) -> None:
    schema = stores.create_tenant(engine, "scans").schema
    with tenant_session(engine, schema) as session:
        r = repo(session, "s1")
        made = [
            scan_for(session, r, f"{i:x}" * 64, at=NOW + timedelta(minutes=i)) for i in range(1, 6)
        ]
        rid = r.id
        expected = [s.id for s in reversed(made)]
    with tenant_session(engine, schema) as session:
        first = stores.list_scans(session, rid, limit=2)
        nxt = stores.list_scans(session, rid, limit=2, before=(first[-1].started_at, first[-1].id))
        rest = stores.list_scans(session, rid, limit=10, before=(nxt[-1].started_at, nxt[-1].id))
        assert [s.id for s in first + nxt + rest] == expected
        assert stores.get_scan(session, expected[0]) is not None
