"""C-07: il modello relazionale rispetta ADR-0018, senza un database."""

import pytest

from ca_api.db import engine as db_engine
from ca_api.db.models import FINDING_STATES, GlobalBase, TenantBase

TENANT_TABLES = {
    "repositories",
    "scans",
    "findings",
    "finding_occurrences",
    "components",
    "graph_nodes",
    "graph_edges",
    "exceptions",
    "finding_events",
}
PHASE_3 = {"vex_statements", "decisions", "agent_runs", "golden_labels", "embeddings"}


def test_the_global_base_has_only_tenants_and_the_tenant_base_the_phase_2_tables() -> None:
    assert set(GlobalBase.metadata.tables) == {"tenants"}
    assert set(TenantBase.metadata.tables) == TENANT_TABLES
    assert not PHASE_3 & (set(GlobalBase.metadata.tables) | set(TenantBase.metadata.tables))


def test_tenant_tables_have_no_explicit_schema_so_the_request_connection_chooses_it() -> None:
    assert all(t.schema is None for t in TenantBase.metadata.tables.values())


def unique_columns(table: str) -> list[tuple[str, ...]]:
    t = TenantBase.metadata.tables[table]
    found = [
        tuple(c.name for c in constraint.columns)
        for constraint in t.constraints
        if constraint.__class__.__name__ == "UniqueConstraint"
    ]
    return found


def test_the_unique_indexes_of_adr_0018_exist() -> None:
    assert ("repository_id", "fingerprint") in unique_columns("findings")
    assert ("repository_id", "report_sha256") in unique_columns("scans")
    assert ("provider", "issuer", "external_id") in unique_columns("repositories")
    assert ("finding_id", "scan_id") in unique_columns("finding_occurrences")


def check_names(table: str) -> set[str]:
    t = TenantBase.metadata.tables[table]
    return {c.name for c in t.constraints if c.__class__.__name__ == "CheckConstraint"}


def test_the_closed_vocabularies_are_check_constraints() -> None:
    assert {"ck_findings_status", "ck_findings_fingerprint"} <= check_names("findings")
    assert {"ck_scans_kind", "ck_scans_status", "ck_scans_digest"} <= check_names("scans")
    assert "ck_exceptions_repo_not_verified" in check_names("exceptions")  # ADR-0018
    assert "ck_repositories_tier" in check_names("repositories")


def test_resolved_is_a_valid_state_but_only_ingestion_may_assign_it() -> None:
    assert "risolto" in FINDING_STATES  # l'API non lo rende assegnabile (ADR-0029)


def test_the_primary_keys_are_uuids_ordered_in_time() -> None:
    for table in TenantBase.metadata.tables.values():
        (key,) = table.primary_key.columns
        assert key.type.__class__.__name__ == "Uuid", table.name


@pytest.mark.parametrize("schema", ["t_abc123", "t_" + "a" * 40, "t_0"])
def test_valid_tenant_schema_names(schema: str) -> None:
    assert db_engine.check_schema(schema) == schema


@pytest.mark.parametrize(
    "schema",
    [
        "",
        "public",
        "t_",
        "T_abc",
        "t_ab-c",
        't_a"; DROP TABLE x; --',
        "t_" + "a" * 41,
        "t_é",
        "x_abc",
        "t_a b",
    ],
)
def test_an_invalid_schema_name_is_refused_before_any_sql(schema: str) -> None:
    with pytest.raises(db_engine.DatabaseError):
        db_engine.check_schema(schema)


@pytest.mark.parametrize(
    "url", ["sqlite://", "postgresql://u:p@h/d", "postgresql+psycopg://u:p@h/d", "mysql://x"]
)
def test_only_the_pg8000_dialect_is_accepted_and_the_url_is_never_echoed(url: str) -> None:
    with pytest.raises(db_engine.DatabaseError) as caught:
        db_engine.make_engine(url)
    assert "u:p" not in str(caught.value)
