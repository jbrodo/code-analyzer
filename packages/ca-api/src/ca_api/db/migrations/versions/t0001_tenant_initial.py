"""Prima revisione: tabelle di un tenant (ADR-0018). DDL esplicito e congelato (C-07, ADR-0018).

Non legge i modelli: una modifica successiva dei modelli non riscrive questa storia.
"""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "t0001"
down_revision = None
branch_labels = ("tenant",)
depends_on = None


def upgrade() -> None:
    op.create_table(
        "repositories",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("provider", sa.String(length=16), nullable=False),
        sa.Column("issuer", sa.String(length=500), nullable=False),
        sa.Column("external_id", sa.String(length=200), nullable=False),
        sa.Column("name", sa.String(length=500), nullable=False),
        sa.Column("default_branch", sa.String(length=200), nullable=True),
        sa.Column("tier", sa.SmallInteger(), nullable=True),
        sa.Column("internet_facing", sa.Boolean(), nullable=True),
        sa.Column("catalog_id", sa.String(length=200), nullable=True),
        sa.Column("current_scan_id", sa.Uuid(), nullable=True),
        sa.Column("updated_by", sa.String(length=300), nullable=True),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.CheckConstraint(
            "provider IN ('github', 'gitlab')", name=op.f("ck_repositories_provider")
        ),
        sa.CheckConstraint("tier BETWEEN 1 AND 3", name=op.f("ck_repositories_tier")),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_repositories")),
        sa.UniqueConstraint(
            "provider",
            "issuer",
            "external_id",
            name=op.f("uq_repositories_provider_issuer_external_id"),
        ),
    )
    op.create_table(
        "findings",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("repository_id", sa.Uuid(), nullable=False),
        sa.Column("fingerprint", sa.String(length=71), nullable=False),
        sa.Column("category", sa.String(length=32), nullable=False),
        sa.Column("rule_id", sa.String(length=200), nullable=False),
        sa.Column("title", sa.Text(), nullable=False),
        sa.Column("data", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=True),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("owner", sa.String(length=200), nullable=True),
        sa.Column("due_date", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.CheckConstraint(
            "fingerprint ~ '^sha256:[0-9a-f]{64}$'", name=op.f("ck_findings_fingerprint")
        ),
        sa.CheckConstraint(
            "status IN ('aperto', 'in_corso', 'accettato', 'falso_positivo', 'risolto')",
            name=op.f("ck_findings_status"),
        ),
        sa.ForeignKeyConstraint(
            ["repository_id"],
            ["repositories.id"],
            name=op.f("fk_findings_repository_id_repositories"),
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_findings")),
        sa.UniqueConstraint(
            "repository_id", "fingerprint", name=op.f("uq_findings_repository_id_fingerprint")
        ),
    )
    op.create_index(
        "ix_findings_repository_id_status", "findings", ["repository_id", "status"], unique=False
    )
    op.create_table(
        "scans",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("repository_id", sa.Uuid(), nullable=False),
        sa.Column("commit", sa.String(length=64), nullable=False),
        sa.Column("ref", sa.String(length=500), nullable=True),
        sa.Column("kind", sa.String(length=8), nullable=False),
        sa.Column("pull_request", sa.Integer(), nullable=True),
        sa.Column("base_commit", sa.String(length=64), nullable=True),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("duration_seconds", sa.Float(), nullable=False),
        sa.Column("report_sha256", sa.String(length=64), nullable=False),
        sa.Column("report_schema_version", sa.String(length=16), nullable=False),
        sa.Column("scoring_config_version", sa.String(length=64), nullable=True),
        sa.Column("uploaded_by", sa.String(length=300), nullable=False),
        sa.Column("artifact_keys", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column(
            "received_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.CheckConstraint(
            "(kind = 'pr') = (base_commit IS NOT NULL)", name=op.f("ck_scans_pr_has_base")
        ),
        sa.CheckConstraint("kind IN ('pr', 'full')", name=op.f("ck_scans_kind")),
        sa.CheckConstraint("report_sha256 ~ '^[0-9a-f]{64}$'", name=op.f("ck_scans_digest")),
        sa.CheckConstraint("status IN ('complete', 'partial')", name=op.f("ck_scans_status")),
        sa.ForeignKeyConstraint(
            ["repository_id"], ["repositories.id"], name=op.f("fk_scans_repository_id_repositories")
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_scans")),
        sa.UniqueConstraint(
            "repository_id", "report_sha256", name=op.f("uq_scans_repository_id_report_sha256")
        ),
    )
    op.create_index(
        "ix_scans_repository_id_started_at", "scans", ["repository_id", "started_at"], unique=False
    )
    op.create_table(
        "components",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("repository_id", sa.Uuid(), nullable=False),
        sa.Column("scan_id", sa.Uuid(), nullable=False),
        sa.Column("purl", sa.String(length=2048), nullable=False),
        sa.Column("name", sa.String(length=500), nullable=False),
        sa.Column("version", sa.String(length=200), nullable=True),
        sa.Column("licenses", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.ForeignKeyConstraint(
            ["repository_id"],
            ["repositories.id"],
            name=op.f("fk_components_repository_id_repositories"),
        ),
        sa.ForeignKeyConstraint(
            ["scan_id"], ["scans.id"], name=op.f("fk_components_scan_id_scans")
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_components")),
    )
    op.create_index("ix_components_scan_id", "components", ["scan_id"], unique=False)
    op.create_table(
        "exceptions",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("finding_id", sa.Uuid(), nullable=False),
        sa.Column("origin", sa.String(length=16), nullable=False),
        sa.Column("reason", sa.Text(), nullable=False),
        sa.Column("expires", sa.Date(), nullable=False),
        sa.Column("approved_by", sa.String(length=300), nullable=False),
        sa.Column("approved_by_verified", sa.Boolean(), nullable=False),
        sa.Column("scan_id", sa.Uuid(), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint(
            "origin = 'server' OR NOT approved_by_verified",
            name=op.f("ck_exceptions_repo_not_verified"),
        ),
        sa.CheckConstraint("origin IN ('server', 'repository')", name=op.f("ck_exceptions_origin")),
        sa.ForeignKeyConstraint(
            ["finding_id"], ["findings.id"], name=op.f("fk_exceptions_finding_id_findings")
        ),
        sa.ForeignKeyConstraint(
            ["scan_id"], ["scans.id"], name=op.f("fk_exceptions_scan_id_scans")
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_exceptions")),
    )
    op.create_index("ix_exceptions_finding_id", "exceptions", ["finding_id"], unique=False)
    op.create_table(
        "finding_events",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("finding_id", sa.Uuid(), nullable=False),
        sa.Column(
            "at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False
        ),
        sa.Column("actor", sa.String(length=300), nullable=False),
        sa.Column("action", sa.String(length=64), nullable=False),
        sa.Column("from_state", sa.String(length=16), nullable=True),
        sa.Column("to_state", sa.String(length=16), nullable=True),
        sa.Column("reason", sa.Text(), nullable=True),
        sa.CheckConstraint(
            "from_state IN ('aperto', 'in_corso', 'accettato', 'falso_positivo', 'risolto')",
            name=op.f("ck_finding_events_from_state"),
        ),
        sa.CheckConstraint(
            "to_state IN ('aperto', 'in_corso', 'accettato', 'falso_positivo', 'risolto')",
            name=op.f("ck_finding_events_to_state"),
        ),
        sa.ForeignKeyConstraint(
            ["finding_id"], ["findings.id"], name=op.f("fk_finding_events_finding_id_findings")
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_finding_events")),
    )
    op.create_index(
        "ix_finding_events_finding_id_at", "finding_events", ["finding_id", "at"], unique=False
    )
    op.create_table(
        "finding_occurrences",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("finding_id", sa.Uuid(), nullable=False),
        sa.Column("scan_id", sa.Uuid(), nullable=False),
        sa.Column("commit", sa.String(length=64), nullable=False),
        sa.Column("path", sa.String(length=4096), nullable=True),
        sa.Column("start_line", sa.Integer(), nullable=True),
        sa.Column("level", sa.String(length=16), nullable=True),
        sa.Column("level_source", sa.String(length=24), nullable=True),
        sa.Column("evidence", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("report_status", sa.String(length=16), nullable=True),
        sa.Column("baseline_state", sa.String(length=16), nullable=True),
        sa.Column("a_score", sa.Float(), nullable=True),
        sa.Column("a_level", sa.String(length=16), nullable=True),
        sa.Column("a_factors", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column("b_score", sa.Float(), nullable=True),
        sa.Column("b_level", sa.String(length=16), nullable=True),
        sa.Column("b_factors", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.CheckConstraint(
            "baseline_state IN ('new', 'existing')",
            name=op.f("ck_finding_occurrences_baseline_state"),
        ),
        sa.ForeignKeyConstraint(
            ["finding_id"], ["findings.id"], name=op.f("fk_finding_occurrences_finding_id_findings")
        ),
        sa.ForeignKeyConstraint(
            ["scan_id"], ["scans.id"], name=op.f("fk_finding_occurrences_scan_id_scans")
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_finding_occurrences")),
        sa.UniqueConstraint(
            "finding_id", "scan_id", name=op.f("uq_finding_occurrences_finding_id_scan_id")
        ),
    )
    op.create_index(
        "ix_finding_occurrences_scan_id", "finding_occurrences", ["scan_id"], unique=False
    )
    op.create_table(
        "graph_edges",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("scan_id", sa.Uuid(), nullable=False),
        sa.Column("source", sa.String(length=4096), nullable=False),
        sa.Column("target", sa.String(length=4096), nullable=False),
        sa.Column("external", sa.Boolean(), nullable=False),
        sa.Column("imports", sa.Integer(), nullable=False),
        sa.Column("dynamic", sa.Boolean(), nullable=False),
        sa.Column("type_only", sa.Boolean(), nullable=False),
        sa.Column("confidence", sa.String(length=16), nullable=False),
        sa.CheckConstraint(
            "confidence IN ('dichiarato', 'dedotto', 'osservato')",
            name=op.f("ck_graph_edges_confidence"),
        ),
        sa.ForeignKeyConstraint(
            ["scan_id"], ["scans.id"], name=op.f("fk_graph_edges_scan_id_scans")
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_graph_edges")),
        sa.UniqueConstraint(
            "scan_id",
            "source",
            "external",
            "target",
            name=op.f("uq_graph_edges_scan_id_source_external_target"),
        ),
    )
    op.create_table(
        "graph_nodes",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("scan_id", sa.Uuid(), nullable=False),
        sa.Column("path", sa.String(length=4096), nullable=False),
        sa.Column("language", sa.String(length=16), nullable=False),
        sa.Column("parse", sa.String(length=16), nullable=False),
        sa.Column("test", sa.Boolean(), nullable=False),
        sa.Column("churn", sa.BigInteger(), nullable=True),
        sa.Column("metrics", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.ForeignKeyConstraint(
            ["scan_id"], ["scans.id"], name=op.f("fk_graph_nodes_scan_id_scans")
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_graph_nodes")),
        sa.UniqueConstraint("scan_id", "path", name=op.f("uq_graph_nodes_scan_id_path")),
    )


def downgrade() -> None:
    op.drop_table("graph_nodes")
    op.drop_table("graph_edges")
    op.drop_index("ix_finding_occurrences_scan_id", table_name="finding_occurrences")
    op.drop_table("finding_occurrences")
    op.drop_index("ix_finding_events_finding_id_at", table_name="finding_events")
    op.drop_table("finding_events")
    op.drop_index("ix_exceptions_finding_id", table_name="exceptions")
    op.drop_table("exceptions")
    op.drop_index("ix_components_scan_id", table_name="components")
    op.drop_table("components")
    op.drop_index("ix_scans_repository_id_started_at", table_name="scans")
    op.drop_table("scans")
    op.drop_index("ix_findings_repository_id_status", table_name="findings")
    op.drop_table("findings")
    op.drop_table("repositories")
