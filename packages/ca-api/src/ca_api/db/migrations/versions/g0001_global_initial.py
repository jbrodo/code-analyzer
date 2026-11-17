"""Prima revisione: tabella dei tenant. DDL esplicito e congelato (C-07, ADR-0018).

Non legge i modelli: una modifica successiva dei modelli non riscrive questa storia.
"""

import sqlalchemy as sa
from alembic import op

revision = "g0001"
down_revision = None
branch_labels = ("global",)
depends_on = None


def upgrade() -> None:
    op.create_table(
        "tenants",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("name", sa.String(length=100), nullable=False),
        sa.Column("schema", sa.String(length=43), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.CheckConstraint("schema ~ '^t_[a-z0-9_]{1,40}$'", name=op.f("ck_tenants_schema_name")),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_tenants")),
        sa.UniqueConstraint("name", name=op.f("uq_tenants_name")),
        sa.UniqueConstraint("schema", name=op.f("uq_tenants_schema")),
    )


def downgrade() -> None:
    op.drop_table("tenants")
