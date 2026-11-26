"""Ambiente di Alembic: sceglie la catena (globale o di un tenant) dagli attributi della config."""

from alembic import context
from sqlalchemy import Engine

from ca_api.db.models import GlobalBase, TenantBase

config = context.config
engine: Engine = config.attributes["engine"]
kind: str = config.attributes["kind"]
schema: str | None = config.attributes["schema"]


def run() -> None:
    if kind == "tenant":
        assert schema is not None
        with engine.connect() as connection:
            connection = connection.execution_options(schema_translate_map={None: schema})
            context.configure(
                connection=connection,
                target_metadata=TenantBase.metadata,
                version_table="alembic_version",
                version_table_schema=schema,
                include_schemas=False,
            )
            with context.begin_transaction():
                context.run_migrations()
            connection.commit()
        return
    with engine.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=GlobalBase.metadata,
            version_table="alembic_version_global",
        )
        with context.begin_transaction():
            context.run_migrations()
        connection.commit()


run()
