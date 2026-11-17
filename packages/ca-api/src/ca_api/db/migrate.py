"""Migrazioni: una catena globale (`tenants`) e una per ogni schema di tenant (C-07, ADR-0018).

Alembic con due rami: `global` e `tenant`. Ogni schema di tenant ha la propria tabella
`alembic_version`, quindi un tenant si migra, e si annulla, da solo. Le migrazioni sono DDL
esplicito e congelato: non leggono i modelli, così una modifica successiva dei modelli non riscrive
la storia.
"""

from pathlib import Path

from alembic import command
from alembic.config import Config
from sqlalchemy import Engine, text

from ca_api.db.engine import check_schema

MIGRATIONS = Path(__file__).with_name("migrations")


def _config(engine: Engine, *, kind: str, schema: str | None = None) -> Config:
    config = Config()
    config.set_main_option("script_location", str(MIGRATIONS))
    config.attributes["engine"] = engine
    config.attributes["kind"] = kind
    config.attributes["schema"] = check_schema(schema) if schema else None
    return config


def upgrade_global(engine: Engine) -> None:
    command.upgrade(_config(engine, kind="global"), "global@head")


def downgrade_global(engine: Engine, revision: str = "base") -> None:
    command.downgrade(_config(engine, kind="global"), f"global@{revision}")


def upgrade_tenant(engine: Engine, schema: str) -> None:
    """Crea lo schema se manca e porta le tabelle del tenant all'ultima revisione."""
    check_schema(schema)
    with engine.begin() as connection:
        connection.execute(text(f'CREATE SCHEMA IF NOT EXISTS "{schema}"'))  # nome validato sopra
    command.upgrade(_config(engine, kind="tenant", schema=schema), "tenant@head")


def downgrade_tenant(engine: Engine, schema: str, revision: str = "base") -> None:
    command.downgrade(_config(engine, kind="tenant", schema=schema), f"tenant@{revision}")
