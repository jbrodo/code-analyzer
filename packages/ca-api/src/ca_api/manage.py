"""Gestione del server (B-02, B-03): migrazioni e tenant. `python -m ca_api.manage <comando>`.

La stringa di connessione viene solo dall'ambiente (`CA_API_DATABASE_URL`): contiene la password e
non compare in nessun messaggio. Un tenant si crea qui, non con una richiesta dell'API: la mappa dei
proprietari delle pipeline (ADR-0019) lo nomina, e l'API non ne crea.
"""

import argparse
import sys
from collections.abc import Sequence

from sqlalchemy.exc import SQLAlchemyError

from ca_api.config import Settings
from ca_api.db import migrate, stores
from ca_api.db.engine import DatabaseError, make_engine


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="ca_api.manage", description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser(
        "migrate", help="porta lo schema globale e quelli dei tenant all'ultima revisione"
    )
    create = commands.add_parser("create-tenant", help="crea un tenant e il suo schema")
    create.add_argument("name")
    args = parser.parse_args(argv)
    settings = Settings.from_env()
    if not settings.database_url:
        print("CA_API_DATABASE_URL non impostata", file=sys.stderr)
        return 2
    try:
        engine = make_engine(settings.database_url)
        migrate.upgrade_global(engine)
        if args.command == "create-tenant":
            tenant = stores.create_tenant(engine, args.name)
            print(f"tenant {tenant.name}: schema {tenant.schema}")
        else:
            for tenant in stores.list_tenants(engine):
                migrate.upgrade_tenant(engine, tenant.schema)
            print("migrazioni applicate")
    except (DatabaseError, SQLAlchemyError, OSError, ValueError) as exc:
        print(f"errore: {exc.__class__.__name__}", file=sys.stderr)  # mai la stringa di connessione
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
