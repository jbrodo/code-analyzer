# Regole per gli agenti di coding

Fonte: `doc/PROJECT.md` §16. Le decisioni sono in `doc/adr/`, il lavoro di Fase 1 in `doc/plan/fase-1.md`.

## Regole

1. Ogni modifica a modelli o schemi aggiorna anche `schemas/` e i test di contratto.
2. Nessuna dipendenza nuova senza verificarne licenza e manutenzione; aggiornare l'SBOM.
3. Le soglie e i pesi di scoring stanno in configurazione, mai hard-coded nella logica.
4. Ogni plugin nuovo include manifest, fixture e test di contratto.
5. Prima di ogni PR passano tutti i comandi di verifica elencati sotto.
6. Messaggi di commit: Conventional Commits.
7. Nessuna chiamata a servizi esterni nei test.

Il verso delle dipendenze tra i pacchetti è definito da ADR-0001 e imposto da `lint-imports`. I modelli di `ca-core` sono la fonte degli schemi in `schemas/` (ADR-0003): `schema_export --check` segnala ogni divergenza.

## Comandi di verifica

```
uv run ruff check .
uv run ruff format --check .
uv run mypy packages
uv run pytest -q
uv run lint-imports
uv run python -m ca_core.schema_export --check
```

I comandi `pnpm --dir web lint` e `pnpm --dir web test` sono omessi finché `web/` non esiste.
