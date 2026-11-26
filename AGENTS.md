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
8. Nei documenti le licenze si descrivono a parole, senza identificatori: l'auto-analisi le rileva come finding di licenza. Lo controlla l'hook `license-ids`; se un identificatore serve davvero, prima un'eccezione approvata dall'utente.
9. Le eccezioni nuove in `.code-analyzer.yml` vanno in una PR a sé, unita prima del codice che le richiede: una PR non applica le eccezioni che introduce (gate di auto-analisi).
10. Ogni immagine di container usata nelle prove è fissata per digest, in `tests/integration/container_images.py`; mai un tag mobile.
11. All'inizio di ogni ondata si unisce `main` nel ramo di lavoro, non solo alla fine.

Il verso delle dipendenze tra i pacchetti è definito da ADR-0001 e imposto da `lint-imports`. I modelli di `ca-core` sono la fonte degli schemi in `schemas/` (ADR-0003): `schema_export --check` segnala ogni divergenza.

## Comandi di verifica

```
uv run ruff check .
uv run ruff format --check .
uv run ty check packages --error-on-warning
uv run pytest -q
uv run lint-imports
uv run python -m ca_core.schema_export --check
uv run python -m ca_api.openapi_export --check
bun run --cwd web lint
bun run --cwd web test
```

`web/` usa Bun 1.4.4, fissato in `web/package.json` (`packageManager`), e Node 24; prima dei due comandi serve `bun install --cwd web --frozen-lockfile`. La CI esegue anche i controlli web.
