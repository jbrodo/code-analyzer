# graph-js-ts (fixture F-01 della Fase 2)

Progetto TypeScript con gli stessi casi di `graph-python`, in `src/` con l'alias `@app/*` di
`tsconfig.json`. **Non va installato né eseguito.**

Gli attesi sono in `expected-graph.yaml` (formato: `../../expected-graph.schema.json`), scritti dal
progetto e non copiati dall'output dell'estrattore. `src/stable/core.test.ts` è un modulo di test:
importa due moduli ma non deve entrare in metriche né smell (ADR-0020). I componenti di
`src/apps/` sono file `.tsx`, per provare anche quella grammatica.

| Caso | Dove | Atteso |
| --- | --- | --- |
| Ciclo di moduli | `src/billing/a.ts` → `b` → `c` → `a` | un ciclo di 3 moduli |
| Ciclo di pacchetti | `src/billing` ↔ `src/ledger` (`a` → `ledger/x`, `ledger/y` → `b`) | un ciclo di 2 pacchetti |
| Negativo dei cicli | `src/catalog/item.ts` → `price` → `tax` | nessun ciclo |
| Hub | `src/core/hub.ts`: 4 moduli lo importano, lui ne importa 4 | hub, con soglia minima di grado 6 |
| Negativi dell'hub | `src/util/helpers.ts`, `src/main.ts`, `src/billing/c.ts` | non sono hub |
| Dipendenza instabile | `src/stable` (I 0,2) → `src/volatile` (I 0,8) | una dipendenza instabile |
| Negativi | `src/svc*` → `src/stable`, `src/volatile` → `src/ext*` | nessuna dipendenza instabile |

Gli archi interni sono 33, tra alias `@app/…` e import relativi.
