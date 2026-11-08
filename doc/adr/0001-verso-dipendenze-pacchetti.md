# ADR-0001: Verso delle dipendenze tra i pacchetti

- Stato: Accettato
- Data: 2026-11-08
- Decisione umana richiesta: no
- Riferimenti: §2, §3, §10.1, ruolo `architect`

## Contesto

§3 elenca i pacchetti ma non dice chi può importare chi. La regola "`ca-core` non dipende da framework o infrastruttura" e i `Protocol` di §6 e §10.1 implicano un'architettura a porte e adattatori, con dipendenze verso l'interno. §3 però colloca `scoring/feeds/` (EPSS, KEV, OSV) dentro `ca-core`, cioè I/O di rete nel nucleo.

## Opzioni

1. Regola solo per convenzione: si degrada al primo import comodo.
2. Regola scritta e verificata in CI.

## Decisione

Opzione 2. Dipendenze interne ammesse:

| Pacchetto | Può dipendere da | Fase |
| --- | --- | --- |
| `ca-core` | nessun pacchetto interno | 1 |
| `ca-plugins` | `ca-core` | 1 |
| `ca-cli` | `ca-core`, `ca-plugins`; poi `ca-graph` | 1 |
| `ca-graph` | `ca-core` | 2 |
| `ca-integrations` | `ca-core` | 2 |
| `ca-decision` | `ca-core` | 3 |
| `ca-agents` | `ca-core`, `ca-decision` | 3 |
| `ca-workflows` | tutti i precedenti tranne `ca-cli` e `ca-api` | 2 |
| `ca-api` | `ca-core`, `ca-workflows` | 2 |

Regole:

- `ca-core` usa solo la libreria standard e librerie dati senza I/O di rete (Pydantic, jsonschema, purl, YAML). Non importa Temporal, FastAPI, SQLAlchemy, client HTTP, client S3 né `subprocess`.
- `ca-cli` non importa Temporal, FastAPI né driver di database: l'immagine CLI deve restare autonoma.
- Le porte (`Protocol`) stanno in `ca-core`; gli adattatori nei pacchetti esterni. Il cablaggio avviene solo nelle radici di composizione (`ca-cli`, poi `ca-workflows` e `ca-api`).
- In `ca_core/scoring/feeds/` resta solo la porta dei feed e il modello dei dati; il client di rete è un adattatore esterno (Fase 2).
- Verifica in CI con `import-linter`, che è uno strumento di sviluppo e non un componente a runtime.

## Conseguenze

- Il grafo è aciclico e i test di `ca-core` non richiedono infrastruttura.
- Il primo task del monorepo include il contratto `import-linter`.
- L'albero di §3 va letto con la correzione su `scoring/feeds/`.
