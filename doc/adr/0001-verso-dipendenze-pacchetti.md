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

## Emendamento per A-16 (2026-11-18): i pacchetti di Fase 2

Motivo: la tabella sopra è quella di prima della Fase 2 e due righe non corrispondono più a ciò che il codice e `import-linter` impongono.

| Pacchetto | Può dipendere da | Cosa cambia |
| --- | --- | --- |
| `ca-cli` | `ca-core`, `ca-plugins`, `ca-graph`, `ca-integrations` | `ca-integrations` entra con ADR-0027: i commenti PR e i report di GitLab partono dalla CI, senza server. La regola «né Temporal, né FastAPI, né driver di database» resta. |
| `ca-api` | `ca-core` | Solo `ca-core`: senza Temporal (ADR-0016) non c'è `ca-workflows` da importare, e il server non importa plugin, container, grafo né integrazioni. |
| `ca-workflows` | — | Non esiste in Fase 2: la riga vale per la Fase 3, se mai servirà. |

I contratti di `import-linter` sono nove (`pyproject.toml`): dipendenze interne verso `ca_core`; `ca_core` senza framework, rete né processi; `ca_cli` senza server né database; `ca_graph`, `ca_integrations` e `ca_plugins` che non si importano tra loro; `ca_graph` senza rete né processi, con il parser solo nell'immagine di estrazione e il solo modulo della storia git che lancia un processo; il resto del mondo che non importa il parser; il parser che non importa il resto; `ca_api` che importa solo `ca_core`; nessun altro pacchetto che importa `ca_api`.
