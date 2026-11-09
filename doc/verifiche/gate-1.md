# Gate 1

Regola di misura e repository pilota (X-01). Decisione D-0009-B dell'utente, 2026-11-09. Si registrano solo durate e conteggi: i report dei pilota sono riservati e non si committano.

## Regola di misura

- Macchina di riferimento: il PC dell'utente, con le specifiche qui sotto.
- Scansione completa con `--offline` e snapshot dei feed fissato prima della misura. La sincronizzazione dei feed è esclusa dai 10 minuti e misurata a parte.
- Durata: `duration_seconds` del report, per ciascun pilota. Costruzione e firma delle immagini sono escluse.
- Configurazione: la policy di licenze di `.code-analyzer.yml` (X-03, D-0013), con quel file escluso dai finding.

## Macchina di riferimento

| Voce | Valore |
| --- | --- |
| CPU | Intel Core i9-10900K, 10 core, 20 thread |
| Memoria | 60 GiB |
| Disco | NVMe, ext4 |
| Sistema | Linux 7.0.0-43-generic |
| Docker | 27.3.1 |

## Snapshot dei feed

| Voce | Valore |
| --- | --- |
| Creato il | 2026-11-09T05:36:56Z |
| Database trivy aggiornato il | 2026-11-08T12:51:20Z |
| SHA-256 di `SNAPSHOT.json` | `5ef25e8599fcd5208b9461d5e07853227fbbdfb57b6f4fa5371f6e7fe1a222dd` |

## Repository pilota

Clone completo, nessuna modifica ai file versionati.

| Pilota | Commit | Data | File versionati | Dimensione | Linguaggi principali | Symlink versionati |
| --- | --- | --- | --- | --- | --- | --- |
| `fastapi/full-stack-fastapi-template` | `aabb90126964a164e02aff39e7c385bb0598236d` | 2026-11-03 | 252 | 9,8 MB | TypeScript, Python | 4 |
| `excalidraw/excalidraw` | `701b901a0f1ba3d0b390d9cdf63d112e25abac4b` | 2026-11-05 | 1.328 | 167 MB | TypeScript | 0 |
| `saleor/saleor` | `1d707dcf6127b098c187a181e5ee344017cdb064` | 2026-11-06 | 4.730 | 315 MB | Python | 2 |

## Misura (X-04)

2026-11-09. CLI impacchettata da `deploy/docker/package-cli.sh`, firma verificata, immagini sul registry locale, cloni su disco, `--offline`, snapshot sopra.

| Pilota | Stato | Durata | Finding | Critici | Alti | Medi | Bassi | `gate --fail-on critico,alto` |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `full-stack-fastapi-template` | `complete` | 19,7 s | 642 | 1 | 24 | 439 | 178 | 1 |
| `excalidraw/excalidraw` | `complete` | 146,2 s | 1.508 | 8 | 175 | 1.297 | 28 | 1 |
| `saleor/saleor` | `complete` | 247,7 s | 47.718 | 1 | 83 | 323 | 47.311 | 1 |

Il plugin più lento è scancode: 223,9 s su saleor. Su excalidraw bandit è saltato per linguaggio non rilevato.

Sincronizzazione dei feed, misurata a parte su un repository minimo con cache vuota: 23 s complessivi, 1,9 GB scaricati.

Configurazione per i pilota: oltre alla policy di licenze, `paths.exclude` su 6 symlink innocui, altrimenti il report è `partial` per la regola `workspace-symlinks`: 4 in `.agents/skills` e `.claude/skills` di full-stack-fastapi-template, rotti in un clone pulito perché puntano a `.venv`; `CLAUDE.md` e `saleor/graphql/CLAUDE.md` di saleor, che puntano ad `AGENTS.md`, analizzato al suo posto.

Rumore da rivedere in Fase 2: su saleor 47.276 finding su 47.718 sono `B101` di bandit.

Da completare per X-04: conferma dei limiti di byte (tmpfs di `/out`, `FEEDS_MIN_FREE_BYTES`, `DEFAULT_MAX_BYTES`, costo dei container in più).

## Auto-analisi (X-05)

2026-11-09, clone pulito del commit `f01a7276a95fe6f5df56ea3c71f7085685a9b5a2`. Stato `complete`, 41,0 s, tutti i plugin `ok`, 2.241 finding. **Non superata:** `gate --fail-on critico,alto` esce con 1 per 25 finding (14 critici, 11 alti), tutti `ca.license` su file che citano identificatori di licenza (documentazione, test, avvisi di terze parti). Fixture e casi vulnerabili sono esclusi da `.code-analyzer.yml`.
