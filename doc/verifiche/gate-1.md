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
