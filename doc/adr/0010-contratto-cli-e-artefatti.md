# ADR-0010: Contratto della CLI e artefatti di scansione

- Stato: Proposto
- Data: 2026-11-08
- Decisione umana richiesta: no (scelta tecnica; da confermare in revisione)
- Riferimenti: §9.1, §12.1, §13; lacuna 9

## Contesto

L'Action di §12.1 passa `--fail-on` a `scan`, ma il flag esiste solo su `gate` (§9.1). `gate` non ha un input: senza database non sa cosa valutare. `--format` ha un solo valore, mentre servono SARIF per l'upload e dati per il gate; l'Action si aspetta `code-analyzer.sarif` senza alcuna opzione di output. Infine, nell'esempio di §12.1 un gate fallito dentro `scan` interromperebbe il job prima di `upload-sarif`.

## Opzioni

1. Aggiungere `--fail-on` a `scan` e tenere anche `gate`: due implementazioni della stessa semantica, e il problema dell'upload resta.
2. `scan` produce solo artefatti; `gate` è l'unico che decide, leggendo il report.

## Raccomandazione

Opzione 2.

| Comando | Fase 1 | Exit |
| --- | --- | --- |
| `scan [PATH] [--output-dir DIR] [--format table\|json\|sarif] [--min-isolation L] [--offline]` | Scrive sempre `code-analyzer.report.json` e `code-analyzer.sarif`; `--format` governa solo lo stdout | 0 report prodotto (anche parziale), 2 nessun report valido. Mai 1 |
| `sbom [PATH] --format cyclonedx [--output FILE]` | Solo syft | 0, 2 |
| `gate [--report FILE] [--fail-on LIST] [--allow-partial]` | Legge il report (ADR-0009) | 0 superato, 1 fallito, 2 errore o scansione parziale |
| `config validate [PATH]` | Schema e controlli semantici (ADR-0014) | 0, 2 |

Fuori da Fase 1: `--pr`, `--base`, `--variant`, `sbom --format spdx`, `explain`, `plugin list|verify|run`. Sono omessi, non presenti e inattivi: §13 elenca solo CycloneDX e i quattro comandi.

Il report (`schemas/scan-report.schema.json`) contiene: versione schema, stato `complete | partial`, repository e commit, configurazione di gate effettiva, per ogni plugin versione, digest, firma, isolamento, durata, esito e snapshot del feed, i finding e le eccezioni applicate. Il report fornisce anche le durate richieste dalla Definition of Done di §17, senza stack OpenTelemetry in Fase 1.

Forma dell'Action in Fase 2 (§12.1 da correggere): `scan` e `gate` separati, con upload SARIF prima di `gate` o con `if: always()`; `server-url` e `variant` restano senza effetto finché non esiste un server o la Variante.

## Conseguenze

- Un'unica implementazione del gate e un artefatto ispezionabile.
- Comando in più nelle pipeline: l'Action dovrà incapsulare i passi.
- `schemas/` ottiene uno schema in più rispetto a §3.
- I file di output vanno esclusi dalle scansioni (ADR-0014).
