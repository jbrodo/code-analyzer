# ADR-0010: Contratto della CLI e artefatti di scansione

- Stato: Accettato il 2026-11-10 alla chiusura della Fase 1 (X-07). Prove indicate in "Revisione A-01" presenti: comandi `scan`, `gate`, `config validate` e `sbom` in `ca_cli` (K-13, L-02..L-05); test unitari, di contratto ed E2E verdi
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

## Revisione A-01

Data: 2026-11-08. Resta `Proposto`: il contratto del report c'è, la CLI no (`ca_cli` contiene solo `__init__.py`).

Confermato:

- `schemas/scan-report.schema.json` e `ScanReport` contengono tutti i campi elencati sopra, con il limite corretto da C-04: lo schema non legava `status` e `failure` agli esiti dei plugin.

Da provare:

- Comandi, flag ed exit: K-13, L-02, L-03, L-04, L-05, con T-07.

Precisazioni sul legame tra `status` e plugin:

- Il vincolo è in un solo verso: un plugin `failed` impone `partial`. `partial` senza plugin falliti resta valido, così una causa futura è un'aggiunta compatibile.
- ADR-0005 fa uscire il gate con 2 anche con `signature: skipped`, ma una firma saltata non è un plugin fallito e il report può essere `complete`. Lo gestisce il gate leggendo `plugins[].signature`, senza nuovi vincoli di schema (K-13).

## Emendamento per R-09: nome del report

Data: 2026-11-09. `publish` scrive `scan-report.json` e la CLI lo rinomina nel sink in `code-analyzer.report.json`: il nome stabilito qui vive in due punti, e chiunque altro usi `publish` otterrebbe il nome sbagliato.

Decisione: il nome pubblico è uno solo e sta nel passo che scrive. `ca_core.pipeline.publish.REPORT_NAME = "code-analyzer.report.json"`. `_CapturingSink` conserva solo i byte per lo stdout e non rinomina più. `ca_cli.scan.REPORT_FILE` resta come alias di `REPORT_NAME`, così `gate.DEFAULT_REPORT` non cambia. Lo schema resta `scan-report`, il nome del contratto e non del file. Nessun documento già prodotto da una CLI rilasciata è coinvolto.

## Emendamento per A-16 (2026-11-18): i comandi e le opzioni di Fase 2

Motivo: la sezione «Fuori da Fase 1» elencava ciò che mancava; ora esiste, con questi esiti.

| Comando | Novità | Exit |
| --- | --- | --- |
| `scan` | `--pr`, `--base COMMIT`, `--baseline FILE`, `--baseline-source`, `--pull-request N` (modalità PR e baseline, ADR-0025); `--variant A\|B` (ADR-0021); `--scoring-config FILE` e `CA_SCORING_CONFIG`; `--service-context FILE` (ADR-0028). Precedenza della variante: `--variant`, poi `scoring.variant`, poi il file di scoring | come prima |
| `gate` | Legge anche `gate.effective_mode`: con `new-findings-only` bloccano solo i finding nuovi | come prima |
| `notify --provider github` | Commento unico e check run sulla PR (ADR-0027) | 0 fatto o saltato con avviso, 2 errore; mai 1 |
| `export --format gitlab` | Report nativi di GitLab (SAST, dependency scanning, qualità del codice, CycloneDX portato alla 1.6) | 0, 2 |
| `upload --server URL` | Invia il report e, se ci sono, SARIF, SBOM e grafo al server con il token OIDC del provider CI (ADR-0016, ADR-0019) | 0 inviato o già presente, 2 errore |

Restano fuori: `sbom --format spdx`, `explain`, `plugin list|verify|run` e il comando `service-context` di ADR-0028 (l'endpoint del server c'è, il comando no). Il report ha le sezioni `scoring`, `enrichment`, `baseline` e `scan` (schema 1.3). L'Action e il componente GitLab chiamano `scan` e `gate` separati e `scan` non riceve `--fail-on` (ADR-0027, §12.1 corretto da A-17).
