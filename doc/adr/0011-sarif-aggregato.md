# ADR-0011: Struttura del SARIF aggregato

- Stato: Accettato il 2026-11-10 alla chiusura della Fase 1 (X-07). Prove indicate in "Revisione A-01" presenti: SARIF aggregato in `ca_core/sarif/aggregate.py` (K-14); test unitari, di contratto ed E2E verdi
- Data: 2026-11-08
- Decisione umana richiesta: no (scelta tecnica; da confermare in revisione)
- Riferimenti: §1, §5 passo 10, §12.1, §13

## Contesto

§13 chiede un SARIF aggregato senza definirlo. Il file è destinato a `upload-sarif`, e i finding fusi da più scanner non appartengono a un solo tool.

## Opzioni

1. Un `run` per scanner: fedele all'origine, ma ripresenta i duplicati e i consumatori come GitHub possono limitare più run nella stessa categoria.
2. Un solo `run` con driver `code-analyzer` e origini nelle estensioni e nelle proprietà.

## Raccomandazione

Opzione 2.

- `tool.driver.name = "code-analyzer"`; gli scanner compaiono in `tool.extensions` con versione.
- Un `result` per finding deduplicato; `partialFingerprints["codeAnalyzer/v1"]` contiene il fingerprint.
- `level`: critico e alto `error`, medio `warning`, basso `note`.
- `properties`: `level` (valori di §4.1), `level_source`, `category`, `tools`, `status`.
- `properties.security-severity` solo se esiste un CVSS, mai inventato.
- Dipendenze: la posizione è il manifest o lockfile in cui compare il pacchetto; purl in `properties`. Finding senza posizione (`health`): compaiono nel report e in `invocations[].toolExecutionNotifications`, non come `result`.
- Finding con eccezione attiva: `suppressions` con la motivazione e `kind: external`.
- URI relativi alla radice; il segreto non compare in `snippet` né in `message` (ADR-0012).
- Output deterministico (ordinamento stabile) e validato contro lo schema SARIF 2.1.0 prima della scrittura.

I vincoli attuali di GitHub Code Scanning su dimensioni, numero di risultati e run vanno verificati quando si realizza l'Action in Fase 2.

## Conseguenze

- Il dettaglio di origine resta nel report e nelle proprietà, non nel `run`.
- Il layout è un contratto pubblico e deve avere test di contratto.

## Revisione A-01

Data: 2026-11-08. Resta `Proposto`: nessun codice scrive ancora il SARIF aggregato. Il testo non contraddice i contratti esistenti: `level`, `level_source`, `category`, `tools` e `status` esistono nel modello `Finding`. Passa ad `Accettato` con K-14 verde.
