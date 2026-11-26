# ADR-0002: Motore di scansione indipendente da Temporal

- Stato: Accettato il 2026-11-10 alla chiusura della Fase 1 (X-07). Prove indicate in "Revisione A-01" presenti: passi della pipeline in `ca_core/pipeline/` (K-15..K-18) e parallelismo nell'adattatore (R-07); test unitari, di contratto ed E2E verdi
- Data: 2026-11-08
- Decisione umana richiesta: no (scelta tecnica; da confermare in revisione)
- Riferimenti: §2, §3, §5, §13

## Contesto

§5 descrive la pipeline solo come `ScanWorkflow` Temporal, ma §2 chiede lo "stesso motore in CI, server e locale" e la Fase 1 consegna una CLI senza server. §3 non indica dove risieda la logica della pipeline fuori da `ca-workflows`.

## Opzioni

1. Pipeline in `ca-cli`, riscritta in `ca-workflows` in Fase 2: due motori, contro §2.
2. Nuovo pacchetto `ca-engine`: pulito, ma aggiunge un componente fuori da §3 per poche funzioni.
3. Passi della pipeline in `ca-core`, puri rispetto alle porte; `ca-cli` li esegue in sequenza, `ca-workflows` li avvolge in activity.

## Raccomandazione

Opzione 3.

- Nuovi moduli: `ca_core/pipeline/` (passi) e `ca_core/ports.py`.
- Porte di Fase 1: `PluginExecutor`, `SourceReader`, `ArtifactSink`, `Clock`.
- Ogni passo è una funzione con ingressi e uscite serializzabili, idempotente e invocabile da sola, così da diventare un'activity senza modifiche. Non esiste un unico `run()` monolitico nel nucleo.
- Il parallelismo tra plugin è responsabilità dell'adattatore `PluginExecutor`.

Passi di §5 attivi in Fase 1:

| Passo §5 | Fase 1 |
| --- | --- |
| 1 `prepare_workspace` | Solo rilevamento linguaggi su `PATH` locale; nessun clone |
| 2 `resolve_changed_files` | No (Fase 2) |
| 3 `run_plugins` | Sì, in due stadi (ADR-0007) |
| 4 `build_graph` | No (Fase 2) |
| 5 `normalize` | Sì: fingerprint, dedup, eccezioni; niente VEX |
| 6 `enrich` | No (Fase 2) |
| 7 `classify` | No (Fase 3) |
| 8 `score` | Sostituito dai livelli provvisori (ADR-0009) |
| 9 `diff_baseline` | No (Fase 2) |
| 10 `publish` | Solo file locali (ADR-0010, ADR-0011) |
| 11 `trigger_agents` | No (Fase 3) |

## Conseguenze

- Fase 1 non richiede Temporal, PostgreSQL né object storage; i test di integrazione di §14 basati su di essi partono in Fase 2.
- In Fase 2 `ca-workflows` non contiene regole di dominio, solo orchestrazione e retry.
- Se i passi crescono fino a rendere `ca-core` dipendente da troppe porte, si rivaluta `ca-engine` con un nuovo ADR.

## Revisione A-01

Data: 2026-11-08. Resta `Proposto`: la decisione non è contestata, ma il suo punto centrale non è ancora nel codice.

Confermato:

- `ca_core/ports.py` definisce le quattro porte di Fase 1, con ingressi e uscite Pydantic serializzabili; `ca_core/fakes.py` le implementa in memoria.
- `lint-imports` rispetta i tre contratti, compreso `ca_core` senza framework, rete né processi.

Da provare:

- `ca_core/pipeline/` non esiste. Che ogni passo sia una funzione serializzabile, idempotente e invocabile da sola si vede con K-15, K-16, K-17, K-18.
- Il parallelismo nell'adattatore `PluginExecutor`: R-07.

Passa ad `Accettato` quando quei task sono verdi.

## Emendamento: parallelismo nella porta

Data: 2026-11-08. La regola "il parallelismo è dell'adattatore" resta, ma il passo non poteva chiederlo: `run_many` esiste solo su `OciExecutor` e `run_plugins` chiama `run` in sequenza, mentre §5 e §7.1 vogliono i plugin in parallelo e G1.b chiede meno di 10 minuti.

Opzioni:

1. Esecuzione a lotti nella porta.
2. Thread nel passo, sopra `run()`. `lint-imports` non lo vieta, ma il limite di concorrenza diventerebbe un dato del nucleo, un adattatore Kubernetes non potrebbe usare le proprie quote e il passo non potrebbe verificare le firme di un lotto prima del primo container (ADR-0005).

Decisione: opzione 1. In `PluginExecutor`, con `Sequence` da `collections.abc`:

```python
def run_many(self, requests: Sequence[PluginRunRequest]) -> list[PluginRunResult]: ...
```

Contratto:

- Un risultato per richiesta, nell'ordine delle richieste; lotto vuoto, lista vuota.
- Un plugin non riuscito è un risultato, mai un'eccezione. Vale anche per timeout ed errori del client del runtime su `create`, `start`, `inspect`.
- Escono come eccezione solo le condizioni che annullano la scansione: `ScanAborted` e runtime assente. Alla prima eccezione le esecuzioni non avviate si annullano subito, senza attendere quelle che precedono nell'ordine. Quelle in corso terminano entro il proprio timeout e rimuovono il container, poi l'eccezione si propaga.
- `run` resta nella porta: serve a `sbom`, che esegue solo syft (ADR-0010).

Nel passo:

- `run_plugins` chiama `run_many` una volta per stadio, in sequenza e senza catturare eccezioni. Il secondo stadio parte solo a primo finito, perché l'SBOM è un suo ingresso (ADR-0007).
- La lettura dell'SBOM resta sequenziale e per nome: "il primo per nome" non dipende da quale container finisce prima.

Limite di concorrenza:

- Vive in `OciExecutor(max_parallel=...)` e lo fissa la radice di composizione con `min(DEFAULT_MAX_PARALLEL, os.cpu_count() or 1)`. Non sta nella porta, nel passo né in `.code-analyzer.yml` (ADR-0014). Nessun nuovo flag (ADR-0010).
- Gli stadi sono sequenziali e la CLI fa una scansione per processo, quindi il limite di ogni chiamata è il tetto del processo. Due processi sulla stessa macchina non si coordinano: fuori dalla Fase 1.
- Il tetto conta i container. Ogni container è limitato dalle proprie `resources`, ma la loro somma no. I manifest built-in non esistono ancora, quindi manca il dato: X-04 misura il picco. Se la somma non sta nella macchina, si passa a un budget sulle `resources` dentro l'adattatore, senza toccare la porta.

Conseguenze: `ca-core` resta senza thread né concetti di infrastruttura; la porta è un'interfaccia Python nello stesso build, quindi non serve un artefatto di contratto separato; il fake esegue il lotto in ordine e i test del passo restano deterministici.

## Emendamento per A-16 (2026-11-18): secondo D2-01

Motivo: la decisione D2-01 (2026-11-10, ADR-0016) ha tolto Temporal dalla Fase 2.

- Il motore resta uno solo, in `ca_core/pipeline/`, eseguito dalla CLI: è anche l'unico in CI e in locale. Il server non esegue scansioni: riceve il report di una scansione già fatta (`POST /v1/scans`, ADR-0016, ADR-0018).
- La frase «`ca-workflows` li avvolge in activity» vale solo se una fase futura riporterà Temporal. I passi restano funzioni con ingressi e uscite serializzabili, idempotenti e invocabili da sole: la proprietà costa poco e tiene aperta la porta.
- Le porte di Fase 2 si aggiungono a quelle di Fase 1: `EnrichmentFeeds`, `GitHistory`, `BaselineSource` e `ArtifactStore` (in `ca_core/ports.py`).
