# ADR-0002: Motore di scansione indipendente da Temporal

- Stato: Proposto; confermate il 2026-11-08 in revisione tecnica (A-01) le porte e il verso delle dipendenze. I passi della pipeline non esistono ancora (K-15..K-18)
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
