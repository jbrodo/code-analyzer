# Architecture Decision Record

Decisioni necessarie prima di implementare la Fase 1 (`doc/PROJECT.md` §13) e, da 0016, la Fase 2 (`doc/plan/fase-2.md` sezione 4). `Proposto` significa che la decisione attende conferma: dove indicato serve l'utente, negli altri casi basta la revisione tecnica. Dopo A-01, un ADR senza decisione umana resta `Proposto` solo perché manca la prova nell'implementazione: la decisione non è contestata e i task che la realizzano procedono. La sezione "Revisione A-01" di ogni ADR elenca ciò che è confermato e i task che portano il resto.

| ADR | Titolo | Stato | Decisione umana |
| --- | --- | --- | --- |
| [0001](0001-verso-dipendenze-pacchetti.md) | Verso delle dipendenze tra i pacchetti | Accettato | No |
| [0002](0002-motore-scansione-senza-temporal.md) | Motore di scansione indipendente da Temporal | Accettato | No |
| [0003](0003-autorita-contratti-json-schema.md) | Autorità dei contratti JSON Schema | Accettato | No |
| [0004](0004-esecuzione-plugin-e-isolamento.md) | Esecuzione dei plugin e livelli di isolamento | Accettato | Presa il 2026-11-08 |
| [0005](0005-firma-immagini-plugin.md) | Firma e verifica delle immagini dei plugin | Proposto (deciso fino al primo rilascio) | Sì |
| [0006](0006-feed-vulnerabilita-offline.md) | Database delle vulnerabilità in Fase 1 | Accettato | Presa il 2026-11-08 |
| [0007](0007-contratto-output-plugin.md) | Adattatori, ordine dei plugin, versioni dei formati | Accettato | No |
| [0008](0008-fingerprint-e-dedup.md) | Algoritmo di fingerprint e deduplicazione | Accettato | No |
| [0009](0009-livelli-e-gate-fase-1.md) | Livelli e gate senza scoring né baseline | Accettato | Sì, per i livelli provvisori |
| [0010](0010-contratto-cli-e-artefatti.md) | Contratto della CLI e artefatti di scansione | Accettato | No |
| [0011](0011-sarif-aggregato.md) | Struttura del SARIF aggregato | Accettato | No |
| [0012](0012-segreti-in-fase-1.md) | Rilevamento dei segreti in Fase 1 | Accettato | Presa il 2026-11-08 |
| [0013](0013-policy-licenze.md) | Valutazione della policy di licenze | Accettato | Presa il 2026-11-08 |
| [0014](0014-configurazione-e-confini-di-fiducia.md) | Configurazione e confini di fiducia | Accettato | No |
| [0015](0015-regole-semgrep-e-licenze-motori.md) | Regole Semgrep e licenze dei motori | Accettato | Presa il 2026-11-10 |
| [0016](0016-modalita-server-e-orchestrazione.md) | Modalità server e orchestrazione in Fase 2 | Accettato | Presa il 2026-11-10 (D2-01) |
| [0017](0017-flusso-contratto-openapi.md) | Flusso del contratto OpenAPI | Accettato (2026-11-18) | No |
| [0018](0018-modello-dati-e-multi-tenancy.md) | Modello dati relazionale e multi-tenancy | Accettato (2026-11-18) | No (D2-02 per l'esercizio dei tenant) |
| [0019](0019-autenticazione-e-rbac.md) | Autenticazione e RBAC | Accettato | Presa il 2026-11-16 (D2-02) |
| [0020](0020-ca-graph-isolamento-grafo-smell.md) | `ca-graph`: isolamento, schema del grafo, smell | Proposto (le definizioni degli smell non sono ancora confrontate con le pubblicazioni) | No |
| [0021](0021-scoring-variante-a-ombra-livelli-override.md) | Scoring Variante A, ombra, livelli e override | Accettato (valori da calibrare in X-02) | No |
| [0022](0022-esposizione-e-churn.md) | Esposizione e churn | Accettato (2026-11-18) | No |
| [0023](0023-variante-b-smell-e-debito-architetturale.md) | Variante B, smell e debito architetturale | Proposto (definizioni da confrontare con le pubblicazioni, benchmark di K-06) | No per la struttura (D2-11, presa il 2026-11-10) |
| [0024](0024-feed-epss-kev-cache-mirror.md) | Feed EPSS e KEV, cache, mirror e firma | Proposto (manca l'origine di OSV e trivy, E-04) | Sì, D2-05: presa il 2026-11-17 (nessun mirror) |
| [0025](0025-baseline-modalita-pr-finding-nuovi.md) | Baseline, modalità PR e finding nuovi | Accettato (2026-11-18) | No |
| [0026](0026-plugin-qualita-iac-coverage.md) | Plugin di qualità, IaC e coverage | Accettato (2026-11-18) | No |
| [0027](0027-integrazioni-ci.md) | Integrazioni CI | Proposto (pubblicazione ferma) | Sì: D2-13 presa il 2026-11-17, D2-12 rimandata |
| [0028](0028-catalogo-servizi.md) | Catalogo servizi | Accettato | Presa il 2026-11-16 (D2-04) |
| [0029](0029-ui-elenco-finding-perimetro-e-dati.md) | UI dell'elenco finding: perimetro e dati | Accettato (2026-11-18) | Sì, D2-15: presa il 2026-11-17 (perimetro confermato) |
| [0030](0030-componenti-server-e-object-storage.md) | Componenti del server e object storage | Accettato | Presa il 2026-11-16 (D2-07) |
| [0031](0031-variante-predefinita-esito-gate-2.md) | Variante di scoring predefinita: esito del Gate 2 | Accettato (2026-11-27) | Sì, §18: presa il 2026-11-27 |
| [0032](0032-licenza-del-prodotto.md) | Licenza del prodotto | Accettato (2026-11-27) | Sì, presa il 2026-11-27 |

## Aggiornamenti dopo la stesura

- ADR-0008, sezione "Precisazioni per K-04": algoritmo esatto di `fp1`, firma di `ca_core.fingerprint`, vettori di prova.
- Emendamenti "dopo A-01" in ADR-0003, 0004, 0005, 0006, 0007, 0014: revisione dei contratti dei plugin. Gli stati in tabella non cambiano.
- Sezioni "Revisione A-01" in ADR-0002, 0003, 0007, 0008, 0010, 0011, 0014: esito della revisione e prove mancanti. ADR-0003 definisce dove vive un'invariante e conferma `tests/contract/`.

- Emendamenti "per R-09" in ADR-0003 (schemi nel pacchetto), 0004 (`/out` su tmpfs, workspace illeggibile, interruzione), 0006 (spazio e pulizia della sincronizzazione), 0010 (nome del report); "per P-07" in ADR-0012 (configurazione git ostile). Gli stati in tabella non cambiano.

## Emendamenti di Fase 2 (A-16, 2026-11-18)

- ADR-0001: pacchetti di Fase 2 e i nove contratti di `import-linter`; `ca-cli` importa `ca-integrations`, `ca-api` solo `ca-core`.
- ADR-0002: secondo D2-01 il server non esegue scansioni e Temporal non c'è; il motore resta uno solo.
- ADR-0006: origine dei feed di arricchimento e mirror rimandati ad ADR-0024 (D2-05).
- ADR-0008 e 0013: verificati, nessun cambiamento oltre ai `kind` già aggiunti da P-05 e G-10 e alla riga di K-20.
- ADR-0009: superata dai livelli da punteggio solo con `levels.source: score` (D2-10, ADR-0021).
- ADR-0010: `--pr`, `--base`, `--baseline`, `--variant`, `--scoring-config`, `--service-context` e i comandi `notify`, `export`, `upload`.
- ADR-0015: motori e componenti nuovi, hadolint solo per uso interno (D2-14).
- ADR-0017, 0018, 0022, 0025, 0026 e 0029 passano ad `Accettato` con le prove indicate nei rispettivi stati. ADR-0020, 0024 e 0027 restano `Proposto`, ciascuno con la sua ragione in tabella; ADR-0021 è `Accettato` dal 2026-11-26.

## Stato alla chiusura della Fase 2 (X-09, 2026-11-27)

Tra gli ADR da 0016 a 0030 quattro restano `Proposto`, riaperti con motivo. Il proprietario è l'utente.

| ADR | Perché resta aperto | Cosa serve per `Accettato` |
| --- | --- | --- |
| 0020 | Le definizioni degli smell non sono confrontate con le pubblicazioni | Il confronto sui testi di §19 |
| 0023 | Come 0020, per la Variante B; il Gate 2 non ha validato il suo ordinamento (ADR-0031) | Il confronto sui testi; l'ordinamento è una questione separata |
| 0024 | Alla chiusura mancavano l'origine di OSV e trivy e il flag della CLI (E-04, completato dopo, il 2026-11-27) | La verifica del resto dell'ADR contro il codice |
| 0027 | L'Action gira nella CI del progetto (N-05), ma il componente GitLab non è mai stato eseguito e nulla è pubblicato | D2-12 e la decisione di pubblicazione |

## Lacune rinviate

Numerazione di `.claude/agents/architect.md`.

| Lacuna | Fase |
| --- | --- |
| 1 Dashboard (UI elenco finding) | 2, risolta da ADR-0029; portfolio in 4 |
| 2 API insufficienti per la UI | 2, risolta da ADR-0029 e dalle route di C-08 |
| 3 RBAC | 2, risolta da ADR-0019 |
| 4 Scoring ombra | 2, risolta da ADR-0021 |
| 5 Fattori non definiti | 2, risolta da ADR-0021 e ADR-0022 (la Variante B resta ad ADR-0023) |
| 6 Soglie discontinue | 2, risolta da ADR-0021 (intervalli semiaperti, arrotondamento prima del confronto) |
| 10 `agent_runs` | 3 |
| 11 Multi-tenancy | 2, risolta da ADR-0018 (uno schema per tenant); packaging in 4 |
| 12 OpenAPI | 2, risolta da ADR-0017 (principio in ADR-0003) |
| 13 Evidenza decisionale | 3 |
- X-07, 2026-11-10: ADR-0002, 0007, 0008, 0010, 0011, 0014 passano ad `Accettato`; le prove elencate nelle rispettive "Revisione A-01" sono nel codice e i test sono verdi.
