# ADR-0016: Modalità server e orchestrazione in Fase 2

- Stato: Accettato. D2-01 decisa dall'utente il 2026-11-10 (opzione 2). Le prove nel codice arrivano con B-01, B-03, B-13 e L-03
- Data: 2026-11-13
- Decisione umana richiesta: sì, presa il 2026-11-10
- Riferimenti: §2, §5, §9.2, §13, §14, §15; ADR-0001, 0002, 0004, 0010; `doc/plan/fase-2.md` sezione 5, incoerenze 1, 21 e 22

## Contesto

§2, §5 ("Dalla Fase 2 il workflow Temporal") e §14 portano Temporal in Fase 2. §13 però non elenca né Temporal né l'esecuzione delle scansioni sul server: chiede "API REST, DB, UI elenco finding". ADR-0002 ha reso la pipeline indipendente dall'orchestratore, e la CLI in CI esegue già scansioni complete sotto i 10 minuti (Gate 1).

Eseguire le scansioni sul server richiede cose che la Fase 2 non ha: un adattatore `PluginExecutor` per Kubernetes con gVisor (obbligatorio sul server per ADR-0004), credenziali di clone per i repository, webhook e un componente durevole da esercire. Il Gate 2 ha bisogno di finding con punteggio consultabili e confrontabili, non di esecuzione sul server.

## Opzioni

1. Temporal e scansioni eseguite dal server: `ca-workflows`, adattatore Kubernetes con gVisor, clone con credenziali, webhook.
2. Il server riceve i report prodotti dalla CLI in CI. Nessuna esecuzione sul server, nessun Temporal.
3. Server con una coda in PostgreSQL e un worker che esegue la CLI: come la 1 senza Temporal, restano gVisor e le credenziali di clone.

## Decisione

Opzione 2.

### Cosa fa il server

- Riceve, valida e conserva gli artefatti di una scansione già eseguita, e li serve all'API e alla UI.
- Non clona repository, non esegue plugin, non parla con un runtime di container e non conserva credenziali dei repository. `ca_api` non importa `ca_plugins`: lo impone un contratto `import-linter` (B-01, emendamento di ADR-0001 in A-16).
- Non ricalcola i finding. Fingerprint, livelli e punteggi sono quelli del report, con la versione della configurazione di scoring che li ha prodotti. Il server aggiunge solo lo stato che gli appartiene: `first_seen`, `last_seen`, occorrenze, triage ed eccezioni (ADR-0018).

### `POST /v1/scans` è un'ingestione

§9.2 dice "Avvia una scansione": in Fase 2 significa "registra una scansione eseguita".

- Corpo `multipart/form-data` con tre parti: `report` (obbligatoria, `scan-report`), `sarif` (facoltativa, SARIF aggregato di ADR-0011), `sbom` (facoltativa, CycloneDX). I nomi dei file non contano. ADR-0018 aggiunge una quarta parte facoltativa, `graph`, per il grafo dei moduli.
- Ogni parte è un input non fidato: si valida contro i file di `schemas/` con gli stessi lettori difensivi del nucleo (limiti di dimensione, profondità e numero di elementi). Un artefatto non valido respinge l'intera richiesta: non esistono ingestioni a metà.
- Il report deve avere `commit`. Una scansione di una cartella non git non si carica.
- Il repository del report deve coincidere con quello del token della pipeline (ADR-0019). Senza corrispondenza: 403.
- La scansione registrata è sempre in uno stato finale, `complete` o `partial`, copiato dal report. `GET /v1/scans/{id}` non ha stati "in coda" o "in corso". I tipi sono `PR` e `completa`; "notturna" non esiste in Fase 2.

Idempotenza:

- La chiave è `(repository, sha256 dei byte del report)`. Il report contiene commit, durate e orari, quindi due esecuzioni diverse hanno digest diversi e la stessa esecuzione inviata due volte ha lo stesso digest. Non serve un campo nuovo nel contratto del report né un'intestazione scelta dal client.
- Prima ingestione: 201 con l'`id` della scansione. Ripetizione: 200 con lo stesso `id`, senza effetti. `first_seen`, `last_seen` e le occorrenze non cambiano alla ripetizione.
- Stesso digest del report con `sarif` o `sbom` diversi dalla prima volta: 409. Gli artefatti di una scansione non si sostituiscono.
- L'ingestione avviene in una sola transazione. Gli artefatti grezzi vanno nell'`ArtifactStore` (ADR-0030) prima del commit, con chiave derivata dal digest: una richiesta interrotta lascia al più un oggetto orfano, mai una scansione senza artefatti.
- Due esecuzioni dello stesso commit sono due scansioni. Quale conti come stato corrente del repository lo definisce ADR-0018, quale sia la baseline ADR-0025.

Limiti di dimensione:

- Stanno nella configurazione del server, non nel codice. Valori predefiniti: 64 MiB per parte, 160 MiB per richiesta. Riferimento: il SARIF più grande misurato nel Gate 1 è di 19,2 MB (bandit su saleor, prima di P-07). B-03 li rimisura sui pilota e li corregge se serve.
- Il limite si applica mentre si legge il corpo, non dopo: oltre il limite la lettura si ferma e la risposta è 413. `Content-Length` serve solo a rifiutare prima.
- Limite di frequenza per repository: fuori da questo ADR, lo valuta S-01.

### Lato CLI

- Comando nuovo: `code-analyzer upload --server-url URL [--report FILE] [--sarif FILE] [--sbom FILE]`. Predefiniti: i nomi di ADR-0010 nella cartella corrente; `sarif` e `sbom` si inviano se i file esistono.
- Exit: 0 caricato o già presente, 2 errore. Mai 1: `gate` resta l'unico comando che decide (ADR-0010).
- `scan` non invia nulla. Un server irraggiungibile non cambia né il report né l'esito del gate: nell'Action `upload` è un passo separato.
- Il token è quello OIDC del provider CI (ADR-0019); nessun segreto a lunga durata. `ca_cli` resta senza import di server e database: usa solo un client HTTP.

### Cosa resta fuori dalla Fase 2

- Temporal, il pacchetto `ca-workflows`, l'adattatore Kubernetes con gVisor, il clone lato server, i webhook `/v1/webhooks/*`, le scansioni notturne.
- `POST /v1/findings/{id}/agents/run`: Fase 3.

Temporal si rivaluta con un nuovo ADR quando serve un innesco che la CI non può dare: scansioni pianificate, reazione a un webhook o a un nuovo avviso di vulnerabilità, cicli degli agenti (§11). Non prima della Fase 3.

### Telemetria del server

§15 chiede telemetria OpenTelemetry e dashboard Grafana nel chart Helm, che è in Fase 4. In Fase 2:

- `ca-api` è strumentato con l'API e l'SDK di OpenTelemetry: durata e stato delle richieste per route, durata delle ingestioni, ingestioni respinte per causa (schema, dimensione, autorizzazione, conflitto), dimensione degli artefatti ricevuti.
- L'esportazione OTLP è facoltativa e disattivata per default; si attiva con le variabili d'ambiente standard di OpenTelemetry. Senza esportatore la strumentazione non apre connessioni.
- Nessun collector, Tempo, Loki, Prometheus o Grafana nel compose o nel prodotto: Fase 4.
- Attributi e log non contengono token, contenuto dei finding, percorsi dei file analizzati né corpi delle richieste. Sono ammessi gli identificativi di tenant, repository e scansione.
- Le durate delle scansioni restano nel report, come in Fase 1.

Le librerie OpenTelemetry sono dipendenze nuove: licenza e manutenzione si verificano in V-01 e V-02 (§16 regola 2).

## Effetti su specifica e ADR

| Documento | Effetto |
| --- | --- |
| §2 | Temporal resta la scelta per l'orchestrazione, ma non entra in Fase 2. gVisor sul server non serve finché il server non esegue plugin |
| §5 | "Dalla Fase 2 il workflow Temporal" va corretto in A-17: in Fase 2 i passi restano funzioni del nucleo chiamate dalla CLI. Il passo 10 `publish` si divide: file locali nella CLI, DB con `upload` |
| §9.2 | `POST /v1/scans` registra una scansione eseguita. Webhook e avvio degli agenti fuori dalla Fase 2 |
| §14 | Nessun test con il test server di Temporal. Restano i test di integrazione con testcontainers per PostgreSQL |
| ADR-0002 | Invariato e confermato: i passi restano serializzabili, idempotenti e invocabili da soli, pronti a diventare activity |
| ADR-0004 | Invariato. Il requisito "sul server gVisor o Firecracker" non ha oggetto in Fase 2 |
| ADR-0010 | Si aggiunge `upload` (A-16) |

## Conseguenze

- Il server della Fase 2 è un'applicazione FastAPI con PostgreSQL e un `ArtifactStore`: nessun worker, nessuna coda.
- I finding sul server sono quelli che la CI dichiara. Chi controlla la pipeline di un repository controlla i finding di quel repository, come già oggi controlla il proprio gate. Non può toccare altri repository (ADR-0019). S-01 lo registra come rischio residuo.
- La configurazione effettiva della scansione resta quella letta dalla CLI, con i confini di ADR-0014. Tier ed esposizione registrati sul server (D2-04, ADR-0028) devono quindi arrivare alla CLI prima dello scoring, oppure applicarsi sul server: lo decide ADR-0028.
- La baseline per la modalità PR non può venire da un'esecuzione sul server: la fonte la sceglie ADR-0025 tra il report del branch base conservato dalla CI e quello servito dall'API.
- Un repository senza CI non ha scansioni sul server. Accettato per la Fase 2.
- Se D2-01 venisse rivista, B-03 resta valido per l'ingestione dalla CI e i task aggiuntivi sono quelli della sezione 3 del piano.

## Realizzazione di B-03 (2026-11-17)

- `POST /v1/scans` è realizzato come descritto: quattro parti validate, 201 e 200 per l'idempotenza, 409 per artefatti diversi, 413 contato mentre si legge, un'unica transazione di database con gli artefatti scritti prima. Una richiesta interrotta lascia al più un oggetto orfano; se il database fallisce l'ingestione prova a cancellare ciò che ha scritto.
- **Il confronto tra repository del report e del token** non può essere un'uguaglianza di identificativi: il report ha solo il nome della cartella analizzata (`repository.name`), il token l'identificativo numerico e il nome completo del provider. Si accetta il nome intero o il suo ultimo segmento, quindi una scansione di una sottocartella (con un altro nome) si rifiuta e si lancia dalla radice del repository. Il commit si confronta solo se il token lo porta.
- Il **branch principale** non è nel report: si riconosce dal `ref` del token (`main` e `master`, configurabili con `CA_API_DEFAULT_BRANCHES`) finché il repository non ne ha uno registrato, che la prima scansione completa su quei branch fissa.
- `ref` e `commit` della scansione vengono dal token e dal report, non dal corpo della richiesta.
- Gli errori di validazione riportano il luogo (JSON Pointer) e il tipo, mai il valore ricevuto.
