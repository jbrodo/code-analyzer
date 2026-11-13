# ADR-0018: Modello dati relazionale e multi-tenancy

- Stato: Proposto. Scelta tecnica; l'esercizio di più tenant dipende da D2-02. Passa ad `Accettato` con le prove di C-07 e B-02
- Data: 2026-11-13
- Decisione umana richiesta: no per il modello; sì (D2-02) per quanti tenant sono in esercizio
- Riferimenti: §4.1, §4.3, §9.2; ADR-0003, 0008, 0014, 0016; lacune 10 e 11 del piano

## Contesto

§4.3 elenca tredici tabelle e chiede "uno schema PostgreSQL per tenant". Cinque tabelle servono solo dalla Fase 3 (`vex_statements`, `decisions`, `agent_runs`, `golden_labels`, `embeddings` con pgvector). Il packaging SaaS è in Fase 4, ma uno schema nato senza tenant si converte male: la separazione va decisa con la prima migrazione.

Con ADR-0016 il server non esegue scansioni: riceve i report della CLI. Il modello deve quindi rispondere a domande che in Fase 1 non esistevano:

- L'`id` di un finding era uguale al fingerprint (ADR-0008, "senza database"). Sul server lo stesso fingerprint esiste in repository diversi.
- `first_seen` e `last_seen` erano l'ora della scansione. Ora li conosce solo il database.
- Le eccezioni stanno in `.code-analyzer.yml` e, da §9.2, anche sul server: manca la precedenza.
- A e B si calcolano entrambe in ombra (D2-10): serve un posto per due punteggi per finding e per scansione.

## Opzioni per la separazione dei tenant

1. Colonna `tenant_id` in ogni tabella, con filtro applicativo o row-level security: uno schema solo, ma un filtro dimenticato espone i dati di un altro tenant.
2. Uno schema PostgreSQL per tenant, con le tabelle dei tenant tutte uguali e una sola tabella globale: è ciò che chiede §4.3.
3. Un database per tenant: isolamento massimo, costo operativo fuori scala per la Fase 2.

## Raccomandazione

Opzione 2.

### Schemi

- Schema `public`: solo `tenants` e la tabella di versione di Alembic per le migrazioni globali. Nessun dato di scansione.
- Uno schema per tenant, `t_<32 cifre esadecimali>`. Il nome lo genera il server dall'`id` del tenant: non contiene mai testo scelto da un utente o letto da un token.
- Nessuna chiave esterna attraversa gli schemi. Le tabelle del tenant non hanno una colonna `tenant_id`: l'appartenenza è lo schema.
- La richiesta arriva al database già legata a un tenant: l'identità autenticata dà il tenant (ADR-0019), il livello di persistenza apre la sessione con lo schema di quel tenant tramite la mappa degli schemi di SQLAlchemy, non componendo `search_path` da stringhe. Una sessione senza tenant non vede alcuna tabella di dati.
- Un solo ruolo PostgreSQL dell'applicazione in Fase 2. Ruoli per tenant e bucket separati sono del packaging SaaS (Fase 4).
- Test obbligatorio in B-02: due tenant con lo stesso repository e lo stesso fingerprint, e nessuna lettura o scrittura dell'uno raggiunge l'altro.

Migrazioni Alembic in due rami: `global` per `public`, `tenant` applicato a ogni schema di tenant con la propria tabella di versione. Creare un tenant significa creare lo schema e applicare il ramo `tenant`. Un aggiornamento applica il ramo a tutti gli schemi e si ferma al primo errore, riportando quali schemi sono a quale versione.

### Tabelle della Fase 2

Tutte nello schema del tenant, salvo `tenants`. Gli identificativi sono UUID versione 7 generati dal server (ordinati nel tempo, quindi buoni come chiave primaria).

| Tabella | Contenuto essenziale |
| --- | --- |
| `tenants` (globale) | `id`, nome, schema, data di creazione |
| `repositories` | `id`; provider e identità esterna (quella del claim `repository` della pipeline, unica); nome; branch principale; `tier`, `internet_facing` e servizio di catalogo, tutti facoltativi (ADR-0028); `current_scan_id` |
| `scans` | `id`; repository; commit; ref; tipo (`pr`, `full`); numero della PR e commit base se è una PR; stato (`complete`, `partial`); inizio e durata dal report; digest del report (unico per repository, ADR-0016); versione dello schema del report; versione della configurazione di scoring; identità di chi ha caricato; chiavi degli artefatti nell'`ArtifactStore`; data di ricezione |
| `findings` | Un finding per `(repository_id, fingerprint)`, con indice unico. `id` opaco; campi descrittivi di §4.1 dall'ultima occorrenza; `first_seen`, `last_seen`; stato di triage, `owner`, `due_date` |
| `finding_occurrences` | Una riga per finding e scansione: posizione e commit in quella scansione, livello e sua origine, evidenza, stato dichiarato dal report, stato rispetto alla baseline (ADR-0025), e i due punteggi in ombra |
| `components` | Pacchetti dell'SBOM della scansione corrente del repository: purl, nome, versione, licenze dichiarate e rilevate |
| `graph_nodes`, `graph_edges` | Grafo dei moduli della scansione corrente (ADR-0020); `edges.confidence ∈ {dichiarato, dedotto, osservato}` |
| `exceptions` | Eccezioni con motivazione, scadenza, origine e approvatore |
| `finding_events` | Registro delle modifiche di triage: chi, quando, da quale stato a quale, motivazione |

`finding_events` non è in §4.3. Serve perché con l'autenticazione (ADR-0019) "chi ha accettato questo finding" deve avere una risposta verificabile, e la sola riga corrente di `findings` non la conserva. A-17 la aggiunge a §4.3.

Tabelle escluse: `vex_statements`, `decisions`, `agent_runs`, `golden_labels`, `embeddings`. L'estensione pgvector non si installa in Fase 2.

I modelli SQLAlchemy vivono in `ca_api` (`ca_core` non importa SQLAlchemy, ADR-0001). `Finding` e `ScanReport` di `ca_core` restano la fonte dei contratti (ADR-0003): tra modello relazionale e modello Pydantic c'è una conversione esplicita, coperta da un test che parte da un report valido e lo rilegge dall'API.

### `id` e fingerprint

- `Finding.id` è già "opaco per i consumatori" nel contratto. Nei report della CLI resta uguale al fingerprint. Nelle risposte dell'API è l'UUID di `findings.id`.
- Il fingerprint resta l'identità tra scansioni dentro un repository (ADR-0008) e non cambia algoritmo. Lo stesso fingerprint in due repository sono due finding.
- `PATCH /v1/findings/{id}` usa l'UUID. Il fingerprint si può cercare come filtro, non è un indirizzo.

### Scansione corrente, `first_seen`, `last_seen`, finding risolti

- La **scansione corrente** di un repository è la più recente, per ora di inizio, tra quelle di tipo `full` sul branch principale. L'elenco dei finding di un repository è l'insieme dei finding con un'occorrenza nella scansione corrente, più quelli risolti se richiesti dal filtro.
- `first_seen` è l'inizio della prima scansione `full` sul branch principale che contiene il finding; `last_seen` dell'ultima. Li scrive solo l'ingestione; i valori presenti nel report non si usano.
- Una scansione di PR crea occorrenze, e se serve la riga del finding, ma non sposta `first_seen`, `last_seen` né lo stato: ciò che esiste solo in una PR non è ancora un problema del repository. Un finding visto solo in PR ha `first_seen` nullo nel database e nell'API compare solo dentro quella scansione.
- Un finding diventa `risolto` quando manca dalla scansione corrente, era presente nella precedente, **e** la scansione corrente è `complete`. Una scansione `partial` aggiunge e aggiorna, ma non risolve nulla: un plugin fallito non ha visto i propri finding.
- Un finding `risolto` che ricompare torna `aperto`, conserva `first_seen` e lascia un evento. `risolto` lo assegna solo l'ingestione, mai un utente.
- Un report caricato in ritardo (più vecchio della scansione corrente) si registra con le sue occorrenze ma non cambia la scansione corrente né gli stati.

### Punteggi in ombra

Stanno in `finding_occurrences`, perché dipendono da dati della singola scansione: snapshot EPSS e KEV, grafo, churn, configurazione di scoring.

- Per ciascuna variante: punteggio, fattori G, P, E, C con la loro evidenza, e livello da punteggio. Due gruppi di colonne, `a_*` e `b_*`; i fattori sono JSON.
- Accanto: il livello provvisorio di ADR-0009 con la sua origine, che resta quello attivo fino al Gate 2 (D2-10).
- `scans.scoring_config_version` dice con quale configurazione sono stati calcolati.
- Per ordinare e filtrare l'elenco, `findings` porta una copia dei valori dell'occorrenza nella scansione corrente. È un dato derivato: l'ingestione lo riscrive, nessun altro lo modifica.
- Dopo la scelta della variante predefinita (Gate 2) non cambia lo schema: cambia quale livello è attivo.

### Stato sul server ed eccezioni del repository

Le due fonti hanno affidabilità diversa e non si fondono.

| Fonte | Chi la scrive | `approved_by` | Effetto in Fase 2 |
| --- | --- | --- | --- |
| `exceptions` di `.code-analyzer.yml` | Chi può modificare il branch (ADR-0014) | Testo dichiarato, non verificato | Applicata dalla CLI: il finding è `accettato` nel report e non blocca il gate |
| Eccezione sul server | Un utente con il ruolo adatto (ADR-0019), con `PATCH` | Identità autenticata | Stato del finding nell'API e nella UI |

Regole:

- L'ingestione registra le eccezioni del report in `exceptions` con origine `repository` e l'approvatore come testo dichiarato. L'API e la UI le mostrano distinte da quelle approvate sul server.
- Lo stato effettivo di un finding è `accettato` se vale almeno una delle due: un'eccezione del server non scaduta, oppure un'eccezione del repository applicata nella scansione corrente. Quando un'eccezione del repository sparisce dal file o scade, alla scansione successiva il finding torna allo stato che ha sul server.
- `falso_positivo` e `in_corso` esistono solo sul server.
- Un'eccezione scaduta non si cancella: resta con la sua scadenza, e lo stato si ricalcola alla lettura.
- **Il gate non legge il server.** In Fase 2 `gate` gira nella CI e conosce solo il report, quindi solo `.code-analyzer.yml`. Un'eccezione approvata sul server non fa passare un gate, e un rifiuto sul server non lo fa fallire. È il limite che deriva da ADR-0016; lo si supera, se serve, facendo scaricare alla CLI le eccezioni del server, con un ADR successivo.

### Storico e conservazione

- I finding non si cancellano per anzianità: `first_seen` e il registro degli eventi devono sopravvivere. Si cancellano solo con il repository.
- Scansioni e occorrenze hanno una durata di conservazione nella configurazione del server. Predefiniti: 365 giorni per le scansioni `full`, 30 giorni per le scansioni di PR. La scansione corrente di ogni repository non si cancella mai.
- Con la scansione si cancellano le sue occorrenze e i suoi artefatti nell'`ArtifactStore`.
- `components`, `graph_nodes` e `graph_edges` contengono solo la scansione corrente e si sostituiscono a ogni nuova scansione corrente, nella stessa transazione dell'ingestione. Le versioni precedenti restano negli artefatti (SBOM e grafo) delle rispettive scansioni, finché quelle esistono.
- Nessun processo pianificato in Fase 2 (ADR-0016: nessun worker): la pulizia è un comando di amministrazione, da lanciare a mano o da un cron dell'host.

### Grafo nell'ingestione

ADR-0016 elenca tre parti per `POST /v1/scans`. Il grafo dei moduli è una quarta parte facoltativa, `graph`, nel contratto di C-02. Senza, `graph_nodes` e `graph_edges` del repository restano quelli della scansione precedente che lo conteneva.

## Conseguenze

- La prima migrazione porta già tenant e schemi: in esercizio c'è un tenant solo finché D2-02 non dice altro, ma il codice non ha un percorso "senza tenant".
- Ogni operazione di manutenzione dello schema va ripetuta per tenant. Con pochi tenant è irrilevante; a centinaia servirà uno strumento, in Fase 4.
- Le interrogazioni tra tenant (statistiche di portfolio su più clienti) non sono possibili con una sola query. È voluto.
- Il report della CLI e la risposta dell'API usano lo stesso schema `Finding` con `id` diversi: i consumatori non devono confrontare gli `id` tra le due fonti. C-08 lo scrive nella descrizione del campo.
- Lo stato dei finding sul server e l'esito del gate in CI possono divergere, per la regola "il gate non legge il server". La UI deve dire, per un finding accettato sul server, che il gate della CI non ne tiene conto (U-01).
- A-17 aggiorna §4.3: tabelle della Fase 2, `finding_events`, fase delle altre.
