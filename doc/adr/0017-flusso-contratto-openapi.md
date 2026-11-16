# ADR-0017: Flusso del contratto OpenAPI

- Stato: Proposto. La decisione non richiede l'utente; passa ad `Accettato` con le prove di B-01, C-08 e W-02
- Data: 2026-11-13
- Decisione umana richiesta: no (scelta tecnica; da confermare in revisione)
- Riferimenti: §2, §9.2, §16 regola 1; ADR-0003; lacuna 12

## Contesto

ADR-0003 ha fissato il principio: i modelli Pydantic generano i contratti, il file in `schemas/` è l'artefatto autorevole e la CI ne verifica l'allineamento. Per l'OpenAPI ha rinviato alla Fase 2.

Con il server arrivano due consumatori indipendenti dell'API: il frontend in `web/` e la CLI con `upload` (ADR-0016). Backend e frontend lavorano in parallelo da quando il contratto è chiuso (C-08), quindi il contratto deve esistere come file prima delle implementazioni e non può essere ridefinito da una delle due parti.

## Opzioni

1. OpenAPI scritta a mano, route verificate contro il file: si discosta da §2 ("OpenAPI generata automaticamente") e da ADR-0003.
2. OpenAPI servita solo a runtime da FastAPI (`/openapi.json`): nessun diff da rivedere, il frontend dipende da un server avviato.
3. OpenAPI esportata dall'applicazione FastAPI in `schemas/openapi.json`, versionata e verificata in CI; tipi del frontend generati da quel file.

## Raccomandazione

Opzione 3: è il flusso di ADR-0003 applicato all'API.

### Esportazione

- `uv run python -m ca_api.openapi_export` scrive `schemas/openapi.json`; con `--check` esce con errore se il file non è allineato. Vive in `ca_api` perché `ca_core` non può importare FastAPI (ADR-0001).
- L'export non avvia il server e non richiede database né rete: costruisce l'applicazione e ne legge lo schema.
- Uscita deterministica: chiavi ordinate, indentazione fissa, a capo finale. Formato OpenAPI 3.1, che usa JSON Schema 2020-12 come gli altri file di `schemas/`.
- Il comando con `--check` si aggiunge ai comandi di verifica di `AGENTS.md` e a `verify.yml` quando nasce `ca-api` (B-01).
- Una route si dichiara con modelli di richiesta e risposta, errori ed esempi prima di essere implementata (C-08): il contratto precede il codice che lo realizza.
- Ogni operazione ha un `operationId` esplicito e stabile. I nomi dei tipi generati ne dipendono; cambiarlo è una modifica incompatibile.

### Modelli condivisi con `schemas/`

- `Finding`, `ScanReport` e gli altri modelli di `ca_core` entrano nell'OpenAPI come componenti generati dagli stessi modelli, non da copie in `ca_api`.
- Un test di contratto confronta ciascun componente con il file corrispondente in `schemas/`, a meno di `$id` e della forma dei `$ref`. Una divergenza è un errore.
- I modelli che esistono solo nell'API (pagine, filtri, richieste di triage) vivono in `ca_api` e hanno `extra="forbid"` come gli altri.

### Tipi del frontend

- I tipi TypeScript dell'API si generano da `schemas/openapi.json`, mai dal server in esecuzione e mai a mano. Il generatore si sceglie in V-01, con licenza verificata in V-02.
- Il file generato è versionato in `web/`, in un solo percorso, con un'intestazione che ne vieta la modifica manuale. È versionato perché il diff dei tipi si rivede insieme al diff del contratto, e perché `lint` e `test` di `web/` non richiedono un passo di generazione.
- Controllo di deriva in CI: si rigenera e si confronta con il file versionato. Fa parte di `bun run --cwd web lint` (O-01).
- Nei test il frontend simula le risposte con gli esempi dell'OpenAPI. Gli esempi si validano contro i propri schemi nei test di contratto (C-10), così una risposta simulata non può divergere dal contratto.

### Versione e compatibilità

- La versione maggiore sta nel percorso: `/v1`. `info.version` è la versione del contratto in forma `1.MINORE.CORREZIONE`, indipendente dalla versione dei pacchetti.
- Dentro `/v1` sono ammesse solo aggiunte compatibili: nuove operazioni, nuovi parametri facoltativi, nuovi campi facoltativi nelle richieste, nuovi campi nelle risposte. Ogni aggiunta aumenta `MINORE`.
- I client devono ignorare i campi di risposta che non conoscono. Le richieste restano rigide: un campo sconosciuto è un errore.
- Aggiungere un valore a un enum in una risposta è incompatibile, salvo che il campo sia dichiarato aperto nello schema (stringa con pattern, come `warnings[].code`).
- Sono incompatibili: rimuovere o rinominare operazioni, campi o parametri, cambiare un tipo, rendere obbligatorio ciò che era facoltativo, cambiare un `operationId`, cambiare il significato di un codice di errore. Richiedono `/v2`, con `/v1` mantenuto per un periodo dichiarato.
- La revisione parte dal diff di `schemas/openapi.json`. Nessuno strumento automatico di confronto in Fase 2: i consumatori sono due e sono nello stesso repository.
- Finché l'API non ha consumatori esterni al repository, cioè fino al Gate 2, `/v1` può cambiare in modo incompatibile dentro una stessa PR che aggiorna contratto, backend, frontend e CLI insieme. Il vincolo di compatibilità parte dal primo rilascio.

### Formato di errore unico

- Ogni risposta 4xx e 5xx ha tipo `application/problem+json` (RFC 9457) e lo stesso schema, `Problem`:

| Campo | Contenuto |
| --- | --- |
| `type` | URI stabile del tipo di problema; `about:blank` se non ce n'è uno specifico |
| `title` | Testo breve, uguale per ogni occorrenza del tipo |
| `status` | Codice HTTP |
| `code` | Identificativo stabile per le macchine, per esempio `report-schema-invalid`, `payload-too-large`, `repository-mismatch`. È un enum del contratto |
| `detail` | Testo per le persone, facoltativo |
| `errors` | Facoltativo, per gli errori di validazione: elenco di `pointer` (JSON Pointer nel corpo o nome del parametro) e `message` |

- L'errore di validazione predefinito di FastAPI (`HTTPValidationError`) si sostituisce con `Problem`, così l'OpenAPI dichiara un solo formato. Lo stesso vale per 401, 403, 404, 409, 413 e 500.
- Un errore non riporta mai il valore ricevuto, solo dove si trova e cosa non va: il corpo di una richiesta può contenere finding e percorsi riservati, e i log dei client non devono riceverli di ritorno. Un 500 non espone tracce né messaggi interni.
- I client decidono su `status` e `code`, mai sul testo di `title` o `detail`.

## Conseguenze

- Un file in più in `schemas/` e un comando in più tra quelli di verifica; `AGENTS.md` regola 1 copre già l'obbligo di aggiornare contratto e test insieme.
- Il frontend può partire quando C-08 è chiuso, senza un backend funzionante.
- Il file dei tipi generati produce diff rumorosi nelle PR che toccano il contratto: è il costo di poterli rivedere.
- La paginazione, i filtri e l'elenco delle route non sono qui: li definisce ADR-0029 e li dichiara C-08.
