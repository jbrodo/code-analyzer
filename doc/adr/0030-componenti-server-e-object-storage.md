# ADR-0030: Componenti del server e object storage

- Stato: Accettato il 2026-11-16 dall'utente (D2-07): pg8000, adattatore su file system e adattatore S3 in Fase 2. Le licenze delle dipendenze nuove restano da verificare nei task e in D2-14
- Data: 2026-11-16
- Decisione umana richiesta: sì (D2-07), presa il 2026-11-16
- Riferimenti: §2, §15, §16 regola 2; ADR-0001, 0013, 0016, 0018, 0019; V-01, V-02 e V-08 in `doc/verifiche/scanner-fase-2.md`; incoerenza 16 del piano

## Contesto

§2 indica PostgreSQL con Alembic e, per gli artefatti, "S3 / MinIO". V-02 ha letto le licenze sul testo delle versioni fissate:

- Il server di object storage nominato da §2 ha una licenza che D-0013 vieta in un prodotto distribuito.
- Il driver PostgreSQL più diffuso, psycopg, ha una licenza che D-0013 mette tra quelle da approvare. Due alternative hanno licenze ammesse: asyncpg, solo asincrono, e pg8000, in Python puro e sincrono.
- Gli altri componenti candidati del server hanno licenze ammesse.

Con ADR-0016 il server è un'applicazione FastAPI con PostgreSQL e un archivio degli artefatti, senza worker né code. Gli artefatti sono report, SARIF, SBOM e grafo: file scritti una volta, letti per digest, cancellati con la scansione (ADR-0018).

## Opzioni

### Archivio degli artefatti

1. Server di object storage incluso nel prodotto: richiede un'eccezione alla policy D-0013.
2. Artefatti in PostgreSQL: un componente in meno, ma file da decine di MB nelle tabelle e nei backup del database.
3. **Porta `ArtifactStore` con un adattatore su file system** e un adattatore per servizi compatibili con S3.

### Driver PostgreSQL

1. psycopg, previa approvazione di Riccardo Roveda.
2. asyncpg, con SQLAlchemy in modalità asincrona.
3. **pg8000, con SQLAlchemy in modalità sincrona.**

## Raccomandazione

Opzione 3 in entrambi i casi.

### `ArtifactStore`

- La porta sta in `ca_core` (C-06): scrivere da un flusso, leggere come flusso, verificare l'esistenza, cancellare. Nessun elenco e nessuna sovrascrittura: una chiave esistente con contenuto diverso è un errore (ADR-0016).
- La chiave la costruisce il server da valori che controlla: schema del tenant, identificativo della scansione, tipo di artefatto, digest. Mai un nome di file ricevuto dal client.
- **Adattatore su file system**, in `ca_api`, per sviluppo, test e pilota. Radice dalla configurazione del server; scrittura su file temporaneo nella stessa cartella e rinomina atomica; percorso composto solo da componenti validati; cartelle e file leggibili dal solo utente del server. Il digest si verifica durante la scrittura.
- **Fake in memoria** per i test del nucleo.
- **Adattatore S3 in Fase 2**, per decisione dell'utente del 2026-11-16; la stesura proponeva di rinviarlo. Parla il protocollo S3 con un servizio fornito da chi installa: indirizzo, bucket e credenziali dalla configurazione del server, credenziali solo dall'ambiente o da file montati. Supera la stessa batteria di test di contratto dell'adattatore su file system (B-07). La libreria client è una dipendenza nuova, da scegliere e verificare in B-07 (§16 regola 2). Per i test serve un server compatibile con S3 con licenza ammessa, usato come strumento di prova e non distribuito; quello nominato da §2 resta escluso.
- Nessun server di object storage nel prodotto né nel compose di sviluppo: l'adattatore predefinito resta il file system.

Un tenant ha la propria sottocartella. Bucket separati per tenant sono del packaging SaaS (ADR-0018).

### Database e driver

- PostgreSQL 16 (§2), fornito da chi installa. Nel compose di sviluppo e nei test si usa l'immagine ufficiale: è uno strumento, non una parte distribuita del prodotto. pgvector non si installa (ADR-0018).
- SQLAlchemy in modalità sincrona con pg8000. Le route che toccano il database sono funzioni sincrone, che FastAPI esegue in un pool di thread. Alembic lavora già così.
- Motivi: licenza ammessa senza approvazioni; nessuna estensione compilata; codice e test più semplici della variante asincrona; e **il codice sincrono lascia aperta la porta a psycopg**, che è il driver di riferimento. Se Riccardo Roveda lo approva in D2-14, sostituirlo è una modifica della dipendenza e dell'indirizzo di connessione.
- Perché regga: nessun SQL e nessun tipo specifico del driver nel codice di `ca_api`; tutto passa da SQLAlchemy. B-02 lo verifica.
- Limite: un driver in Python puro è più lento nel caricamento di molte righe. Il volume da reggere è l'ingestione del pilota più grande; B-03 lo misura. Se non basta, le alternative sono psycopg con approvazione o asyncpg riscrivendo la persistenza in asincrono.

### Componenti del server

Dipendenze di `ca_api`, con le versioni di V-01 come punto di partenza. Ogni task che ne aggiunge una fissa la versione corrente con il suo checksum e aggiorna l'SBOM (§16 regola 2).

| Componente | Ruolo | Licenza secondo V-02 |
| --- | --- | --- |
| fastapi, uvicorn | Applicazione e server ASGI | Ammessa |
| sqlalchemy, alembic | Persistenza e migrazioni | Ammessa |
| pg8000 | Driver PostgreSQL | Ammessa |
| pyjwt | Verifica dei token (ADR-0019) | Ammessa |
| opentelemetry-api, opentelemetry-sdk | Strumentazione (ADR-0016) | Ammessa |
| testcontainers | Solo test | Ammessa |

Non ancora verificate, da verificare in B-01 prima di aggiungerle: la libreria crittografica che `pyjwt` richiede per gli algoritmi asimmetrici, e il lettore di `multipart/form-data` che serve a `POST /v1/scans`. Per il secondo conta anche che applichi i limiti di dimensione mentre legge (ADR-0016). Lo stesso vale per le dipendenze transitive, che V-02 non ha coperto: le elenca l'SBOM dell'immagine.

### Forma dell'installazione in Fase 2

- Un'immagine del server (I-03) su Python 3.14, utente non privilegiato, file system in sola lettura con un volume per gli artefatti.
- La stessa immagine serve i file statici della SPA: il pilota è un container più PostgreSQL. Le intestazioni di sicurezza della SPA, tra cui la Content Security Policy (ADR-0019), le imposta il server.
- Il server parla HTTP. TLS lo termina un proxy dell'installazione (I-05, I-06), che non fa parte del prodotto.
- Configurazione da un file e dall'ambiente: connessione al database, radice degli artefatti, limiti di ADR-0016, emittenti di ADR-0019, conservazione di ADR-0018. I segreti solo dall'ambiente o da file montati.
- Il backup deve prendere insieme database e cartella degli artefatti: una scansione nel database senza i suoi file è incoerente. La documentazione di I-05 lo dice.

## Conseguenze

- Nessun componente con licenza vietata o da approvare entra nel prodotto con questa scelta. D2-14 resta necessaria per la distribuzione dell'immagine del server, sull'SBOM della build.
- Il server con l'adattatore su file system gira su un solo host; con l'adattatore S3 può avere più repliche.
- §14 citava un contenitore di object storage tra i test di integrazione: resta, ma con un server a licenza ammessa scelto in B-07.
- §2 dopo la correzione di A-17: porta `ArtifactStore` con due adattatori, file system e S3; nessun server incluso.

## Verifica del lettore di multipart (C-08, 2026-11-17)

`python-multipart` 0.0.34 è il lettore di `multipart/form-data` che FastAPI richiede per `POST /v1/scans`: licenza permissiva dichiarata sul pacchetto (classificatore Apache Software License), rilasci regolari fino al 2026-11-16, Python 3.11 o successivo. Aggiunto a `ca-api`. I limiti di dimensione di ADR-0016 si applicano in B-03 mentre si legge il corpo; la libreria da sola non li impone. La libreria crittografica che serve a `pyjwt` per gli algoritmi asimmetrici resta da verificare in B-04.

## Verifica delle dipendenze di persistenza (B-02, 2026-11-17)

Aggiunte a `ca-api`: SQLAlchemy 2.0.58 (serie 2.0, MIT), Alembic 1.20.1 (MIT), pg8000 1.31.6 (BSD a tre clausole); solo ai test, `testcontainers` 4.15.0 (Apache 2.0). Transitive nuove, tutte con licenza permissiva e lette dai metadati dei pacchetti: scramp (MIT-0), asn1crypto (MIT; ultimo rilascio del 2022, è una libreria stabile ma ferma: la usa pg8000 per l'autenticazione), Mako e MarkupSafe (MIT, BSD), greenlet (MIT e PSF), python-dateutil, docker, requests, urllib3, charset-normalizer, python-dotenv, wrapt, tzdata. La licenza di ogni pacchetto è quella dichiarata dal pacchetto, non un parere legale: D2-14 resta di Riccardo Roveda per la distribuzione dell'immagine del server, sull'SBOM della build.

## Realizzazione di B-07 (2026-11-17)

- **Client S3: `boto3` 1.44.4** (Apache 2.0, rilasciato il 2026-11-16) con botocore, s3transfer, jmespath (MIT) e six. Scelta di una libreria diffusa e mantenuta invece di una firma SigV4 scritta a mano: codice di sicurezza in meno da mantenere. Le credenziali arrivano solo dalla catena predefinita (ambiente o file montati), mai da un argomento; un endpoint `http` è rifiutato salvo richiesta esplicita.
- **Server S3 di prova: SeaweedFS** (licenza Apache 2.0 letta dal repository il 2026-11-17, mantenuto), in un container, solo per i test e mai distribuito. MinIO resta escluso.
- Adattatore su file system: ogni componente del percorso si apre con `O_NOFOLLOW`, cartelle 0700 e file 0600, radice non privata rifiutata, scrittura su temporaneo e `link` atomico (nessuna sovrascrittura nemmeno in corsa). Adattatore S3: tetto di byte e digest mentre si legge, `PutObject` con `If-None-Match: *` (rifiuta la sovrascrittura in corsa: provato con sei scrittori concorrenti), digest nei metadati dell'oggetto per riconoscere una ripetizione con un `HEAD`.
- Entrambi, più il fake in memoria, superano la stessa batteria di contratto (`tests/unit/api/store_battery.py`): roundtrip, vuoto, 4,6 MiB, digest dichiarato, tetto con lettura limitata, ripetizione contro conflitto, chiavi non valide, cancellazione idempotente.
- **Non fatto:** la costruzione dell'archivio dalla configurazione del server (B-03); le variabili per indirizzo, bucket e regione; non provato su un servizio S3 reale (solo SeaweedFS); la crittografia lato server e il ciclo di vita degli oggetti sono di chi installa.
