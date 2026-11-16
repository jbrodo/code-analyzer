# ADR-0019: Autenticazione e RBAC

- Stato: Accettato il 2026-11-16 dall'utente (D2-02): token nella SPA, quattro ruoli, un tenant in esercizio. Il parere di `security` arriva con S-01 e può chiedere un emendamento
- Data: 2026-11-16
- Decisione umana richiesta: sì (D2-02), presa il 2026-11-16
- Riferimenti: §9.2; ADR-0014, 0016, 0018, 0029; lacuna 3; `doc/ux/fase-2.md` §4.1

## Contesto

§9.2 dice soltanto: "OIDC per utenti; OIDC dei provider CI per le pipeline (nessun token a lunga durata)". Mancano i ruoli, il legame tra identità e tenant, il legame tra pipeline e repository, e il flusso della SPA.

Tre ADR aspettano questa risposta:

- ADR-0016: `POST /v1/scans` accetta un report solo se il repository del report coincide con quello del token della pipeline.
- ADR-0018: la richiesta arriva al database già legata a un tenant, e il tenant viene dall'identità.
- ADR-0014 e ADR-0029: `approved_by` di un'eccezione è una dichiarazione finché non c'è un'identità verificata; sul server deve essere l'utente autenticato.

Con ADR-0016 il server non ha worker né stato oltre PostgreSQL e l'`ArtifactStore`.

## Opzioni

### Chi tiene il token dell'utente

1. **La SPA è un client OIDC pubblico**: flusso authorization code con PKCE nel browser, token di accesso tenuto in memoria e inviato all'API come `Authorization: Bearer`. L'API verifica un JWT e non ha sessioni.
2. Il server è il client OIDC e dà al browser un cookie di sessione (`HttpOnly`, `SameSite`). Il token non raggiunge mai JavaScript. Servono una tabella di sessioni o un cookie firmato, la protezione dalle richieste tra siti, e un secondo meccanismo accanto a quello delle pipeline.
3. Token dell'API emessi dal server (chiavi personali): sono token a lunga durata, vietati da §9.2.

### Dove stanno i ruoli

1. **In un claim del token dell'IdP**, con una mappa in configurazione dai valori del claim ai ruoli del prodotto.
2. In una tabella del server gestita da un amministratore: richiede una UI o un'API di gestione degli utenti, che ADR-0029 esclude.

## Raccomandazione

Opzione 1 in entrambi i casi. Il vantaggio principale: utenti e pipeline si autenticano nello stesso modo, con un JWT firmato da un emittente fidato, e il server ha un solo percorso di verifica.

Punto da sottoporre a S-01: con l'opzione 1 uno script iniettato nella pagina può usare il token finché la pagina è aperta. Le difese sono la durata breve del token, l'assenza di archiviazione persistente e la Content Security Policy della SPA (W-01). L'opzione 2 toglie il token dal browser al prezzo di stato e di un secondo meccanismo. Se S-01 la preferisce, cambiano B-04 e W-03, non il resto di questo ADR.

### Emittenti fidati

La configurazione del server elenca gli emittenti. Nessun IdP è cablato nel codice.

| Campo | Significato |
| --- | --- |
| `issuer` | Valore esatto del claim `iss`. Solo `https`, salvo un'opzione di sviluppo esplicita che il server segnala all'avvio |
| `kind` | `user` o `pipeline` |
| `audience` | Valore atteso in `aud`: l'identificatore di questa installazione |
| `tenant` | Tenant a cui l'emittente appartiene (solo `user`) |
| `roles_claim`, `roles_map` | Claim che porta i gruppi e mappa verso i ruoli (solo `user`) |
| `provider` | `github` o `gitlab` (solo `pipeline`): sceglie i claim da leggere |
| `owners` | Mappa da identificativo del proprietario dei repository a tenant (solo `pipeline`) |

Verifica di ogni token, uguale per i due tipi:

1. Si legge `iss` senza fidarsi del resto e lo si cerca nell'elenco. Un emittente sconosciuto è 401 e **non provoca alcuna richiesta in uscita**: l'indirizzo delle chiavi viene dalla configurazione, mai dal token.
2. Firma verificata con le chiavi pubbliche dell'emittente. Algoritmi ammessi in un elenco fisso di algoritmi asimmetrici; `none` e quelli simmetrici sono sempre respinti.
3. `aud` uguale a quello configurato; `exp` e `nbf` rispettati con una tolleranza d'orologio in configurazione (predefinito 60 secondi); durata `exp - iat` non oltre un massimo in configurazione (predefinito un'ora), così un emittente mal configurato non introduce token lunghi.
4. Le chiavi si tengono in memoria con una scadenza. Un `kid` sconosciuto provoca un solo aggiornamento, con un limite di frequenza per emittente.

Il server non emette token, non ha chiavi di firma proprie e non conserva token ricevuti.

### Utenti

- La SPA usa authorization code con PKCE come client pubblico, senza segreto. Il token sta in memoria: mai in `localStorage`, `sessionStorage` o cookie. Ricaricando la pagina si rifà il flusso, che con la sessione dell'IdP attiva non chiede nulla all'utente.
- Nessun token di aggiornamento conservato nel browser. La durata della sessione è quella decisa dall'IdP.
- L'identità registrata è la coppia `(iss, sub)`. Nome ed email dal token servono solo alla visualizzazione, e sono ciò che compare come `approved_by` e nel registro delle modifiche insieme alla coppia.
- Il tenant è quello dell'emittente. Un claim di tenant, con più tenant sullo stesso IdP, è del packaging SaaS (Fase 4).
- `GET /v1/me` restituisce identità, ruoli e tenant (ADR-0029).
- La libreria OIDC del frontend, se serve, è una dipendenza nuova di W-03 e segue §16 regola 2.

### Ruoli

Quattro ruoli, validi su tutti i repository del tenant. Permessi per singolo repository non entrano in Fase 2.

| Ruolo | Può |
| --- | --- |
| `lettore` | Leggere repository, scansioni, finding, SBOM, grafo |
| `triage` | Ciò che può `lettore`; prendere in carico, assegnare, riaprire |
| `approvatore` | Ciò che può `triage`; segnare falso positivo, creare e revocare eccezioni |
| `amministratore` | Ciò che può `lettore`; registrare tier ed esposizione di un repository (ADR-0028) |

`amministratore` non include `approvatore`: chi configura i repository non approva per questo le eccezioni. Un utente può avere più ruoli. Un utente autenticato senza alcun ruolo riceve 403 ovunque tranne `GET /v1/me`.

Un approvatore può approvare un'eccezione su un finding di cui è owner. La separazione dei compiti non è imposta in Fase 2; `finding_events` registra chi ha fatto cosa (ADR-0018).

### Matrice dei permessi

Endpoint di ADR-0029. `P` è l'identità di una pipeline.

| Endpoint | `lettore` | `triage` | `approvatore` | `amministratore` | `P` |
| --- | --- | --- | --- | --- | --- |
| `GET /me` | sì | sì | sì | sì | no |
| `GET /repositories`, `/repositories/{id}`, `/repositories/{id}/scans` | sì | sì | sì | sì | no |
| `GET /scans/{id}`, `/scans/{id}/sarif` | sì | sì | sì | sì | solo il proprio repository |
| `GET /repositories/{id}/findings`, `GET /findings/{id}` | sì | sì | sì | sì | no |
| `GET /repositories/{id}/sbom`, `/graph` | sì | sì | sì | sì | no |
| `PATCH /findings/{id}`: stato `in corso` o `aperto`, owner | no | sì | sì | no | no |
| `PATCH /findings/{id}`: falso positivo, eccezione creata o revocata | no | no | sì | no | no |
| `PATCH /repositories/{id}` | no | no | no | sì | no |
| `POST /scans` | no | no | no | no | solo il proprio repository |
| Baseline del proprio repository (B-12, ADR-0025) | — | — | — | — | solo il proprio repository |
| `GET /service-context` (ADR-0028) | no | no | no | no | solo il proprio repository |

Una risorsa di un altro tenant risponde 404, non 403: l'esistenza non si rivela. Dentro il tenant, un'azione non permessa dal ruolo è 403 con il ruolo richiesto nel corpo, che la UI mostra (U-01).

Un utente non carica scansioni: `POST /scans` accetta solo identità di pipeline. Per le prove in locale si usa l'emittente finto dell'ambiente di sviluppo (I-05).

### Pipeline

- La pipeline chiede al proprio provider un token OIDC con `aud` uguale all'identificatore dell'installazione e lo passa a `code-analyzer upload` (ADR-0016). Nessun segreto configurato nel repository.
- Il repository si identifica con l'**identificativo numerico** dato dal provider, non con il nome: un nome si può riassegnare dopo una cancellazione o un trasferimento. Il nome serve alla visualizzazione e si aggiorna a ogni caricamento.
- Claim attesi, da confermare alla fonte in B-04: per GitHub Actions `repository_id`, `repository_owner_id`, `repository`, `ref`, `sha`; per GitLab `project_id`, `namespace_id`, `project_path`, `ref`. L'identità esterna in `repositories` è `(provider, issuer, identificativo)`.
- Il tenant viene da `owners`: l'identificativo del proprietario nel token deve comparire nella mappa. Altrimenti 403.
- Primo caricamento di un repository il cui proprietario è nella mappa: il repository si crea, senza tier né esposizione. Non serve registrarlo prima.
- Il report deve dichiarare lo stesso repository e lo stesso commit del token, dove il token li porta. Differenza: 403 (ADR-0016).
- Il token si verifica all'inizio della richiesta; un caricamento lungo non fallisce perché il token scade durante la lettura del corpo.
- Nei flussi che il provider esegue per una PR da un fork il token OIDC di norma non è disponibile: quei flussi non caricano. Il comportamento dell'Action in quel caso è di ADR-0027.

Un token di pipeline rubato entro la sua validità permette di caricare un report falso per quel repository. Resta dentro il rischio già accettato da ADR-0016 (chi controlla la pipeline controlla i finding del proprio repository) e non tocca altri repository.

### `approved_by`

- Un'eccezione creata con `PATCH /findings/{id}` ha come approvatore l'identità autenticata. Il campo non è nel corpo della richiesta (ADR-0029).
- Un'eccezione che arriva da `.code-analyzer.yml` conserva il testo dichiarato e l'origine `repository`: il server non la promuove mai a verificata, nemmeno se il testo coincide con il nome di un approvatore (ADR-0018).

### Libreria e prove

- Verifica dei JWT con `pyjwt` (licenza permissiva, verificata in V-02), che copre firma, claim e chiavi pubblicate. `authlib` resta l'alternativa se servisse il flusso lato server (opzione 2).
- Nei test un emittente finto in processo, con chiavi generate dal test: nessuna chiamata esterna (§16 regola 7). Nel compose di sviluppo un IdP di prova (I-05), accettato solo con l'opzione di sviluppo.
- Casi obbligatori in B-04 e T-05: emittente sconosciuto senza richieste in uscita; `aud` errato; firma con chiave non pubblicata; algoritmo `none` e simmetrico; token scaduto; durata eccessiva; token di pipeline su un endpoint degli utenti e viceversa; repository del token diverso da quello del report; proprietario non in mappa; risorsa di un altro tenant.

## Conseguenze

- Il server resta senza stato di sessione. Revocare un utente significa revocarlo sull'IdP; l'effetto arriva alla scadenza del token, quindi la durata del token di accesso è una scelta di sicurezza di chi configura l'IdP.
- I ruoli valgono per tutto il tenant. Chi ha bisogno di permessi per repository deve aspettare un ADR successivo; il messaggio "Non hai accesso a questo repository" di U-01 in Fase 2 corrisponde a un 404.
- Il server fa richieste in uscita solo verso gli indirizzi delle chiavi degli emittenti configurati. Va scritto nel modello delle minacce (S-01) e nei requisiti di rete dell'installazione (I-05, I-06).
- Aggiungere un provider CI significa aggiungere una riga alla tabella dei claim, con i suoi test.
- I nomi dei claim dei provider sono citati a memoria e non verificati alla fonte in questo ADR: B-04 li conferma sulla documentazione corrente prima di implementare.
- Se D2-02 sceglie un IdP specifico, non cambia il codice: cambia la configurazione dell'emittente e l'IdP di prova di I-05. Se rinuncia ai ruoli, `PATCH` delle eccezioni esce da B-09 e W-06 e `approved_by` resta una dichiarazione anche sul server.
- A-17 aggiorna §9.2 con ruoli, matrice e `GET /v1/me`.
