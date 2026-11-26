# Verifiche di sicurezza della Fase 2

## S-05 — Feed e mirror

Revisione di progetto in sola lettura, 2026-11-16, su ADR-0024 e ADR-0006 e sui fatti di V-05 (`scanner-fase-2.md`). Il codice dei feed EPSS e KEV non esiste ancora (E-01..E-06): nulla è stato eseguito, e ogni voce è una richiesta per quei task o per un ADR. S-06 ricontrolla l'implementazione.

Esito: nessun critico, 1 alto, 7 medi, 5 bassi. L'alto non ferma E-01..E-04: va risolto in ADR-0021 prima che il livello da punteggio diventi attivo (X-06, X-08). **La decisione sul rischio residuo spetta all'utente.**

### Cosa regge

- La sincronizzazione non riceve il workspace e scarica file interi: nessun dato del repository raggiunge la rete, nemmeno l'elenco delle CVE.
- L'origine non si cambia da `.code-analyzer.yml`.
- Uno snapshot che fallisce un controllo si scarta per intero; il puntatore cambia solo dopo la validazione.
- I campi di testo di KEV non entrano nel report, quindi non arrivano alla UI né ai commenti delle PR.
- Il feed assente è distinto dalla CVE non valutata, e il report registra SHA-256 e identità del contenuto: un punteggio si può ricostruire e contestare.
- Il mirror fallisce chiuso senza firma valida.

### Alto

**S5-A1. Dopo il Gate 2 il gate dipende da feed senza firma, e l'errore è nel verso sbagliato.**
Oggi i livelli delle dipendenze vengono dal CVSS (ADR-0009) e i due feed non toccano il gate. Con il livello da punteggio P moltiplica tutto: un EPSS portato a zero, o una voce tolta da KEV, porta P al minimo di §6.1 (0,01) e una vulnerabilità con CVSS massimo scende a `basso`. Chi riesce a servire uno snapshot plausibile ma alterato, o un mirror compromesso, spegne il gate per tutte le dipendenze senza toccare il repository. Il verso opposto (voce aggiunta a KEV) blocca le pipeline: rumoroso, ma sicuro.
ADR-0024 delimita l'effetto a "cambia l'ordinamento e può cambiare un livello": è corretto per singolo finding, ma l'attacco vale per tutti insieme.
Richiesta per ADR-0021 (A-06), una delle tre:

1. un limite inferiore al livello di una dipendenza in funzione del CVSS, in configurazione, così i feed possono alzare un livello ma non azzerarlo;
2. con origine `public`, livello attivo uguale al più grave tra quello da punteggio e quello provvisorio di ADR-0009, per le sole dipendenze;
3. accettazione esplicita del rischio da parte dell'utente, scritta nell'ADR.

**Decisione dell'utente del 2026-11-16: richiesta 1.** A-06 scrive in ADR-0021 il limite inferiore dal CVSS, con i valori nella configurazione di scoring e un caso nella tabella di regressione (F-05).

Fino al Gate 2 vale D2-10: il gate non legge i punteggi, e l'effetto è limitato all'ordinamento usato in G2.b, dove lo snapshot è registrato e il confronto si può rifare.

### Medi

| ID | Problema | Richiesta | Dove |
| --- | --- | --- | --- |
| S5-M1 | **Ritorno a uno snapshot vecchio.** I controlli non guardano la data del contenuto: un file autentico ma vecchio di mesi supera forma, dimensione e conteggio. Nasconde le voci di KEV aggiunte nel frattempo | Rifiutare uno snapshot con `score_date` o `catalogVersion` precedente a quello in cache. Avviso `feeds-stale` anche quando il contenuto appena scaricato è più vecchio della soglia di età | E-02, E-03; emendamento di ADR-0024 |
| S5-M2 | **La plausibilità guarda solo il numero di voci.** Si possono alterare migliaia di punteggi senza cambiare il conteggio | KEV: una voce presente nello snapshot precedente e assente nel nuovo è anomala, perché il catalogo cresce. Avviso con il numero, rifiuto oltre una soglia piccola in configurazione. EPSS: rifiuto se la quota di CVE con variazione oltre una soglia supera un tetto, entrambi in configurazione e tarati sugli snapshot di F-04 | E-02, E-03 |
| S5-M3 | **Senza cache ogni sincronizzazione è la prima.** Su un runner effimero senza cache dei feed non esiste uno snapshot precedente: S5-M1 e S5-M2 non scattano mai e resta solo il conteggio minimo | Il report dice se lo snapshot è stato confrontato con uno precedente. La documentazione dell'Action indica la cache dei feed come requisito di sicurezza, non solo di velocità | E-06, N-04, L-05 |
| S5-M4 | **Feed assente e P.** Il valore di P senza EPSS è una costante ancora da fissare. Se è basso, impedire lo scaricamento (rete bloccata, `--offline` senza cache) abbassa tutti i punteggi: stesso verso di S5-A1 | P senza feed non inferiore al valore di una CVE con EPSS medio; e ADR-0021 decide se, con il livello da punteggio attivo, `enrichment-feed-missing` fa uscire `gate` con 2 come una scansione parziale | A-06 |
| S5-M5 | **Lettura nel processo della CLI.** A differenza dei database dei plugin, questi file si leggono sull'host con i permessi dell'utente. Il JSON di KEV ha un tetto di 32 MiB a fronte di 1,85 MB reali; in Fase 1 un JSON di 23 MiB ha portato a 586 MiB di memoria (M-10) | Tetto di KEV a 8 MiB. Limiti su profondità e numero di elementi con il lettore difensivo già usato per i SARIF. Tetto alla lunghezza di riga del CSV. `RecursionError` e `MemoryError` trattati come snapshot respinto | E-02, E-03 |
| S5-M6 | **Chiave del mirror.** ADR-0024 riusa la verifica di ADR-0005 senza dire con quale chiave si firma. Il job che costruisce il mirror ha la rete e legge dati non fidati: se firma con la chiave delle immagini, comprometterlo espone la firma dei plugin | Chiave dei feed distinta da quella delle immagini, con ancora di fiducia propria nel pacchetto | E-05; emendamento di ADR-0024 |
| S5-M7 | **Mirror firmato ma vecchio.** La firma prova l'origine, non la freschezza: un artefatto firmato mesi fa resta valido | L'indice firmato porta la data di costruzione e le identità dei contenuti. Valgono S5-M1 e una età massima dell'indice, in configurazione | E-05 |

### Bassi

- **S5-B1. Redirect.** ADR-0024 li ammette verso l'host dell'origine. Aggiungere: solo HTTPS a ogni passo, numero massimo di passi, nessuna credenziale inoltrata.
- **S5-B2. Richieste in uscita.** Indirizzi fissi senza parametri, intestazioni fisse, `User-Agent` senza nome dell'host, dell'utente o del repository. Un test con la rete simulata controlla che `--offline` non apra connessioni e che nessuna richiesta contenga dati del workspace.
- **S5-B3. Origine nel report.** L'origine è un'etichetta. Per un'origine diversa da `public` e dal mirror verificato, il report porta anche l'host, senza credenziali, e `gate` lo stampa tra gli avvisi: chi rivede una pipeline deve vedere da dove arrivano i dati che ordinano i finding.
- **S5-B4. Valori ammessi.** `knownRansomwareCampaignUse` si accetta solo tra i valori noti; `dateAdded` solo come data; l'identificativo della CVE con un modello stretto. La colonna `percentile` di EPSS si valida anche se non si usa.
- **S5-B5. Rilettura dalla cache.** Lo snapshot in cache si ricontrolla al caricamento: SHA-256 rispetto al puntatore e stessi controlli di forma. È la voce B-05 della Fase 1, qui più rilevante perché il file si legge sull'host.

### Effetto di un EPSS manipolato sul punteggio

Variante A, §6.1, per una dipendenza: P vale 1,0 se la CVE è in KEV, altrimenti il massimo tra EPSS e 0,01.

| Manipolazione | Effetto su P | Effetto oggi (D2-10) | Effetto con il livello da punteggio |
| --- | --- | --- | --- |
| EPSS abbassato o riga tolta | Fino a 0,01 | Ordinamento in ombra | Il livello scende fino a `basso`: S5-A1 |
| Voce tolta da KEV | Da 1,0 al valore di EPSS | Ordinamento in ombra | Cade l'override "in KEV e raggiungibile" di §6.3: S5-A1 |
| EPSS alzato | Fino a 1,0 | Ordinamento in ombra | Livello più alto: pipeline bloccate, visibile |
| Voce aggiunta a KEV | 1,0 | Ordinamento in ombra | Override a `critico`: pipeline bloccate, visibile |
| Feed reso irraggiungibile | Costante di ADR-0021 | Avviso | S5-M4 |

Gli altri fattori non cambiano e nessuna manipolazione esegue codice. Con più CVE sullo stesso finding si usa il massimo: per abbassare P vanno alterate tutte.

### Rischio che resta

Con origine `public` un file plausibile, recente e coerente con il precedente, ma alterato in poche righe, non si riconosce: le fonti non firmano. S5-M1 e S5-M2 alzano il costo, non lo eliminano. Lo chiude solo una fonte firmata, cioè il mirror di D2-05 costruito da una rete fidata, oppure la richiesta 1 o 2 di S5-A1, che toglie al feed il potere di abbassare un livello.

## Note comuni a S-01..S-04

Revisione di progetto del 2026-11-17 su ADR-0016, 0018, 0019, 0020, 0026, 0027 e 0028, in sola lettura sul codice (che per questi punti non esiste ancora, salvo il contratto `graph`). **Chi l'ha scritta è lo stesso agente che ha scritto gli ADR**: è una revisione per controllare l'ordine delle richieste, non un parere indipendente. Prima del Gate 2 serve S-06 sul codice, fatto da un revisore diverso. Fatti sui provider citati a memoria: nelle voci dove pesano sono marcati "da verificare".

## S-01 — Modello delle minacce del server

Esito: nessun critico, 2 alti, 6 medi, 3 bassi. Parere su D2-02 più sotto: la scelta presa regge con le condizioni indicate.

### Alti

**S1-A1. Lo stato «scansione corrente» non deve venire dal report.**
ADR-0018 definisce la scansione corrente come l'ultima `full` sul branch principale, e ADR-0016 collega un report al repository del token. Né l'uno né l'altro dicono da dove si legge il branch. Il report lo dichiara chi lo scrive. Su GitHub, ogni job di un flusso del repository, anche di una PR dallo stesso repository, può ottenere un token con `id-token: write` e caricare un report che si dichiara `full` su `main`: sposta `current_scan_id`, fa `risolti` i finding che mancano e riscrive `first_seen`.
Richiesta (ADR-0019, B-03): il tipo di scansione e il branch si derivano dalle attestazioni del token (`ref`, `sha`; su GitLab `ref_protected`), non dal report. Una scansione è `full` e può spostare la scansione corrente solo se `ref` è il branch principale registrato per il repository, e, dove il provider lo permette, il ref è protetto. Tutto il resto è `pr` o una scansione a parte che non cambia stato. Report e token devono concordare su `commit`, dove il token lo porta.

**S1-A2. Nessun limite per tenant a ingestione e archivio.**
ADR-0016 rimanda i limiti di frequenza a questo documento. 160 MiB per richiesta senza tetto sul totale permette a una pipeline compromessa, o a un tenant, di esaurire disco e database. Con l'adattatore S3 di ADR-0030 diventa anche un costo.
Richiesta (B-03): tetto di ingestioni per repository nell'unità di tempo e di richieste in parallelo per tenant (risposta 429 con `Retry-After`); quota di byte per tenant nella configurazione del server, con rifiuto 507 o 413 al superamento; la pulizia di ADR-0018 non basta perché non è un processo.

### Medi

| ID | Problema | Richiesta | Dove |
| --- | --- | --- | --- |
| S1-M1 | **Testo del repository nell'API e nella UI.** Titoli, percorsi, messaggi, `remediation` e motivazioni sono dati scelti da chi controlla il repository. ADR-0029 dice «testo, mai HTML» ma non c'è un test che lo imponga | Test in B-08 e W-05 con un report che contiene HTML, Markdown, URL e sequenze `javascript:`; `Content-Type` sempre esplicito, `X-Content-Type-Options: nosniff`; la SPA non usa `dangerouslySetInnerHTML` (regola di lint in `web/`) | B-08, B-09, W-05, W-01 |
| S1-M2 | **CSP della SPA.** ADR-0019 conta sulla CSP per limitare uno script iniettato, ma non la definisce | `script-src 'self'` senza `unsafe-inline` né `unsafe-eval`, `style-src 'self'`, `connect-src 'self'` più gli indirizzi dell'IdP, `frame-ancestors 'none'`, `base-uri 'none'`, `form-action 'self'`; nessuno script o font di terzi; test che legge le intestazioni | I-03, B-01, W-03 |
| S1-M3 | **CORS e CSRF.** Con token nell'intestazione `Authorization` e nessun cookie non c'è CSRF. Diventa vero solo finché resta così | CORS non abilitato (stessa origine). Il server rifiuta richieste con l'intestazione `Cookie` verso l'API e non imposta cookie. Se D2-02 passasse ai cookie di sessione, questa voce si riapre | B-01, B-04 |
| S1-M4 | **Registro delle modifiche modificabile.** `finding_events` è l'unica risposta verificabile a «chi ha accettato questo finding» (ADR-0018) | Solo inserimenti: nessun `UPDATE` né `DELETE` dal ruolo dell'applicazione (permessi PostgreSQL), eccetto la cancellazione del repository. Test | C-07, B-02 |
| S1-M5 | **Isolamento tra tenant per mappa degli schemi.** Un errore di cablaggio (sessione senza mappa, mappa condivisa tra richieste) espone un tenant a un altro | Test che apre due sessioni concorrenti con tenant diversi e cerca perdite; la sessione senza tenant fallisce in modo rumoroso; il nome dello schema si valida con la forma `t_<32 esadecimali>` prima di ogni uso | B-02 |
| S1-M6 | **Chiavi dei token e richieste in uscita.** Il server contatta gli indirizzi delle chiavi degli emittenti configurati: se la configurazione li lascia raggiungere reti interne è un canale di SSRF a configurazione sbagliata | Solo `https`; nessun redirect fuori dall'host configurato; limite di dimensione e di tempo della risposta; rifiuto degli indirizzi di loopback e di metadati cloud salvo l'opzione di sviluppo esplicita | B-04 |

### Bassi

- **S1-B1.** Il campo `owner` è testo libero: lunghezza e caratteri di controllo come per gli altri testi (ADR-0029). Già previsto, serve il test.
- **S1-B2.** I log del server non devono contenere né token né corpi (ADR-0016). Aggiungere un test che scorre i log di un'ingestione con un token riconoscibile.
- **S1-B3.** Il digest del report è la chiave di idempotenza: due report con lo stesso digest ma repository diversi sono già separati dal repository nella chiave (ADR-0016). Confermato; serve un test.

### C ed E dichiarati dal repository

ADR-0028 chiude il vettore con il file di contesto e con la regola «in PR vale il branch base». Resta un residuo: senza il server, il file lo scrive chi gestisce la pipeline, quindi chi modifica il flusso su una PR dallo stesso repository lo cambia. È lo stesso limite di `--fail-on` (ADR-0027) e va nella documentazione, non nel codice.

### Parere su D2-02

La scelta presa (token in memoria nella SPA, quattro ruoli, un tenant) regge, a quattro condizioni: S1-M1 e S1-M2 realizzati prima che la SPA mostri dati reali; durata massima del token di accesso un'ora, come in ADR-0019; nessuna libreria di terzi caricata a tempo di esecuzione; nessuna scrittura del token in storage persistente (test). Se una di queste non si riesce a garantire, il cookie di sessione dal server diventa la scelta più prudente. L'RBAC per tutto il tenant è accettabile per un tenant solo: va riaperto prima di averne due.

## S-02 — `ca-graph` su input ostile

Esito: nessun alto, 4 medi, 3 bassi. La divisione di ADR-0020 (parser in un container senza rete, resto sull'host sui dati) è corretta e regge a tutte le minacce considerate.

### Dove gira tree-sitter

Parere: giusto. Un difetto nel parser in C o in una grammatica ha come effetto massimo l'esecuzione dentro un container con workspace in sola lettura, senza rete, senza capability e con limiti di memoria e processi: è lo stesso rischio degli altri plugin. Eseguirlo nel processo della CLI lo porterebbe sull'host. Conferma anche il contratto `import-linter` che vieta di importarlo altrove.

### Medi

| ID | Problema | Richiesta | Dove |
| --- | --- | --- | --- |
| S2-M1 | **Tetti del contratto contro `max_bytes`.** `MAX_EDGES` è 2 milioni; a circa 200 byte per arco il grafo supera i 256 MiB del tetto del manifest. I due limiti non sono coerenti: vale il più basso, ma un documento valido per lo schema può essere rifiutato dal runner | Misurare il grafo dei pilota in G-09 e fissare `max_bytes` di conseguenza; abbassare i tetti dello schema a valori raggiungibili con quel limite (la misura di V-07: 6 milioni di nodi AST ma meno di 20 mila moduli e meno di 200 mila archi) | G-09, C-02 |
| S2-M2 | **Albero molto profondo.** Un file con migliaia di annidamenti costruisce un albero che una visita ricorsiva in Python non regge (`RecursionError`), e un limite di ricorsione alzato per rimediare è una porta al crash del container | Visita iterativa (cursore dell'albero), niente ricorsione sul contenuto; un file che supera un tetto di profondità o di nodi si conta come saltato, non fa fallire l'estrazione | G-02, G-03 |
| S2-M3 | **Collegamenti simbolici e file speciali nel workspace.** Un link che porta a `/proc` o fuori dal workspace, un FIFO, un file di dispositivo. Il workspace è in sola lettura ma l'estrattore lo legge | `lstat` prima di aprire; solo file regolari, senza seguire collegamenti, come `SourceReader` (ADR-0008); apertura con `O_NOFOLLOW` e `O_NONBLOCK` | G-02, G-03 |
| S2-M4 | **Storia git ostile per il churn.** Storia enorme (tempo e memoria), commit con date falsificate, oggetti corrotti | Un solo comando di lettura con tetti su commit letti e durata (già in ADR-0022); le date del commit sono dichiarate dall'autore e falsificabili: chi le sposta nel passato riduce il churn dei propri file e quindi P di smell e qualità. Effetto limitato a quelle due categorie e dichiarato nel report; non è un difetto da risolvere ma va scritto in ADR-0022 | G-11, ADR-0022 |

### Bassi

- **S2-B1.** Il contratto non vietava i caratteri di controllo nei percorsi (a capo, NUL, escape): un nome di file con `::error::` su una riga propria finiva in log, commenti e UI. **Corretto oggi** in C-02, con i casi nei test di contratto.
- **S2-B2.** `tsconfig.json` con catene di `extends` cicliche o molto lunghe: limite di passi già in ADR-0020, serve il caso di prova in F-01.
- **S2-B3.** `paths.exclude` del repository può togliere moduli dal grafo e quindi far sparire smell. È la stessa fiducia di ogni esclusione (ADR-0014); il report elenca le esclusioni.

## S-03 — Linter, IaC e coverage su input ostile

Esito: nessun critico, 1 alto, 4 medi, 3 bassi.

### Alto

**S3-A1. Il lettore XML dei report di copertura può essere aggirato dalla codifica.** *Chiuso in P-05 il 2026-11-17: parser `pyexpat` sui byte; F-03 ha ora gli stessi documenti in UTF-16 con e senza BOM, dopo commenti e con entità di parametro.*
ADR-0026 e la fixture F-03 respingono un documento che contiene `<!ENTITY`. Se il controllo è un confronto di stringa su testo, un documento in UTF-16 o con una dichiarazione di codifica diversa dal contenuto aggira la ricerca dopo la decodifica sbagliata, mentre il parser lo legge correttamente. Il lettore di prova della fixture ha la stessa debolezza.
Richiesta (P-05): non cercare il testo. Usare il parser di `pyexpat` con un gestore per le dichiarazioni di entità e di DTD che interrompe la lettura al primo evento, applicato sui byte. Se il formato prevede un DOCTYPE esterno innocuo (V-03), si ignora senza seguirlo, ma qualunque dichiarazione di entità è un rifiuto. Casi di prova in F-03: lo stesso documento ostile in UTF-8, UTF-16 con BOM, UTF-16 senza BOM con dichiarazione, e con la dichiarazione dopo commenti o istruzioni di elaborazione.

### Medi

| ID | Problema | Richiesta | Dove |
| --- | --- | --- | --- |
| S3-M1 | **Il percorso del report è del repository.** Va aperto senza seguire collegamenti simbolici, e la verifica di contenimento deve valere sul file aperto, non su un percorso controllato prima (TOCTOU) | `O_NOFOLLOW` e `fstat` sul descrittore: regolare e dimensione sotto il tetto; contenimento sul percorso risolto della cartella, non della stringa | P-05 |
| S3-M2 | **Soppressioni in linea non provate per ruff, eslint e hadolint.** *Aggiornamento 2026-11-17: provate per ruff (anche `# ruff: noqa` a livello di file, che `--ignore-noqa` copre), eslint (`--no-inline-config`) e hadolint (`--disable-ignore-pragma`, che ignora anche `global ignore`). Chiuso.* V-04 le elenca ma non le verifica. In più, `# ruff: noqa` a livello di file potrebbe non essere coperto da `--ignore-noqa` | Prova su ciascuno prima di fissare l'invocazione; se un'opzione manca, il plugin elenca le soppressioni trovate come finding `health` | P-01, P-02, P-04 |
| S3-M3 | *Realizzato in P-03 il 2026-11-17 con la copia di lavoro; provato con checkov reale.* **checkov con i file passati uno per uno.** Perde i riferimenti tra file Terraform. Il ripiego, una copia nel tmpfs senza i file di configurazione, è sicuro solo se la copia esclude davvero tutti i nomi che checkov legge (`.checkov.yaml`, `.checkov.yml`, `.checkov/`, il file di baseline) | Elenco di esclusione fissato e provato con un repository che li contiene tutti; i moduli remoti non si scaricano (`--download-external-modules` assente) | P-03 |
| S3-M4 | **YAML e HCL ostili.** Alias YAML che si espandono e file molto grandi arrivano a checkov e a hadolint. Il limite di memoria del container li ferma, ma il risultato è un plugin fallito e quindi una scansione `partial`: un repository può far uscire `gate` con 2 | Atteso, fail-closed: il gate non passa. Va nella documentazione. Provare il caso in P-03 per fissare memoria e `pids` | P-03, S-06 |

### Bassi

- **S3-B1. Canali di testo del file oltre `snippet`.** Il controllo del nucleo rifiuta solo `snippet`. I campioni di V-03 mostrano `fixes` (ruff), `source` e `suggestions` (eslint JSON). Parere: estendere il controllo del nucleo a quelle chiavi per il contratto dei plugin, così un errore di un adattatore non fa passare testo del repository. Per K-10.
- **S3-B2. `disable_rules`.** Il repository può spegnere regole: ogni regola spenta nasconde finding. Resta dichiarato nel report (ADR-0026); `gate` stampa su stderr il numero di regole disattivate insieme agli altri avvisi (D2-09), così chi rivede una pipeline lo vede.
- **S3-B3. Un report di copertura falso** (committato nella PR) nasconde i finding di copertura. Il livello è limitato a `medio`, quindi nessun effetto sul gate; in PR conta la configurazione del base che dice dove sta il report, non il contenuto.

### Configurazione eseguibile dei linter

Parere: la scelta di ADR-0026 (nessuna configurazione del repository, mai) è quella giusta e non va resa configurabile. eslint 10 non carica configurazione con `--no-config-lookup`, e i plugin si risolvono dalla posizione del file di configurazione dell'immagine. Due condizioni: la configurazione dell'immagine non imposta `parserOptions.project` né `projectService` (altrimenti legge il `tsconfig.json` del repository, che è un dato e non codice ma allarga la superficie); e `node_modules` del workspace non deve entrare nel percorso di risoluzione (test con un pacchetto ostile con il nome del parser).

## S-04 — Integrazioni CI

Esito: nessun critico, 1 alto, 5 medi, 3 bassi.

### Alto

**S4-A1. Il token OIDC si ottiene da ogni job del repository, anche da una PR dallo stesso repository.**
ADR-0027 chiede `id-token: write` per `upload`. Su `pull_request` da un ramo dello stesso repository il flusso è quello della PR: chi apre la PR può chiedere un token con la propria audience e il proprio `ref`. È il vettore di S1-A1. Lato CLI non si può evitare; si evita lato server (derivare ciò che conta dalle attestazioni del token), e lato Action (S4-M3).
Richiesta: ADR-0019 e B-03 come in S1-A1; la documentazione dell'Action dice di dare `id-token: write` solo al job che carica, mai a quello che analizza una PR.

### Medi

| ID | Problema | Richiesta | Dove |
| --- | --- | --- | --- |
| S4-M1 | **Iniezione di comandi del flusso nel log.** `gate` stampa su stderr gli avvisi del report e `scan --format table` stampa titoli. Una riga che inizia con `::` in un testo del repository (un titolo, un percorso) è un comando del flusso di GitHub: può mascherare parti del log, falsificare annotazioni o fermare l'elaborazione dei comandi | Ogni testo derivato dal report che la CLI scrive su stdout o stderr passa da una funzione che neutralizza `::` a inizio riga e i caratteri di controllo; l'Action esegue i passi che stampano con l'elaborazione dei comandi sospesa tramite un token casuale | N-02, N-04, K-13 |
| S4-M2 | **Testo nel commento: marcatore e autolink.** Un titolo può contenere il marcatore nascosto con cui si ritrova il commento, un riferimento a una issue, una menzione o un URL che il provider trasforma in collegamento | La neutralizzazione di ADR-0027 copre anche la stringa del marcatore, i riferimenti `#123`, `@nome` e gli indirizzi nudi; il commento da aggiornare si cerca per autore e marcatore, e il marcatore contiene un valore non ripetibile da chi scrive il report (identificativo del repository) | N-03 |
| S4-M3 | **Immagine e chiave pubblica sono ingressi del flusso.** Su una PR dallo stesso repository il flusso, e quindi `image` e la chiave, li decide la PR. Con accesso al socket del daemon, un'immagine CLI ostile è root sul runner | Documentare che il flusso va protetto dai meccanismi del provider; l'Action rifiuta immagini senza digest e verifica la firma prima di eseguire (ADR-0005); nessun valore predefinito che punti a un registry pubblico finché vale D2-16 | N-04 |
| S4-M4 | **Baseline: la ricerca dell'artefatto per nome.** ADR-0027 filtra per evento, branch e commit, ma un altro flusso nello stesso repository può pubblicare un artefatto con lo stesso nome | Filtrare per l'identificativo del flusso (file del flusso), non solo per il nome dell'artefatto; il nome dell'artefatto contiene il commit | N-04 |
| S4-M5 | **Socket del daemon nell'immagine CLI in CI.** Accesso al socket equivale a root sul runner (M-11 della Fase 1). Il rischio è accettato per chi usa già Docker nei job, ma l'immagine CLI va esaminata come codice con privilegio | Verifica di firma e digest dell'immagine CLI prima dell'uso; la CLI non esegue mai un'immagine che non sia nel manifest impacchettato; test che il socket non entra mai in un container plugin | N-04, I-01 |

### Bassi

- **S4-B1. `workflow_run`.** Come `pull_request_target`, gira nel contesto del ramo base con accesso a segreti; se il flusso fa il checkout del codice della PR diventa lo stesso problema. L'Action lo rifiuta come `pull_request_target`, o almeno avverte.
- **S4-B2. Annotazioni del check run.** `title`, `message` e `path` sono testo del repository: stessa neutralizzazione del commento, più il limite di lunghezza del provider.
- **S4-B3. GitLab: token per i commenti.** Se l'utente fornisce un token di progetto per commentare, va indicato il permesso minimo (non l'accesso completo all'API se esiste uno scope più stretto, da verificare alla fonte in N-07), e il token non deve arrivare ai container dei plugin (stesso test del token di GitHub).

### Claim OIDC verso il server

I nomi dei claim in ADR-0019 sono a memoria. Per GitHub ci si aspetta `repository_id`, `repository_owner_id`, `ref`, `sha`, `job_workflow_ref`; per GitLab `project_id`, `namespace_id`, `ref`, `ref_protected`. B-04 li conferma alla fonte. Oltre a S1-A1, conviene accettare `full` sul branch principale solo da `job_workflow_ref` (GitHub) uguale a un flusso registrato per il repository: così un flusso nuovo aggiunto da una PR non può spostare lo stato. È una scelta di B-04, da proporre all'utente se complica l'adozione.

### Socket nell'immagine CLI

Il rischio è quello di ogni strumento che lancia container dal job. Accettato per la Fase 2 dove il runner è di chi installa, e già dichiarato in ADR-0004. Non accettabile su runner condivisi con altri progetti: la documentazione lo dice.

## S-06 — Revisione dell'implementazione (2026-11-18)

**Come è stata fatta, e cosa non vale.** Revisione fatta dallo stesso modello che ha scritto una gran parte del codice (come S-01..S-05 per gli ADR): **non è indipendente** e non sostituisce una revisione di una persona. Per ogni rilievo di S-01..S-05 ho cercato nel codice e nei test la difesa richiesta; dove non c'era l'ho scritta e provata (voce «Corretto in S-06»), dove non l'ho cercata fino in fondo lo dico (voce «Non verificato»). Non ho eseguito un test di penetrazione né un fuzzing. Ho letto, per questa revisione, `packages/ca-api/`, i punti di ingresso di `ca-plugins`, `ca-graph` e `ca-integrations`, `integrations/github-action/` e `web/src/{api,auth}/`; non ho riletto per intero i plugin né gli adattatori.

**Esito.** Nessun critico. Dei rilievi alti (S1-A1, S1-A2, S3-A1, S4-A1, S5-A1) tre erano già realizzati e due non lo erano (S1-A2 solo in parte, S5-A1 per nulla, benché decisa dall'utente il 2026-11-16): li ho realizzati in questa revisione. Altri sei rilievi di grado medio o basso erano scoperti e sono stati corretti; restano aperti quelli elencati in «Rischio residuo».

### Stato dei rilievi

| ID | Stato | Evidenza |
| --- | --- | --- |
| S1-A1 scansione corrente dal token | **Verificato**, con un limite | `ca_api/ingest.py` (`_is_main_branch`): il tipo e il branch vengono dal `ref` del token e dal branch registrato, mai dal report; una PR e un ramo non principale non spostano lo stato (test di integrazione). Limite: `ref_protected` (GitLab) e `job_workflow_ref` (GitHub) non si usano; `sha` si confronta solo se il token lo porta |
| S1-A2 limiti per tenant | **Corretto in S-06**, in parte | `ca_api/throttle.py`: tetto di ingestioni per repository nell'ora (120) e di ingestioni in parallelo per tenant (4), configurabili (`CA_API_MAX_INGESTS_PER_HOUR`, `CA_API_MAX_CONCURRENT_INGESTS`, 0 li spegne), 429 `rate-limited` con `Retry-After`; ogni tentativo conta, anche se rifiutato. **Non c'è la quota di byte per tenant.** Lo stato sta nel processo: con più repliche il tetto vale per replica |
| S1-M1 testo del repository | **Verificato**; due difese aggiunte in S-06 | Test con markup ostile in W-04 e W-05 e nell'API; `X-Content-Type-Options: nosniff` ora su **ogni** risposta (`ca_api/headers.py`, prima solo sulla SPA); regola ESLint che vieta `dangerouslySetInnerHTML`, `innerHTML` e `outerHTML` fuori dai test |
| S1-M2 CSP della SPA | **Verificato** | `ca_api/spa.py` (I-03): script e stili solo della propria origine, nessun `unsafe-inline` né `unsafe-eval`, `connect-src` con la sola origine dell'IdP, `frame-ancestors 'none'`, `base-uri 'none'`; un nonce nuovo per risposta autorizza lo stile che Radix inietta. Test sulle intestazioni e prova in un browser vero contro l'immagine |
| S1-M3 CORS e CSRF | **Parziale**, per scelta | Nessun CORS e nessun cookie letto o impostato dal server. **Il rifiuto dell'intestazione `Cookie` non c'è**: i cookie si inviano per host e non per porta, quindi sarebbe rifiutata ogni richiesta di un browser con cookie di altre applicazioni su `127.0.0.1` o sullo stesso dominio, e il server non li legge comunque. Si riapre se D2-02 passasse ai cookie |
| S1-M4 registro delle modifiche | **Parziale** | Il codice inserisce soltanto in `finding_events` (nessun `UPDATE` né `DELETE`). Il ruolo di database dell'applicazione, però, ha tutti i permessi: **non c'è la protezione a livello di PostgreSQL** (stessa lacuna del ruolo per tenant, vedi sotto) |
| S1-M5 isolamento tra tenant | **Verificato**; prova aggiunta in S-06 | Il nome dello schema si valida (`SCHEMA_NAME`) prima di ogni uso; test di due tenant che leggono insieme per venticinque volte senza perdite (`test_api_reads.py`), oltre al test di un tenant che non vede le risorse di un altro. Limite noto: SQL grezzo qualificato attraverserebbe i tenant (nessun ruolo per tenant) |
| S1-M6 chiavi dei token e richieste in uscita | **Parziale** | `auth/jwks.py`: solo `https` (`http` solo su loopback con l'opzione di sviluppo), redirect solo verso lo stesso host, tetto di byte e di tempo. **Non si rifiutano gli indirizzi privati o di metadati cloud** per un host `https` configurato: la configurazione degli emittenti è dell'operatore |
| S1-B1 `owner` e testi liberi | **Corretto in S-06** | `owner` e le motivazioni rifiutano i caratteri di controllo e bidirezionali (a capo e tabulazione restano nelle motivazioni); test con 422 senza rimbalzare il valore |
| S1-B2 log senza token né corpi | **Parziale** | I log del server sono due righe fisse; test per l'eccezione non gestita (B-13). Nessun test che scorra i log di un'ingestione completa con un token riconoscibile |
| S1-B3 chiave di idempotenza | **Verificato** | Test dell'ingestione ripetuta e dello stesso report su repository diversi |
| Condizioni su D2-02 | **Verificate** | Durata massima del token un'ora (`max_token_lifetime_seconds`); nessuno script di terzi (CSP); il token non va in nessun archivio del browser, e lo dimostra un test e una prova nel browser; lo stato transitorio del flusso è in `sessionStorage` (vedi ADR-0019) |
| S2-M1 tetti del grafo | **Aperto**, basso | `MAX_EDGES` (2 milioni) e `max_bytes` del manifest (64 MiB) restano incoerenti: vale il più basso, e un grafo valido ma grande fa fallire il plugin |
| S2-M2 albero profondo | **Verificato per costruzione** | Le visite degli estrattori sono iterative (`while stack`); non ho eseguito un caso con migliaia di annidamenti |
| S2-M3 collegamenti e file speciali | **Verificato** | `treesitter/files.py`: `lstat`, `O_NOFOLLOW`, `O_NONBLOCK`, solo file regolari, tetti di dimensione |
| S2-M4 storia git ostile | **Verificato** | `treesitter/history.py`: tetti su commit e durata, interruzione del gruppo di processi, rifiuto di `.git` con collegamenti |
| S3-A1 XML della copertura | **Verificato** | `coverage_adapter.py`: `pyexpat` sui byte, qualunque dichiarazione di entità è un rifiuto |
| S3-M1 percorso del report | **Verificato** | `runner.py`: `O_NOFOLLOW` e controllo sul file aperto |
| S3-M2 soppressioni in linea | **Verificato** | ruff `--ignore-noqa`, eslint `--no-inline-config`, hadolint `--disable-ignore-pragma` |
| S3-M3, S3-M4 | **Verificati** / accettato | Copia di lavoro per checkov; un YAML ostile fa fallire il plugin e rende `partial`, effetto dichiarato |
| S3-B1 altri canali di testo del file | **Aperto** | Il controllo del nucleo rifiuta solo `snippet`; `fixes`, `source` e `suggestions` restano ammessi |
| S3-B2, S3-B3 | **Non verificati** | Chiusi nei task dai loro autori |
| S4-A1 token OIDC da una PR | **Corretto in S-06** nella documentazione | Il server deriva ciò che conta dal token (S1-A1). `doc/utente/server.md` ora dice di dare `id-token: write` solo al job che carica |
| S4-M1 comandi del flusso nel log | **Verificato** | `scan --format table` e `gate` stampano solo conteggi, codici, livelli e fingerprint, mai titoli o percorsi del repository |
| S4-M2 testo del commento | **Verificato** | `ca_integrations/github/format.py` (`clean_text`, `neutralize`) con i test di `notify` |
| S4-M3 immagine e chiave come ingressi | **Parziale** | Ingressi obbligatori senza valore predefinito; il README dell'Action lo dichiara. Un flusso modificato da una PR dello stesso repository decide ancora quali usare |
| S4-M4 ricerca della baseline | **Parziale** | Filtrata per evento, branch, commit e stato; **non per l'identificativo del flusso**: un altro flusso dello stesso repository può pubblicare un artefatto con lo stesso nome |
| S4-M5 socket del daemon | **Accettato** | Documentato in ADR-0004 e ADR-0027 |
| S4-B1 `workflow_run` | **Corretto in S-06** | L'Action ora rifiuta anche `workflow_run`, come `pull_request_target`; test |
| S4-B2, S4-B3 | **Non verificati** | Annotazioni del check run e permesso del token GitLab |
| S5-A1 limite inferiore dal CVSS | **Corretto in S-06** | Decisa dall'utente il 2026-11-16 ma **non realizzata** in ADR-0021 né nel codice: ora `overrides.dependency_cvss_floor` (da 9,0 `alto`, da 7,0 `medio`), indipendente dai feed e dalla raggiungibilità, con la prova di punta a punta di un EPSS azzerato |
| S5-M1 snapshot vecchio | **Corretto in S-06** | Uno snapshot con la data del contenuto precedente a quella dello snapshot in cache è rifiutato (`older-than-previous`), con `feeds-sync-failed` e lo snapshot precedente che resta |
| S5-M2 voci di KEV tolte | **Corretto in S-06** | Una voce presente nel precedente e assente nel nuovo è rifiutata (`kev-entry-removed`); le voci nuove sono benvenute |
| S5-M3 runner senza cache | **Aperto** | Senza uno snapshot precedente S5-M1 e S5-M2 non scattano; il report non lo dice |
| S5-M4 P senza EPSS | **Mitigato** | La costante `feed_missing` è in configurazione; il limite di S5-A1 impedisce che il feed assente nasconda un CVSS alto |
| S5-M5, S5-B1, S5-B4, S5-B5 | **Verificati** | Tetti in `limits.json`, lettura difensiva (`parse.py`: valori ammessi di `knownRansomwareCampaignUse`, forma di CVE e date), rilettura dalla cache (prove di «cache non fidata»), redirect solo https |
| S5-M6, S5-M7 mirror | **Non applicabili** | Nessun mirror in Fase 2 (D2-05) |
| S5-B2, S5-B3 | **Non verificati** | Richieste in uscita fisse; origine nel report |

### Rischio residuo da sottoporre all'utente

1. **Quota di byte per tenant (S1-A2).** I tetti di frequenza e di parallelismo ci sono, la quota no: un tenant può ancora riempire archivio e database caricando, nei limiti di frequenza, report grandi. Serve una colonna con la dimensione degli artefatti e una soglia per tenant. Decisione: farla in Fase 2 o accettare il rischio finché c'è un solo tenant (D2-02).
2. **Un solo ruolo di database senza permessi ridotti (S1-M4, S1-M5).** Il registro delle modifiche non è append-only per il database e SQL grezzo qualificato attraverserebbe i tenant. Un ruolo per tenant e uno per la sola scrittura del registro chiuderebbero entrambi. Con un solo tenant in esercizio è accettabile; va riaperto prima di averne due.
3. **Livelli minimi dal CVSS da calibrare.** I valori (9,0 → `alto`, 7,0 → `medio`) sono ipotesi come gli altri: più alti per fidarsi dei feed, più bassi per proteggersi da una manomissione. Si decidono con X-02.
4. **Quale flusso può spostare lo stato (S1-A1).** Lo stato della scansione corrente si sposta solo con un token il cui `ref` è il ramo principale, quindi non da una PR. Un flusso nuovo aggiunto direttamente al ramo principale, però, può farlo. Limitare il privilegio ai flussi registrati per il repository (`job_workflow_ref`) è una scelta di adozione, da proporre se serve.
5. **Revisione indipendente.** Questa revisione e le quattro precedenti sono dello stesso autore del codice. Prima di una distribuzione servirebbe l'occhio di una persona, in particolare su `ca_api/auth/`, `ca_api/ingest.py`, `ca_api/spa.py`, il runner dei plugin e `integrations/github-action/`.
6. **Aperti minori:** S1-M6 (indirizzi privati), S2-M1, S3-B1 (altri canali di testo), S4-M4 (artefatto per flusso), S5-M3 (cache assente non dichiarata), S1-B2 (test dei log di un'ingestione).

### Decisioni dell'utente sul rischio residuo (2026-11-18)

1. **Quota di byte per tenant: accettata finché c'è un solo tenant** (D2-02). Resta il rischio dichiarato qui sopra e si riapre prima del secondo tenant, insieme alla colonna con la dimensione degli artefatti e alla soglia per tenant.
2. **Un solo ruolo di database: accettato con un tenant solo.** La protezione a livello di PostgreSQL (ruolo separato per il registro delle modifiche, ruolo per tenant) si fa insieme alla quota e prima del secondo tenant.
3. **Valori del limite dal CVSS: restano 9,0 `alto` e 7,0 `medio`**, da calibrare in X-02 con gli altri valori di scoring. Contano solo con `levels.source: score`.

Restano da decidere, se serve, il rischio 4 (quale flusso può spostare lo stato) e la revisione indipendente prima di una distribuzione.
