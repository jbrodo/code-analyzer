# ADR-0027: Integrazioni CI

- Stato: Proposto. Stesura chiusa; D2-12 e D2-13 (aperte) ne chiudono la parte di pubblicazione. Il parere di `security` arriva con S-04
- Data: 2026-11-16
- Decisione umana richiesta: sì, per dove si pubblicano e si provano Action e componente (D2-12, D2-13, D2-16). No per il resto
- Riferimenti: §12.1, §12.2; ADR-0001, 0004, 0010, 0011, 0016, 0019, 0025, 0026; V-02 e V-08 in `doc/verifiche/scanner-fase-2.md`; incoerenze 12, 13 e 18 del piano

## Contesto

§12.1 descrive un'Action `using: docker` che passa `--fail-on` a `scan`. Entrambe le cose non reggono più: ADR-0010 ha separato `scan` da `gate`, e la CLI avvia i plugin come container fratelli (ADR-0004, I-01), quindi le serve il daemon del runner. §12 non dice chi scrive il commento sulla PR e il check run, con quale token, da dove arriva la baseline (ADR-0025 lo rimanda qui), né cosa succede con una PR da un fork.

Con ADR-0016 il server non parla con i provider e non conserva credenziali: tutto ciò che scrive su una PR parte dalla pipeline. Ma ADR-0001 non permette a `ca-cli` di importare `ca-integrations`.

I fatti sui provider citati qui (permessi del token nei flussi da fork, limiti delle API, ambito degli artefatti) sono riportati a memoria, salvo quelli letti in V-02. N-04 e N-07 li verificano alla fonte prima di implementare, e ogni differenza corregge questo ADR.

## Opzioni

### Chi scrive commento e check run

1. **La CLI nella pipeline**, con il token del job.
2. Il server, con una GitHub App: richiede credenziali a lunga durata sul server e i webhook, entrambi esclusi da ADR-0016.

### Forma dell'Action

1. `using: docker` con l'immagine CLI, come §12.1: un solo comando per esecuzione, quindi `scan`, caricamento del SARIF e `gate` non si possono ordinare.
2. **Action composita** che esegue i passi in ordine, lanciando l'immagine CLI con accesso al daemon.

## Raccomandazione

Opzione 1 per chi scrive, opzione 2 per la forma.

### Dove sta il codice

- `ca-integrations` dipende solo da `ca-core`. Contiene: la composizione del commento e delle annotazioni come funzioni pure sul report (N-03); le conversioni verso i formati di GitLab (N-06); i client delle API dei provider (N-02).
- **`ca-cli` può importare `ca-integrations`**: è una radice di composizione. È l'emendamento di ADR-0001 (A-16). Resta il divieto per `ca-cli` di importare framework web e driver di database.
- `ca-api` non importa `ca-integrations` in Fase 2.
- I client usano lo stesso client HTTP di `upload` (ADR-0016). Una dipendenza nuova segue §16 regola 2.

Comandi nuovi della CLI, da aggiungere ad ADR-0010 in A-16:

| Comando | Cosa fa | Exit |
| --- | --- | --- |
| `notify --provider github [--report FILE]` | Crea o aggiorna il commento della PR e il check run | 0 fatto o saltato con avviso, 2 errore. Mai 1 |
| `export --format FORMATO [--report FILE] --output FILE` | Converte il report in un formato nativo del provider | 0, 2 |

`gate` resta l'unico comando che decide (ADR-0010). `notify` non cambia l'esito di una pipeline: un provider irraggiungibile non fa né passare né fallire il gate.

### Commento sulla PR

- **Uno per PR.** Il corpo contiene un marcatore nascosto. `notify` cerca un commento con il marcatore **scritto dall'identità del token** e lo aggiorna; se non c'è lo crea. Un commento di un altro autore con lo stesso marcatore si ignora.
- **Solo finding nuovi** (stato `new` di ADR-0025), con i conteggi di esistenti e risolti. Senza baseline valida il commento lo dice ed elenca i finding che bloccano.
- Ordinati come l'elenco (ADR-0029), con un tetto in configurazione (predefinito 20) e il numero dei rimanenti. Per un gruppo di correlazione compare un solo finding, con gli strumenti degli altri (ADR-0026).
- Per ogni finding: livello, titolo, regola, posizione, e la correzione se c'è (ADR-0029). Avvisi della scansione e stato `partial` in testa.
- **Tutto il testo che viene dal report è non fidato**: titoli, messaggi e percorsi vengono dal repository e dagli scanner. Si rende come testo: caratteri di Markdown e HTML neutralizzati, menzioni e riferimenti automatici disattivati, nessun collegamento costruito da quei testi, lunghezze limitate. Nessun frammento di codice e nessun valore di segreto: il report non ne contiene (ADR-0012), e N-03 lo prova comunque.
- Il corpo resta sotto il limite di dimensione del provider; oltre, si tronca l'elenco, mai un finding a metà.

### Check run

- Un check run per esecuzione, sul commit di testa della PR.
- Conclusione calcolata con la stessa funzione del nucleo che usa `gate`: `failure` se il gate fallirebbe, `neutral` se la scansione è parziale, `success` altrimenti. Una sola implementazione della regola; il comando che fa fallire il job resta `gate`.
- Annotazioni sui finding nuovi che hanno una posizione: `critico` e `alto` come errore, `medio` come avviso, `basso` come nota. Tetto in configurazione (predefinito 50, il massimo per richiesta); il resto nel riepilogo.
- Serve a chi non ha la scansione del codice del provider: con quella attiva, il caricamento del SARIF produce già le proprie annotazioni, e il check run si può disattivare.

### Token e permessi su GitHub

Solo il token del job. Nessun token personale e nessuna App in Fase 2.

| Permesso | Serve a | Quando |
| --- | --- | --- |
| `contents: read` | Checkout | Sempre |
| `actions: read` | Scaricare la baseline dall'esecuzione del branch principale | PR |
| `pull-requests: write` | Commento | PR, se il commento è attivo |
| `checks: write` | Check run | PR, se il check run è attivo |
| `security-events: write` | Caricamento del SARIF | Se attivo |
| `id-token: write` | Token OIDC per `upload` | Se c'è un server (ADR-0019) |

- Il token arriva alla CLI da una variabile d'ambiente, mai da un argomento, e non compare nei log.
- **Nessuna variabile d'ambiente della pipeline arriva ai container dei plugin.** È già così per costruzione del runner; N-02 aggiunge il test con il token presente.
- Le action di terzi usate dentro la nostra si fissano per hash del commit, con le versioni verificate in N-04.

### Passi dell'Action

`integrations/github-action/action.yml`, composita:

1. Controllo dell'evento. Con `pull_request_target` l'Action si ferma con un errore (vedi sotto).
2. Su una PR: recupero della baseline.
3. `scan`, con `--pr --base --baseline` su una PR.
4. Su un push al branch principale: il report si conserva come artefatto del flusso, con un nome fisso.
5. Caricamento del SARIF, se attivo, anche quando un passo precedente è fallito.
6. Su una PR: `notify`.
7. Con `server-url`: `upload`.
8. `gate`, per ultimo.

Ingressi: `fail-on`, `variant`, `server-url`, immagine e chiave pubblica per la verifica della firma, e gli interruttori di commento, check run e SARIF. Non c'è un'immagine predefinita su un registry pubblico: finché valgono D2-16 e la decisione sulla pubblicazione, l'Action funziona solo nelle pipeline che costruiscono e firmano le immagini da sé, come `e2e.yml`.

Correzioni a §12.1 per A-17: Action composita; `--fail-on` su `gate`; `fetch-depth: 2` basta al confronto, la storia completa serve solo alla copertura di gitleaks (ADR-0025).

### Baseline su GitHub

ADR-0025 chiede che la baseline arrivi da fuori dal repository e sia del commit base.

- **Commit analizzato e commit base.** Su una PR si analizza il commit di merge che il provider prepara; il base è il suo primo genitore, cioè la punta del branch di destinazione in quel momento. Così la differenza è esattamente ciò che la PR introduce. Commento e check run si attaccano al commit di testa.
- **Fonte 1: artefatto.** L'Action cerca l'esecuzione dello stesso flusso che ha `push` come evento, il branch principale come branch e il commit base come commit, e ne scarica il report. Queste tre proprietà le attesta il provider, non il contenuto della PR.
- **Non la cache della CI.** Una cache si cerca prima nell'ambito del branch corrente: un flusso aggiunto dalla PR potrebbe salvarne una con la stessa chiave e farla trovare al posto di quella buona.
- **Fonte 2: scansione del base nello stesso job**, se l'artefatto manca (esecuzione ancora in corso, artefatto scaduto). Il base si estrae in una cartella a parte e si analizza per intero, con la sua configurazione. Attiva per default; costa una scansione in più (ADR-0025).
- Senza nessuna delle due vale la regola di ADR-0025: avviso e gate come `all`.

### PR da fork e `pull_request_target`

- Su un flusso `pull_request` che parte da un fork il token è di sola lettura e non ci sono né segreti né token OIDC. `scan` e `gate` girano normalmente. `notify` riceve un rifiuto: scrive il contenuto del commento nel riepilogo del job, registra un avviso ed esce con 0. `upload` si salta con un avviso. La baseline si legge, perché l'artefatto è leggibile; altrimenti vale la fonte 2.
- **`pull_request_target` non è supportato.** Quel tipo di flusso dà a contenuto scelto da chi apre la PR un token con permessi di scrittura e i segreti del repository. I plugin sono isolati, ma un difetto nell'isolamento o nella CLI esporrebbe quel token. L'Action si rifiuta di partire e la documentazione spiega perché.
- Il commento per le PR da fork richiederebbe due flussi, uno senza privilegi che analizza e uno privilegiato che pubblica il risultato. Non entra in Fase 2.

Limite da dichiarare: su `pull_request` il file del flusso è quello della PR, quindi chi apre la PR può togliere il gate modificando il flusso. Il prodotto non può impedirlo. Chi deve imporre il gate usa i meccanismi del provider per eseguire un flusso da un ramo protetto; la documentazione (L-05) lo indica.

### GitLab

- Componente in `integrations/gitlab-component/templates/code-analyzer.yml`. Vive in un progetto GitLab e si può usare solo dalla stessa istanza (V-02): il monorepo su GitHub ne è la fonte, la copia sull'istanza è di D2-12.
- **Serve un runner con un daemon di container** raggiungibile dal job, per esempio con il servizio Docker-in-Docker. Le CI senza daemon non sono supportate (ADR-0004). Il componente lo controlla all'inizio e fallisce con un messaggio chiaro.
- Passi: `scan`, `export` verso i report nativi, `upload` se c'è un server, `gate`. Il job fallisce secondo il gate.
- Report nativi di §12.2, prodotti da `export` dal report (N-06): `sast`, `dependency_scanning`, `codequality`, `cyclonedx`. I finding di segreti, licenze, IaC e architettura non hanno posto in quei quattro: restano nel report e nel SARIF, conservati come artefatti. Il formato dei segreti di GitLab è un'aggiunta possibile, non richiesta da §12.2.
- Gli schemi dei report di GitLab hanno una licenza permissiva (V-02): si includono tra gli schemi di terzi per i test di contratto (C-09).
- Token OIDC per `upload` chiesto con la parola chiave del provider per i token di identità, con l'`aud` dell'installazione (ADR-0019).
- **Nessun commento sulla merge request per default.** Il token del job non può scriverlo, e l'alternativa è un token di progetto a lunga durata. Il componente accetta una variabile con un token fornito dall'utente e in quel caso commenta; senza, non lo fa.
- Baseline: l'API degli artefatti dà l'ultimo artefatto di un branch, non quello di un commit, e ADR-0025 respinge una baseline di un altro commit. La fonte predefinita su GitLab è quindi la scansione del base nello stesso job; l'artefatto si usa quando il commit coincide.

### Cosa resta bloccato

Sviluppo e prove di Action e componente usano il registry locale avviato nel job (N-04, N-05, N-07). Restano bloccati: l'uso da repository esterni e la pubblicazione (N-09: D2-13, D2-16, I-04), e le prove del componente su un'istanza reale (N-08: D2-12). Il Marketplace richiede un repository pubblico dedicato con il file dell'Action alla radice (V-02): la sottocartella del monorepo è la forma della Fase 2, come raccomanda D2-13.

## Conseguenze

- ADR-0001 cambia: `ca-cli` importa `ca-integrations`. L'immagine CLI cresce dei client dei provider, non di framework.
- ADR-0010 guadagna `notify` ed `export`; §12.1 e §12.2 si correggono in A-17.
- Senza server, tutto ciò che un utente vede su una PR dipende dai permessi del token del job. Con i permessi minimi mancanti `notify` degrada con un avviso, non fallisce.
- Le PR da fork non ricevono il commento. Il risultato è nel riepilogo del job e nell'esito del gate.
- Su GitLab i finding che non entrano nei quattro report nativi si vedono solo negli artefatti, e senza un token dell'utente non c'è commento. È meno di quanto offre GitHub: va scritto nella documentazione.
- Ogni pipeline deve conservare il report del branch principale come artefatto, o pagare una seconda scansione per PR.
- S-04 rivede: token nell'ambiente della CLI, testi non fidati nel commento, fonte della baseline, rifiuto di `pull_request_target`.

### Realizzazione del client GitHub (N-02, 2026-11-17)

`ca_integrations.github`. Scostamenti e fatti nuovi:

- **Identità dell'autore.** Con il token del job `GET /user` non è disponibile, quindi l'identità con cui riconoscere il proprio commento la dà il chiamante (predefinito `github-actions[bot]`), non l'API. Un commento con il marcatore ma di un altro autore si ignora.
- **Marcatore iniziale.** Il commento si riconosce solo se *inizia* con il marcatore: un marcatore nel mezzo di un testo non conta.
- **Trasporto.** Solo libreria standard, senza dipendenze nuove. Nessun redirect seguito (il token andrebbe a un altro host), HTTPS obbligatorio salvo loopback richiesto esplicitamente, tetto di 5 MiB sulla risposta, timeout, nessun nuovo tentativo.
- **Ricerca del commento** al più su 20 pagine da 100; oltre si crea un commento nuovo invece di cercare all'infinito.
- **Non verificato alla fonte:** i limiti di dimensione e le annotazioni per richiesta di GitHub, e i nomi esatti dei permessi, restano quelli scritti a memoria in `ca_integrations.limits`. Chi li legge alla fonte è N-03.

## Realizzazione di N-03 e di `notify` (2026-11-17)

- `ca-cli` dipende ora da `ca-integrations` (consentito da `lint-imports`); il pacchetto entra nei wheel di `package-cli.sh`. **L'immagine della CLI non è stata ricostruita**: da provare prima dell'uso.
- `notify --provider github` legge il token solo da `GITHUB_TOKEN`. Repository, PR e commit di testa vengono dai flag, poi dal report (`scan.pull_request`) e dal file `GITHUB_EVENT_PATH`, validati; un valore malformato vale come assente. Ordine per la PR: flag, report, evento.
- Un permesso mancante (`forbidden`) scrive il commento nel riepilogo del job e esce con 0; ogni altro errore esce con 2 con il solo codice. Un commento fallito non ferma la check run.
- Le annotazioni non sono neutralizzate per Markdown: GitHub le mostra come testo. Sono pulite da caratteri di controllo e bidirezionali e limitate in lunghezza.
- **Da verificare alla fonte** (non fatto): limiti di GitHub su commenti, annotazioni e riepilogo; il fatto che un backslash davanti a `@` e `#` non basti, motivo per cui si aggiunge anche il carattere invisibile.
