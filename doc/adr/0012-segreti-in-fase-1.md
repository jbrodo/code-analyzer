# ADR-0012: Rilevamento dei segreti in Fase 1

- Stato: Accettato il 2026-11-08 dall'utente: livello `alto` per i segreti non verificati e disattivazione di B105, B106 e B107. Riaperto da V-09 sull'invariante del valore e aggiornato nell'emendamento in fondo
- Data: 2026-11-08
- Decisione umana richiesta: sì (livello dei segreti non verificati; verifica online futura)
- Riferimenti: §3, §6.3, §7.2, §7.3, §13, §15; lacuna 7

## Contesto

§6.3 rende Critico un "segreto valido esposto", ma stabilire la validità significa provare il segreto contro il servizio emittente, e i plugin hanno `network: none`. `trufflehog` è in §3 ma non in §7.3 né in Fase 1. A quanto noto all'autore è AGPL-3.0, condizione da confermare (ADR-0015).

## Opzioni

1. Solo gitleaks, nessuna verifica, nessun segreto dichiarato "valido".
2. trufflehog con verifica online in Fase 1: mette insieme sorgenti, segreto e rete, viola §7.2 e l'invariante di ADR-0006 e contatta servizi terzi con credenziali reali.
3. gitleaks più un plugin di verifica separato con uscita limitata: la strada corretta se la verifica servirà, ma è prematura.

## Raccomandazione

Opzione 1.

- `evidence.validity = "unverified"` su ogni segreto. L'override "segreto valido" di §6.3 non si applica in Fase 1.
- Livello `alto` per tutti i segreti: blocca con il gate predefinito, ma non afferma una validità non provata. In alternativa `critico`, più prudente ma più rumoroso.
- Il valore non lascia mai il container: l'adattatore lavora sull'output grezzo in un percorso interno, calcola l'hash per il fingerprint (ADR-0008) e scrive in `/out` un SARIF oscurato. L'emendamento in fondo estende la regola a tutti i plugin e sostituisce il controllo sul valore, che la CLI non conosce, con un controllo strutturale.
- Storia git: in Fase 1 tutte le scansioni sono complete, quindi si analizza tutta la storia disponibile. Con clone superficiale il report segnala la copertura ridotta.

Se in seguito servirà la verifica: plugin con capability `enrich`, esplicitamente abilitato, che riceve solo il segreto e il tipo di servizio, senza workspace. Va deciso con un nuovo ADR in Fase 2 o oltre.

## Conseguenze

- Nessun finding viene classificato per validità: anche i token già revocati bloccano, finché non c'è un'eccezione o una pulizia.
- Le fixture devono usare segreti finti riconoscibili, per non attivare la protezione dei push né creare rischi reali.
- Una sentinella di test deve risultare assente da report, SARIF, stdout e log.

## Emendamento dopo V-09

Data: 2026-11-08. V-04 e V-07 smentiscono due presupposti: che il valore possa uscire solo da gitleaks, e che gitleaks legga sempre la storia. L'opzione 1 resta; il livello `alto` o `critico` resta in D-0012.

### Il valore può uscire da altri plugin

- bandit B105 scrive il valore in chiaro in `message.text` e negli snippet (`region` e `contextRegion`). semgrep emette lo snippet della riga trovata, che può contenere un segreto anche quando la regola riguarda altro.
- gitleaks con `--redact` lascia `snippet: "REDACTED"`, e il controllo "snippet assente" fallirebbe sul suo SARIF non rielaborato.

Raccomandazione:

1. bandit si esegue con `--skip B105,B106,B107`. I segreti sono compito di gitleaks.
2. Ogni adattatore rimuove `snippet` da tutto il SARIF che scrive in `/out`. Il fingerprint non ne risente: il contesto del codice si legge dal `SourceReader` (ADR-0008).
3. La CLI fa fallire il plugin se un SARIF contiene la chiave `snippet` a qualunque profondità, per qualunque plugin. Per gitleaks controlla anche che `message` sia conforme al modello oscurato. La CLI non conosce il valore, quindi il controllo è strutturale.
4. Le regole Semgrep del progetto non interpolano metavariabili in `message`. Il test sentinella copre anche una regola che lo fa, perché le regole indicate dal repository (`plugins.semgrep.rules`) non sono sotto il nostro controllo.

Costo: con B105, B106 e B107 disattivate, le password a bassa entropia scritte nel codice Python non si rilevano se gitleaks non le riconosce. V-04 indica queste regole come "già coperte da gitleaks", ma la copertura non è stata misurata. L'alternativa è tenerle e riscrivere `message` per regola: più codice nell'adattatore e un rischio che ritorna a ogni nuova regola con il valore nel testo. Le fixture non devono attendersi queste tre regole.

### gitleaks su repository di altro proprietario

Esce con 0 e zero risultati, con `dubious ownership` solo nel log: un falso negativo che sembra un esito pulito. L'adattatore imposta `GIT_CONFIG_COUNT=1`, `GIT_CONFIG_KEY_0=safe.directory`, `GIT_CONFIG_VALUE_0=/workspace` e, se nel log compare comunque quell'errore, marca il plugin come fallito. P-07 lo prova con un test dedicato su un workspace di altro proprietario.

### Dati dell'output gitleaks

- `partialFingerprints` contiene `commitSha`, `email`, `author`, `date` e `commitMessage`. L'adattatore non scrive quei campi in `/out`: il commit, se serve, va in `Location.commit`. Autore, email e messaggio non escono dal container, salvo una scelta esplicita futura.
- L'hash del fingerprint (ADR-0008) richiede il valore, quindi l'adattatore esegue gitleaks senza `--redact` su un percorso nel tmpfs interno e scrive in `/out` solo il SARIF oscurato. I campioni di V-04 sono stati prodotti con `--redact`, quindi questo flusso è da provare in P-07.
