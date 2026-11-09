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

## Emendamento per P-07: configurazione git ostile (M-08)

Data: 2026-11-09. Attua M-08 di S-01. `safe.directory`, prescritto dall'emendamento dopo V-09, fa rientrare `.git/config` del repository analizzato, che è codice: un comando definito lì gira nel container del plugin. Sostituisce la sezione "gitleaks su repository di altro proprietario" per il modo di ottenere la lettura; il requisito resta (storia letta anche con altro proprietario, plugin fallito se non si può).

### Misure

git 2.53.0, `git log -p -U0 --full-history --all --diff-filter=tuxdb`, con la sola `safe.directory`; un comando di prova lascia un marcatore. Sorgente di gitleaks v8.30.1 (`sources/git.go`) letto il 2026-11-09; gitleaks non è stato eseguito.

| Vettore in `.git/config` | Default | Con `--no-textconv --no-ext-diff` | Con in più `--no-show-signature` e `GIT_NO_LAZY_FETCH=1` | Con git ombra |
| --- | --- | --- | --- | --- |
| `diff.<driver>.textconv` | Eseguito | Bloccato | Non provato (già bloccato) | Bloccato |
| `log.showSignature` e `gpg.ssh.program` | Eseguito | **Eseguito** | Bloccato | Bloccato |
| Promisor con `extensions.partialClone`, URL `ext::` e `protocol.ext.allow` | Eseguito | **Eseguito** | Bloccato | Bloccato |
| `diff.external`, `core.fsmonitor`, `core.pager` | Non eseguiti | Non provato | Non provato | Non provato |

`--log-opts` non è aggiuntivo: in gitleaks v8.30.1 se è valorizzato **sostituisce** `--full-history --all --diff-filter=tuxdb`. Il solo `--log-opts="--no-textconv --no-ext-diff"` richiesto da M-08 ridurrebbe la scansione alla storia di HEAD, senza errori. Inoltre gitleaks legge `.gitleaks.toml` dalla cartella analizzata e `.gitleaksignore` dalla cartella corrente: un repository può spegnere le regole o ignorare i propri finding.

### Opzioni

1. **`--log-opts` con l'elenco delle opzioni di disattivazione.** Lista di divieti: copre i vettori noti e si rompe al successivo, e va ripetuto a mano l'elenco di opzioni che gitleaks mette di suo.
2. **Git ombra:** una git dir pulita nel tmpfs dell'adattatore, con collegamenti ai dati. La configurazione ostile non viene mai letta.

### Decisione

Opzione 2. Nessuna `safe.directory`, nessun `GIT_CONFIG_COUNT` e nessun `--log-opts`.

L'adattatore, nel tmpfs `/tmp` del container, costruisce `<ombra>`:

- `config` scritta dall'adattatore: `core.repositoryformatversion` e `core.bare = true`, più `extensions.objectformat` (`sha1`, `sha256`) ed `extensions.refstorage` (`files`, `reftable`) solo se presenti e tra quei valori. Si leggono con `git config --file /workspace/.git/config --get`, che non segue gli include e non esegue nulla. Altri valori: plugin fallito con motivo fisso.
- `HEAD` **copiato**, dopo aver verificato che sia `ref: refs/…` con caratteri ammessi o un hash: git rifiuta un `HEAD` symlink verso un percorso assoluto.
- Symlink a `/workspace/.git/objects` e, se esistono, `refs`, `packed-refs`, `shallow`, `reftable`.

Ambiente di gitleaks e git: `GIT_CONFIG_NOSYSTEM=1`, `GIT_CONFIG_GLOBAL=/dev/null`, `GIT_ATTR_NOSYSTEM=1`, `GIT_NO_LAZY_FETCH=1`, cartella corrente vuota in `/tmp`, nessun altro `GIT_*`. Argomento: `gitleaks git <ombra>` con `--gitleaks-ignore-path <cartella vuota>`.

Errori di git. gitleaks può uscire con 0 dopo un errore di git, come per `dubious ownership` in V-07, quindi l'adattatore fa fallire il plugin per ogni riga `[git]` di livello errore nel log, oltre a quella già prevista. Un clone parziale ha blob mancanti e con l'ombra `git log` esce con 128 (provato): deve risultare fallito, non pulito. `.git` che non sia una directory (worktree collegato, sottomodulo): plugin fallito con motivo fisso.

Non misurato: l'ombra con oggetti di altro proprietario (le prove erano con lo stesso utente) e l'esecuzione con gitleaks reale. Li accerta il test qui sotto; se gitleaks rifiutasse la git dir ombra il punto torna in `architect` prima di ripiegare su `--log-opts`.

Conseguenze: il repository non controlla più né comandi né regole di gitleaks. Restano il parsing di pack ostili da parte di git e gitleaks, coperti da R-1, e la lettura dei file puntati da `objects/info/alternates`, che non esce dal container.

Prova, `tests/integration/test_gitleaks_hostile_repo.py`, sull'immagine reale con `docker run` e una cartella di marcatori montata in scrittura solo dal test:

- parametri `textconv`, `log.showSignature` con `gpg.ssh.program`, promisor `ext::`, `core.fsmonitor`, `core.pager`: nessun marcatore creato;
- controllo positivo: lo stesso repository con `git log` diretto nella stessa immagine, con `safe.directory`, crea il marcatore per i primi tre, così il test non passa per un vettore spento;
- segreto presente solo in un commit di un altro branch trovato con `--all` (nessuna perdita di copertura);
- `.gitleaks.toml` e `.gitleaksignore` ostili nel repository senza effetto;
- workspace di altro proprietario: segreto trovato senza `safe.directory`;
- clone parziale: plugin fallito.
