# Verifiche di sicurezza della Fase 1

## S-01 — Rischio residuo di sandbox e firma

Revisione in sola lettura dell'agente `security`, 2026-11-08, su Docker 27.3.1. Eseguiti i test in `tests/integration/runner` tranne quelli di firma, che non sono stati rieseguiti in questa revisione. Riproduzioni di M-02 e M-08 in una cartella temporanea. I numeri di riga si riferiscono al momento della revisione.

Esito: nessun finding critico, 2 alti che bloccano R-09, 12 medi, 6 bassi. **La decisione sul rischio residuo spetta all'utente e non è ancora stata presa: R-09 resta aperto.**

### Alti (bloccano R-09)

**A-01. Nessun limite di disco durante la scrittura su `/out` e `/feeds`.** `ca_plugins/runner.py` controlla solo dopo l'uscita e solo i file dichiarati; `feeds.py` controlla a posteriori. T-03 ha misurato 256 MiB su ext4 in 0,32 s con `max_bytes` di 1 MiB. La radice predefinita è `/tmp` dell'host, `run_many` moltiplica l'effetto, e `release()` non ha chiamanti in produzione. Impatto: disponibilità dell'host. Correzione preferita per `/out`: volume tmpfs con `size=` per esecuzione, proprietario 65534, `noexec,nosuid`, letto con `docker cp` del solo file dichiarato (limite esatto, elimina M-01 e B-04, Podman non provato). Alternativa: controllo con soglia durante l'attesa più `--ulimit fsize=<max_bytes>`. Per `/feeds` serve comunque il controllo con soglia. Il valore del limite totale è da decidere. Serve un emendamento ad ADR-0004.

**A-02. Workspace non leggibile da 65534: la scansione può risultare `complete` e pulita.** Con `umask 077`, o con codice nascosto in file 0600 o directory 000, l'host vede i file ma il plugin no. Se lo scanner esce con 0, il report è `complete` e il gate passa. V-07 ha un precedente con gitleaks. Il comportamento dei singoli scanner su input illeggibile non è misurato. Correzione: controllo sull'host prima del lotto (`o+r` sui file, `o+rx` sulle directory), altrimenti stato `partial` con un avviso che riporta il conteggio e mai i nomi.

### Medi

| ID | Problema | Correzione | Blocca |
| --- | --- | --- | --- |
| M-01 | Sottodirectory create dal plugin in `/out` non rimovibili, errore silenzioso (2 `xfail` strict); stesso caso in `_prune` di `feeds.py` | L'opzione tmpfs di A-01, o container di pulizia e avviso | Da decidere; consigliato in R-09 |
| M-02 | `_validate_tree` di `feeds.py` passa su un sottoalbero illeggibile (riprodotto) | `onerror` che fa fallire la validazione, `lstat` protette | No |
| M-03 | Timeout e pulizia dipendono dal client: con SIGTERM il container continua; Ctrl-C lascia partire la coda; l'etichetta non è usata per pulire | Gestore di segnali, `cancel_futures=True`, rimozione dei container orfani all'avvio, `close()` nella CLI | Da decidere; consigliato in R-09 |
| M-04 | Il livello di isolamento dichiarato non è verificato: seccomp `unconfined` non è rilevato, `gvisor` significa solo che esiste `runsc`, nessuna versione minima del runtime | Leggere `SecurityOptions`, controllo dentro il container per gVisor, versione minima | No |
| M-05 | `docker` e `cosign` risolti da `PATH` con cwd nel repository; `cosign` controllato solo per versione dichiarata | Rifiutare percorsi relativi o sotto il workspace, SHA-256 di `cosign` per piattaforma | No |
| M-06 | Ancora di fiducia della firma nell'ambiente; il report non registra quale chiave | Chiudere D-0005, chiave nel pacchetto, impronta nel report | Primo rilascio |
| M-07 | `CA_INSECURE_ALLOW_UNSIGNED` senza avviso; con `gate --allow-partial` l'esito è 0 | Avviso su stderr; `signature-skipped` sempre exit 2 o flag separato | No |
| M-08 | `safe.directory` riattiva la configurazione git del repository: su una directory ostile, `textconv` esegue un comando con `git log -p` (riprodotto con git 2.53) | P-07: `--no-textconv --no-ext-diff` in `--log-opts`, con prova su `.git/config` ostile | P-07 |
| M-09 | Il container di sincronizzazione ha rete senza restrizioni, inclusi metadati cloud e reti private | Documentare il blocco con `DOCKER-USER` per host self-hosted | No |
| M-10 | Parsing SARIF senza limite di memoria: 23 MiB di `[{},...]` portano a +586 MiB di RSS | `RLIMIT_AS` in un sottoprocesso o conteggio preventivo; rivedere i tetti con X-04 | No |
| M-11 | Modalità immagine CLI con socket non progettata; un percorso diverso tra client e daemon porterebbe dati sbagliati nel plugin | Progettare e rivedere prima di costruire l'immagine CLI | Immagine CLI |
| M-12 | I test del confine non girano in CI; `.github/dependabot.yml` ha `package-ecosystem: ""` | Job con Docker e `cosign`; Dependabot su `uv`, `docker`, `github-actions`; ricostruzione al CVE | No |

### Bassi

- **B-01:** `max_parallel` conta i container e non la somma delle risorse; mancano `--ulimit nofile` e `core`.
- **B-02:** stderr di Docker nel report, ripulito ma non vuoto; usare messaggi fissi.
- **B-03:** `_FeedingExecutor` sincronizza con rete prima della verifica dell'intero lotto, e registra `signature: skipped` per un plugin non partito.
- **B-04:** `/out` non è `noexec`.
- **B-05:** snapshot in cache non rivalidato al caricamento; rinvio a S-02.
- **B-06:** `HTTP(S)_PROXY` non passato a `cosign`, variabili TLS di Docker non passate al client; falliscono chiusi.

### Verificati senza difetti

Firma prima dell'esecuzione e ordine digest/firma, senza TOCTOU tra verifica e pull; iniezione di argomenti; variabili d'ambiente verso il plugin; lettura di `/out`; permesso 0777 dentro la 0700 di `mkdtemp`; SARIF ostile e `secret_sha256`; race di `run_many` sulle directory; permessi della CI.

### Non verificato

gVisor e Podman; test di firma reali in questa revisione; i 6 scanner senza adattatore, incluso l'esito su input illeggibile; pipeline di rilascio dei digest; exploit reali di parser o kernel; CVE correnti delle versioni fissate; validità del file Dependabot lato GitHub.

### Rischio residuo (per D-0004, decisione dell'utente)

Parere di `security`: il confine è adeguato contro un exploit del parser su runner CI effimeri e postazioni di sviluppo, una volta corretti A-01 e A-02. Non è adeguato, senza gVisor, per host persistenti condivisi che analizzano repository di terzi.

| ID | Rischio | Stato |
| --- | --- | --- |
| R-1 | Exploit del parser senza kernel intermedio: esecuzione come 65534, con seccomp, senza capability né rete | Non eliminabile senza gVisor |
| R-2 | Integrità del risultato: un plugin compromesso può omettere finding con exit 0 | Non eliminabile nel runner |
| R-3 | Riservatezza dentro il container: il plugin legge workspace e storia git e può far uscire dati solo col report | Da accettare; riguarda chi conserva i report |
| R-4 | Snapshot dei feed avvelenato: falsi negativi | Già accettato in ADR-0006 |
| R-5 | Scanner fissati senza aggiornamento automatico (M-12) | Riducibile |

Decisioni dell'utente del 2026-11-09:

- R-1..R-5 accettati per CI effimere e uso locale, a condizione che A-01 e A-02 siano corretti e riverificati da `security`.
- Runner persistenti condivisi: non accettati senza gVisor.
- M-01 e M-03 inclusi in R-09.
- `/out` su tmpfs con dimensione massima; il valore del limite si fissa misurando in X-04.

## S-01 — Riverifica dopo R-09

Revisione in sola lettura di `security`, 2026-11-09, sul codice dopo R-09. Test con Docker reale: 206 passati, 1 fallito una volta (`test_subdirectory_in_out_is_invisible_to_the_reader[mode-000]`, passato alla ripetizione, causa non determinata, con gli E2E in parallelo).

**R-09 non è chiudibile:** servono correzione e riverifica di N-01 e N-02, correzione o accettazione esplicita di N-03, e una decisione su N-04.

| Finding | Esito |
| --- | --- |
| A-01 `/out` | Risolto: tetto del volume provato con Docker reale, 12 flussi tar ostili rifiutati |
| A-01 `/feeds` | Parzialmente risolto: byte controllati, inode no (N-03) |
| A-02 | Risolto |
| M-01 | Risolto |
| M-03 | Parzialmente risolto (N-02) |
| M-08 | Risolto: i vettori di esecuzione provati sono bloccati sull'immagine reale |

### Finding nuovi

| ID | Gravità | Problema | Correzione | Blocca R-09 |
| --- | --- | --- | --- | --- |
| N-01 | Alto | File di configurazione del repository spengono gli scanner senza traccia: con i binari fissati, `.trivyignore` e `trivy.yaml` portano trivy da 25 vulnerabilità a 0, `.syft.yaml` porta syft da 7 componenti a 0. `osv-scanner.toml` non riprodotto | `cwd` vuoto in `/tmp` e opzioni esplicite (trivy `--config "" --ignorefile ""`, syft `-c` su file vuoto, osv `--config` su file vuoto), con controllo positivo | Sì |
| N-02 | Medio | `_stopping` controllato una sola volta prima di `pull`: un segnale durante `pull` o preparazione lascia partire il plugin (riprodotto con client finto) | Ricontrollare prima di ogni `create` e `start`, e rifare il `kill` dopo `start` | Sì |
| N-03 | Medio | Inode non controllati in `/feeds`: file vuoti sotto una directory 000 sfuggono a guardia e validazione (riprodotto con 50 file) | Soglia su `f_favail` e `onerror` che fa fallire `_validate_tree` (anche M-02) | Sì, salvo accettazione |
| N-04 | Medio | Soppressioni in linea senza traccia: `gitleaks:allow` da 1 a 0 risultati, `# nosec` nasconde B307, `nosem` attivo in semgrep | Disattivarle o dichiararle nel report | Decisione dell'utente |
| N-05 | Medio | gitleaks non legge la working tree quando c'è `.git`: un segreto non committato non è analizzato, verificato sul codice | Aggiungere `gitleaks dir` o dichiarare il limite | No |

N-04, decisione dell'utente del 2026-11-09, valida per ora: le soppressioni in linea sono ignorate (ADR-0012).

Bassi: B-07 (`_prune` senza `lstat`, un symlink `snap-*` porta `purge_feeds` a montare la destinazione), B-08 (`expires` calcolato prima del pull), B-09 (B103 scrive un nome di file preso dal codice nel `message`), B-10 (`apt-get` senza versione in gitleaks e scancode).

Rischio residuo: le decisioni del 2026-11-09 restano valide. R-2 va riletto: l'accettazione presupponeva un plugin compromesso, mentre N-01 e N-04 permettono di nascondere risultati senza compromettere nulla. Nuovo residuo: con SIGKILL il plugin continua fino alla scansione successiva sullo stesso daemon.

Non verificabile: gVisor, Podman, `userns-remap`, Docker rootless; SIGKILL del client; soglia di spazio libero contro una scrittura veloce reale; `osv-scanner.toml`.

## S-01 — Seconda riverifica (N-01, N-02, N-03)

Revisione in sola lettura di `security`, 2026-11-09. Test con Docker reale e feed congelati: 192 passati. Le modifiche a bandit, gitleaks e semgrep notate durante la revisione sono l'applicazione di N-04.

| Finding | Esito |
| --- | --- |
| N-01 | Parzialmente risolto: risolto per trivy, syft, semgrep, bandit e `.gitleaks.toml`; restano N-06 e N-07 |
| N-02 | Risolto (15 `abort` su Docker reale, nessun residuo) |
| N-03 | Parzialmente risolto: pubblicazione bloccata e soglia corretta, ma il controllo ogni secondo non è un tetto rigido (misurati 298.000 file vuoti al secondo su tmpfs) |
| M-02, B-07, metà di B-08 | Risolti |

| ID | Gravità | Problema | Correzione | Blocca R-09 |
| --- | --- | --- | --- | --- |
| N-06 | Alto | Un `.gitignore` con il lockfile fa uscire osv-scanner con 128: l'adattatore lo trasforma in SARIF vuoto, esito OK (da 33 risultati a 0) | `--no-ignore`, con vettore nel test ostile | Sì |
| N-07 | Alto | In modalità `dir` gitleaks legge `<target>/.gitleaksignore` nonostante `--gitleaks-ignore-path`: da 2 risultati a 0 | Se il file esiste in modalità `dir`, far fallire il plugin o dichiararlo nel report; alternativa da provare | Sì |
| N-08 | Medio | `--ignore "*.git/*"` di scancode esclude ogni directory che finisce in `.git`: rinominare `third_party` in `third_party.git` nasconde una licenza | Limitare il pattern al componente `.git` | No |
| N-09 | Basso | `# trivy:ignore:*` riduce i risultati Dockerfile da 4 a 2; rientra nella decisione N-04 | Da valutare | No |

R-09 non è chiudibile finché N-06 e N-07 non sono corretti e riverificati, e finché l'utente non accetta o fa correggere il residuo di N-03.

Decisioni dell'utente del 2026-11-09: residuo di N-03 accettato per la Fase 1, soglia da rivedere in X-04; N-09 accettato, `# trivy:ignore:*` resta attivo sui Dockerfile perché trivy 0.76.2 non offre un'opzione per disattivarlo, e il limite va dichiarato nella documentazione utente (L-06).

## S-01 — Terza riverifica e controllo di classe

Revisione in sola lettura di `security`, 2026-11-09, sulle immagini ricostruite dagli adattatori attuali. Test mirati con Docker reale: 159 passati. N-06, N-07 e N-08 sono risolti.

Domanda esaminata: in quali condizioni controllabili dal repository il plugin esce con successo con un risultato vuoto o ridotto senza traccia nel report. Criterio di blocco: il file resta usabile, i risultati spariscono in blocco, non c'è traccia e nessun altro scanner della stessa categoria li riporta.

| ID | Scanner | Condizione | Gravità | Prova | Blocca R-09 |
| --- | --- | --- | --- | --- | --- |
| N-10 | osv-scanner, trivy | Lockfile come symlink verso un file con altro nome | Alto | npm: osv 33→0, trivy 34→0; Poetry 25→0 e 25→0 | Sì |
| N-10b | semgrep | Sorgente JS come symlink verso un file con altra estensione | Alto per JS/TS | 1→0, semgrep è l'unico SAST per JS/TS | Sì |
| N-11 | semgrep | File oltre 1 MB (`--max-target-bytes`): basta un commento di riempimento | Alto per JS/TS | JS 1→0, Python 2→0 (bandit mantiene i 2 di Python) | Sì |
| N-12 | osv, trivy, syft | Lockfile corrotto o vuoto | Medio | osv 33→0, trivy 34→0, syft 7→0 | No |
| N-13 | gitleaks | Allowlist del `gitleaks.toml` predefinito (`*.png`, `*.bin`, `package-lock.json`, `node_modules/` e altri) | Medio | 1→0 | Decisione dell'utente |
| N-14 | gitleaks | Byte NUL nel file in modalità `git` | Medio | 1→0; in modalità `dir` il segreto è trovato | Decisione dell'utente |
| N-15 | bandit | Errore di sintassi, NUL, `coding` inesistente: il file è saltato, l'avviso è scartato dall'adattatore | Medio | 2→0; semgrep trova ancora quei casi | No |
| N-16 | bandit | `.tox`, `.eggs`, `__pycache__`, `CVS`, `.hg`, `.svn` esclusi di default | Basso | 2→0; semgrep li vede | No |

Altri limiti bassi da dichiarare: `"dev": true` nel lockfile (trivy 34→0, syft 7→2, osv resta 33); lockfile in `node_modules/` o rinominato; script senza estensione; per scancode directory VCS, `.gitignore`, `.gitattributes` e testo UTF-16.

Esiti negativi: `.gitattributes` con `-diff` o `binary`, `vendor`, `test`, `dist`, `build`, directory nascoste e 40 livelli di profondità non riducono i risultati di osv, trivy e syft; 10 MB di riempimento sui lockfile non riducono nulla.

Vincolo: `ca_core` non legge `invocations` del SARIF dei plugin, quindi le note degli adattatori non arrivano al report; ogni traccia va emessa da `report.warnings`.

Non verificato: timeout per regola di semgrep; lockfile corrotto insieme a uno valido in osv; ecosistemi diversi da npm e PyPI.

Decisione dell'utente del 2026-11-09: N-13 e N-14 accettati e da dichiarare nella documentazione utente (L-06).
