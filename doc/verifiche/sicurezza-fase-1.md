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
