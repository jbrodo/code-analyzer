# ADR-0004: Esecuzione dei plugin e livelli di isolamento

- Stato: Accettato il 2026-11-08 dall'utente; rischio residuo da valutare con `security` (S-01)
- Data: 2026-11-08
- Decisione umana richiesta: sì (accettare un isolamento inferiore a gVisor in CI e in locale)
- Riferimenti: §2, §7.1, §7.2, §15; lacuna 8

## Contesto

§2 e §7 prevedono plugin in immagini firmate con gVisor o Firecracker. §2 chiede anche una CLI unica per CI, server e locale, dove quel runtime di norma manca: i runner CI ospitati e Docker Desktop non hanno `runsc`. Sulla macchina di sviluppo attuale Docker è presente, `runsc` e Podman no.

"Immagine CLI unica" e "`image` per plugin" (§7.1) sono in tensione: non è detto se gli scanner stiano dentro l'immagine CLI.

## Opzioni

1. **Immagine unica con tutti gli scanner, eseguiti come sottoprocessi.** Non serve Docker e funziona ovunque, ma cade la rete `none` per plugin, il file system è condiviso con la CLI e la firma non è per plugin. Contraddice §7.2.
2. **Solo gVisor/Firecracker.** Rispetta §2, ma la CLI non gira sulla maggior parte delle CI e in locale.
3. **Un'immagine per plugin, runtime OCI scelto a run time, con livello di isolamento dichiarato.**
4. **Come 3, con ripiego su sottoprocesso sull'host.** Massima portabilità, ma il codice analizzato viene elaborato senza confinamento.

## Raccomandazione

Opzione 3.

- Una sola forma di esecuzione: immagine per plugin (§7.1). "CLI unica" significa un solo codice e una sola immagine CLI, che orchestra le immagini dei plugin ma non le contiene.
- Porta `PluginExecutor` (ADR-0002) con adattatore `OciExecutor` per Docker/Podman in Fase 1. L'adattatore Kubernetes con gVisor arriva con il server.
- Livelli registrati nel report per ogni plugin: `gvisor` se `runsc` è registrato nel daemon, altrimenti `hardened-container`.
- `hardened-container` significa: `--network none`, root file system in sola lettura, workspace in sola lettura, `--cap-drop ALL`, `no-new-privileges`, utente non root, limiti di CPU, memoria e PID da `resources` del manifest, profilo seccomp predefinito.
- Il flag `--min-isolation` e il server impongono il livello: su server il minimo è `gvisor` e non è declassabile. Il valore non si legge mai da `.code-analyzer.yml` (ADR-0014).
- Nessun ripiego su sottoprocesso. Senza runtime OCI: exit 2 con messaggio esplicito.
- Firecracker non si implementa finché non serve un requisito che gVisor non copre.

Limiti da far rispettare al confine tra plugin e host:

- `/out` è una directory per plugin, nuova a ogni esecuzione. L'host legge solo file regolari, senza seguire symlink (`O_NOFOLLOW`), e con limite di dimensione.
- I limiti di byte e il loro valore si fissano nel piano misurando le fixture; il loader rifiuta un manifest senza limite.
- Argomenti di container costruiti come lista, senza shell; nessuna variabile d'ambiente dell'host viene passata al plugin.

Modalità di avvio della CLI:

- Installata sull'host: caso di riferimento di Fase 1.
- Da immagine CLI con socket del daemon montato: i plugin sono container fratelli, quindi servono percorsi host (`CA_HOST_WORKSPACE`, `CA_HOST_OUTPUT`). Il socket resta alla sola CLI e non viene mai esposto ai plugin. È un privilegio equivalente a root sull'host e va documentato.

## Conseguenze

- In CI e in locale l'isolamento è inferiore a quello di §2: la difesa è il confinamento del container, senza kernel intermedio. Il rischio residuo è un exploit del parser di uno scanner su contenuto ostile; va valutato dall'agente `security`.
- Le CI senza daemon (es. GitLab su Kubernetes senza DinD) restano non supportate finché non si aggiunge un adattatore; da trattare con il componente GitLab in Fase 2.
- §2 e §7 andranno precisati per dire che gVisor è obbligatorio solo su server.

## Emendamento dopo V-09

Data: 2026-11-08. Aggiunge requisiti misurati in V-07. La scelta (opzione 3) e i livelli di isolamento non cambiano.

- Il profilo `hardened-container` comprende anche `--tmpfs /tmp:rw,noexec,nosuid` e `HOME=/tmp`. Senza, trivy, semgrep e scancode non partono. Il root file system resta in sola lettura: `/tmp` è un'area scrivibile non eseguibile che sparisce con il container. `HOME` è un valore fisso del runner, quindi resta valida la regola che nessuna variabile dell'host arriva al plugin.
- Scrittura su `/out`: il plugin gira come `65534:65534`, diverso dal proprietario. Con permessi 755 non scrive, con 777 scrive e l'host legge i file creati (`nobody`, 644).
  - Per ogni esecuzione l'host crea una directory privata con permessi 0700 e al suo interno `/out` con permessi 0777. La directory esterna impedisce agli altri utenti locali di raggiungere la 0777.
  - Il plugin scrive in `/out` soltanto file regolari al primo livello: una sottodirectory creata da 65534 non sarebbe eliminabile dall'host.
  - La directory 0700 non è stata misurata in V-07: la prova R-02. `security` valuta il permesso 0777 in S-01.
- Un limite di 256 PID basta a scancode con `-n 2` e `-n 4`.
- Podman e gVisor non sono stati provati, perché assenti sulla macchina di sviluppo: R-02 e R-05 restano la prima verifica su quei runtime.

## Emendamento dopo A-01

Data: 2026-11-08. Esito della revisione di `plugin-manifest` e delle porte. La scelta (opzione 3) e i livelli non cambiano.

- `resources.pids` obbligatorio: confermato, è il limite di PID richiesto qui sopra.
- `outputs.max_bytes` ha un tetto di 268.435.456 byte (256 MiB) nello schema. Il file viene letto interamente in memoria e un valore errato non deve poter esaurire la macchina. Il tetto è provvisorio: il limite di ciascun plugin si fissa misurando con X-04.
- `sarif` e `cyclonedx` devono avere percorsi diversi: stesso percorso significa un file interpretato in due formati.
- La porta `SourceReader` serve anche a leggere `/out`, con radice `output_dir` e limite `outputs.max_bytes`. Il contratto è lo stesso: file regolari sotto una radice, senza seguire symlink, con limite di dimensione. La lettura avviene dopo l'uscita del container, quindi nessuno scrive in contemporanea.
- Il `SourceReader` non segue alcun symlink, nemmeno quelli che restano dentro la radice. È più stretto del "symlink che escono" di ADR-0008: un symlink riportato da uno scanner fa fallire il plugin in modo visibile nel report. Va rivisto se i repository pilota lo incontrano.
- `SourceTooLarge`, sottoclasse di `SourceError`, distingue il file oltre il limite da un percorso non valido. Il primo produce un finding senza contesto (ADR-0008), il secondo fa fallire il plugin: un solo file grande non deve rendere parziale la scansione.
- Il livello di isolamento si conosce prima di avviare i container: la porta `PluginExecutor` espone il livello disponibile, così `--min-isolation` esce con 2 senza eseguire alcun plugin.

## Emendamento: esito `invalid_output`

Data: 2026-11-08. Oggi un output rifiutato al confine di `/out` diventa `failed` con `exit_code` 0, in contrasto con la definizione di `failed`, e si riconosce solo leggendo `detail`. R-07 chiede un esito distinto.

Opzioni: un valore in `RunOutcome`, oppure un campo dedicato in `PluginRunResult`. Il campo aggiungerebbe combinazioni prive di senso (`ok` con motivo di invalidità); l'esito è già una scelta esclusiva.

Decisione: `RunOutcome.INVALID_OUTPUT = "invalid_output"`.

- Significa: container terminato con exit 0, ma un output dichiarato è assente, non regolare, un symlink o oltre `outputs.max_bytes`. `exit_code` è 0 e `output_dir` è `None`.
- `FAILED` torna a significare solo exit diverso da zero o container non avviato.
- La validazione del contenuto (schema SARIF e CycloneDX) resta in `ca-core`, dopo la porta, e non usa questo valore: il passo segna direttamente il plugin come fallito.
- `detail` nomina solo il file dichiarato nel manifest, mai contenuto dello scanner.

Report: `schemas/` non cambia. `PluginRun.outcome` resta `ok` o `failed`, perché §7.2 dice che l'output non valido è un plugin fallito e gate e finding `health` non distinguono le cause. `failure` riporta il `detail` senza prefissi, per esempio `output non valido: results.sarif` o `output oltre il limite: results.sarif`. È testo per le persone: nessun consumatore deve interpretarlo.

## Emendamento per R-09: `/out` su tmpfs, workspace illeggibile, ciclo di vita

Data: 2026-11-09. Attua A-01, A-02, M-01 e M-03 di S-01 (`doc/verifiche/sicurezza-fase-1.md`) e la decisione dell'utente dello stesso giorno: `/out` su tmpfs con dimensione massima, valore fissato misurando in X-04. La scelta (opzione 3) e i livelli non cambiano. Per `/out` sostituisce la directory 0777 dentro la 0700 e la regola "solo file al primo livello" dell'emendamento dopo V-09: il primo livello resta vincolo per i soli file dichiarati. Per `/feeds` vedi ADR-0006.

### Misure

Docker 27.3.1, cgroup v2, immagine `busybox:1.36`, 2026-11-09.

| Prova | Esito |
| --- | --- |
| `--mount type=tmpfs` con `tmpfs-size` e `tmpfs-mode` | Funziona, già `noexec,nosuid,nodev`. Non esistono `uid=`/`gid=`; `tmpfs-options` è rifiutato da questa versione, proprietario `root` |
| `--tmpfs /out:size=…,mode=0700,uid=65534,gid=65534,nr_inodes=…` | Funziona con proprietario 65534 |
| `docker cp` da un `--mount type=tmpfs`, container fermo o in esecuzione | Il file non si trova: `docker cp` non vede i tmpfs del container |
| Volume locale con `type=tmpfs`, `docker cp` a container fermo | Il file non si trova: il volume si smonta all'arresto e il contenuto sparisce |
| Stesso volume tenuto montato da un secondo container in esecuzione, `docker cp` da questo dopo l'uscita del plugin | Funziona. Il plugin scrive come 65534 e il tetto ferma la scrittura: 5 MiB chiesti, 2 MiB scritti con un tmpfs da 2 MiB. `noexec` provato: exit 126 |
| `docker cp <c>:/out/<nome> -` su symlink, FIFO, directory, file assente | Tar con voce di tipo symlink, FIFO o directory; nessun contenuto seguito. File assente: exit 1 e nessun tar |
| Volume montato `readonly` nel secondo container | Scrittura rifiutata |
| Tmpfs da 128 MiB con `--memory 32m`, scrittura di 64 MiB | Il processo che scrive è ucciso per memoria: le pagine del tmpfs sono addebitate al cgroup di chi scrive |

Quindi la correzione indicata da S-01, "volume tmpfs letto con `docker cp`", non basta da sola: serve un container che tenga montato il volume mentre l'host legge.

### A-01: opzioni

1. **Tmpfs del container più `docker cp`.** Non funziona, vedi Misure.
2. **Volume tmpfs per esecuzione, tenuto montato da un container di custodia.** Limite esatto del kernel, nessuna scrittura sul disco dell'host, dati fermi durante la copia.
3. **Bind mount con controllo a soglia durante l'attesa e `--ulimit fsize` (alternativa di S-01).** Nessun container in più, ma il controllo insegue la scrittura: T-03 ha scritto 256 MiB in 0,32 s. Scartata dall'utente.

Non si aggiungono componenti rispetto a §2: la custodia è un container in più con la stessa immagine già verificata.

### A-01: decisione

Opzione 2. **Per ogni esecuzione con `/out`**, in `_execute`, nell'ordine:

1. Volume, con `<hex>` lo stesso del nome del container:

   ```text
   <runtime> volume create --driver local --label code-analyzer.executor=1 \
     --label code-analyzer.expires=<epoch> \
     --opt type=tmpfs --opt device=tmpfs \
     --opt o=size=<T>,nr_inodes=1024,uid=65534,gid=65534,mode=0700,noexec,nosuid,nodev \
     ca-out-<hex>
   ```

2. Custodia, creata e avviata prima del plugin, in sola lettura sul volume. Stesso digest verificato, profilo `hardened-container`, nessuna rete, `--runtime` come il plugin:

   ```text
   <runtime> create --name ca-hold-<hex> --label code-analyzer.executor=1 \
     --label code-analyzer.expires=<epoch> --pull never --log-driver none --read-only \
     --cap-drop ALL --security-opt no-new-privileges --user 65534:65534 --network none \
     --cpus 0.1 --memory 32m --memory-swap 32m --pids-limit 8 \
     --mount type=volume,src=ca-out-<hex>,dst=/out,readonly \
     --entrypoint sleep <immagine@digest> <timeout+300>
   ```

   `sleep` viene dall'immagine del plugin, derivata da `plugin-base`. La durata è finita perché un client ucciso non lasci il container per sempre.
3. Plugin con `--mount type=volume,src=ca-out-<hex>,dst=/out`, al posto del bind mount.
4. All'uscita con 0, per ogni output dichiarato, copia del solo file (sotto).
5. Nel `finally`, nell'ordine: `kill` e `rm` del plugin, `kill` e `rm` della custodia, `volume rm`. Ogni passo è protetto a sé: uno che fallisce non salta i successivi, e il residuo si rimuove all'avvio successivo (M-03).

**Dimensione.** Funzione pura `out_tmpfs_bytes(outputs)`:

```python
OUT_MARGIN_MIN = 16 * 1024**2  # provvisorio, da confermare in X-04
declared = sum(p is not None for p in (outputs.sarif, outputs.cyclonedx))
data = declared * outputs.max_bytes
T = data + max(OUT_MARGIN_MIN, data // 4)
```

Il margine copre file temporanei dell'adattatore in `/out`, e fa sì che un output appena oltre `max_bytes` sia riconosciuto come `invalid_output` e non come scrittura troncata. Valori risultanti: `max_bytes` di 16 MiB, 32 MiB; 50 MiB, 66 MiB; 256 MiB (tetto dello schema) con un output, 320 MiB; con due output, 640 MiB. Il valore resta provvisorio: X-04 registra `max_bytes`, `T` e la dimensione reale, e conferma o corregge.

**Memoria.** `--memory` e `--memory-swap` diventano `byte(resources.memory) + T`, con `resources.memory` del manifest che resta il budget dello scanner. Altrimenti un output legittimo porterebbe allo stato `memoria esaurita`. Il massimo di memoria addebitabile a un plugin sale di `T`: è un valore noto per plugin e moltiplicato al più per `max_parallel` (B-01 resta aperto). Il valore si passa in byte: `_memory()` non basta più.

**Copia del file dichiarato**, nuova `_fetch_output(holder, name, max_bytes, dest_dir)`:

- `Popen([cli, "cp", f"{holder}:{OUT_DIR}/{name}", "-"], stdout=PIPE, stderr=DEVNULL, stdin=DEVNULL, env=_client_env())` con il nome da `_first_level_name` del manifest e un timer `_CP_TIMEOUT = 120` che uccide il client. Mai `-L`: i symlink non si seguono.
- Lettura in streaming con `tarfile.open(fileobj=proc.stdout, mode="r|")`, mai `extract` o `extractall`. Prima voce: `name` uguale al nome dichiarato, `type` in `{REGTYPE, AREGTYPE}`, altrimenti `_InvalidOutput("output non valido: <nome>")`. Così symlink, FIFO e directory sono rifiutati dal solo header, senza aprirli. `size > max_bytes`: `_InvalidOutput("output oltre il limite: <nome>")` prima di leggere il contenuto.
- Scrittura in `<run>/out/<nome>` con `O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC`, 0600, con lettura limitata alla `size` dichiarata. Meno byte del dichiarato, una seconda voce, un tar illeggibile o exit diverso da 0: `_InvalidOutput("output non valido: <nome>")`, file parziale compreso.
- `<run>/out` è creata dall'host con permessi 0700, non è più montata nel container e contiene solo copie dell'host: `OutputReader` e `PluginRunResult.output_dir` non cambiano, e `rmtree` riesce sempre. Il controllo dopo l'esecuzione (`_check_outputs`) diventa questa copia.

**File non dichiarati.** Non vengono letti, elencati né copiati: spariscono con `volume rm`. Sottodirectory comprese. Non è un errore e l'esito non cambia: un plugin che riempie `/out` di file non dichiarati danneggia solo se stesso (R-2 di S-01).

**Fallimento chiuso.** Se `volume create` o l'avvio della custodia falliscono, il plugin è `failed`. Non esiste ripiego su bind mount. Se la custodia muore prima della copia, il file non si trova e il plugin è `invalid_output`.

Elimina M-01 per `/out` e B-04. I due `xfail` strict di `tests/integration/runner/test_t03_out_hostile.py` vanno rimossi.

Limiti: non provato con Podman né gVisor (commenti `UNPROVEN`). Con `userns-remap` o Docker rootless `uid=65534` non corrisponde al 65534 del container e il plugin fallisce in modo visibile: da rivedere se servirà. Il costo in tempo dei due passi in più si legge nelle durate di X-04.

### A-02: workspace non leggibile

Controllo sull'host prima del lotto, in `scan.py`, dopo `prepare_workspace` e prima di `run_plugins`:

```python
# ca_plugins/source.py
def count_unreadable(root: str, excluded: Sequence[str]) -> int: ...

# ca_core/pipeline/exclusions.py
def coverage_exclusions(user_patterns: Sequence[str]) -> list[str]:
    """Predefiniti senza quelli esentati per un tool (`.git`), poi `paths.exclude`."""
```

La regola sta nell'adattatore e non in `ca-core`, perché 65534 è un dettaglio del runner: `SourceReader` non cambia. `PLUGIN_UID` e `PLUGIN_GID` sono costanti di `runner.py`.

Regola esatta:

- **Classe di permessi di 65534.** Se `st_uid == 65534` si usano i bit proprietario, altrimenti se `st_gid == 65534` i bit gruppo, altrimenti i bit "altri". Linux non somma le classi: un file 0604 di gruppo 65534 non è leggibile. Nel caso normale la regola coincide con `o+r` e `o+rx`.
- **Analizzabile:** ogni file regolare e ogni directory sotto la radice, radice inclusa, raggiunti senza seguire symlink, con percorso non escluso da `coverage_exclusions(config.paths.exclude)`. Symlink, FIFO, socket e dispositivi non sono analizzabili, non si seguono e non si contano. Si usa `lstat` tramite `os.scandir` e aperture con `O_NOFOLLOW`, come in `LocalSourceReader`.
- **`.git` conta**, anche se è un'esclusione predefinita: gitleaks legge la storia. I percorsi esclusi non contano e non si visita il loro interno: i loro finding sarebbero comunque scartati, e un `.env` 0600 si risolve con `paths.exclude`, che resta visibile nel report.
- **Leggibile:** file con bit `r`; directory con bit `r` e `x`.
- **Conteggio:** un'entrata analizzabile conta se non è leggibile o se un suo antenato non lo è. Ciò che sta sotto una directory non leggibile conta perché il plugin non può raggiungerlo; l'host lo visita se può. Una directory che l'host non riesce ad aprire conta una volta.
- Limiti: gli stessi `MAX_FILES` e `MAX_DEPTH` di `LocalSourceReader`. `SourceError` diventa `ScanError`, exit 2.

Esito con conteggio maggiore di 0:

- `status = partial`. I plugin girano comunque, perché i risultati parziali restano utili.
- `Warning_(code="workspace-unreadable", message="<n> percorsi non leggibili dai plugin: analisi incompleta")`, senza `subject`. Mai nomi di file, né nel report né su stderr. Una riga su stderr con lo stesso testo.
- `schemas/` non cambia: `partial` senza plugin falliti è già valido (ADR-0010). `gate` esce con 2 senza `--allow-partial`.

Conseguenze: un clone con `umask 077` è `partial` e la correzione è `chmod -R o+rX`. Le ACL POSIX non sono considerate e il controllo non è atomico rispetto all'esecuzione: l'estrazione del repository precede la CLI.

### M-03: interruzione e container orfani

Nella CLI, `main()`:

- Gestore unico per SIGINT, SIGTERM e SIGHUP, installato solo nel thread principale e ripristinato alla fine. Alla prima consegna imposta i tre segnali a `SIG_IGN`, poi solleva `KeyboardInterrupt`: un secondo segnale non interrompe la pulizia. Exit 2, come ogni scansione senza report (ADR-0010).
- `Context` ha un nuovo campo `close: Callable[[], None]`, predefinito no-op; `build_context` passa `executor.close`. `main()` lo chiama in `finally`. La porta `PluginExecutor` non cambia.

In `OciExecutor`:

- `self._active: set[str]` protetto da lock, e `self._stopping = threading.Event()`. Il nome del container si registra prima di `create` e si controlla `_stopping` subito dopo: chi registra dopo la scansione di `abort()` vede l'evento e si ferma.
- `abort()`: imposta `_stopping`, poi un solo `<cli> kill <nomi…>` con timeout di 10 secondi, poiché le CI concedono pochi secondi tra SIGTERM e SIGKILL. `_execute` esegue poi il proprio `finally`.
- `run_many`: dentro il `with`, `except BaseException: pool.shutdown(wait=False, cancel_futures=True); self.abort(); raise`.
- `close()` chiama `abort()` se ci sono container attivi, poi rimuove la radice di lavoro; è idempotente.
- Etichetta `code-analyzer.expires=<epoch>` su container e volumi: istante di `create` più timeout dell'esecuzione (`resources.timeout` o `feeds.sync_timeout`) più 900 secondi. È il "timeout massimo" di quell'esecuzione, senza un tetto globale e senza toccare le scansioni in corso di un altro processo sullo stesso daemon.
- Rimozione degli orfani: `_sweep_orphans()`, una sola volta per istanza, dopo il rilevamento del runtime e prima del primo `create`, quindi non da `isolation()`. `ps -a --filter label=code-analyzer.executor=1 --format '{{.Names}}\t{{.Label "code-analyzer.expires"}}'`; si rimuovono quelli con etichetta scaduta, assente o non numerica, con `rm --force --volumes`. Poi lo stesso con `volume ls`, e `volume rm`, che rifiuta un volume in uso. Migliore sforzo: un errore non ferma la scansione.

Residuo: con SIGKILL del client il plugin continua fino alla scansione successiva sullo stesso daemon; la custodia termina da sola. Sui runner CI effimeri sparisce con la macchina, e i runner persistenti condivisi senza gVisor non sono ammessi (decisione del 2026-11-09).

## Emendamento per I-03: modalità immagine CLI (M-11)

Data: 2026-11-09. Stato: **progetto rivisto da `security` (N-32..N-39), non implementato.** Il caso di riferimento resta la CLI installata sull'host.

Problema. Con la CLI in un container e il socket del daemon montato, i plugin sono container fratelli: i sorgenti dei `--mount` li risolve il daemon sull'host, non la CLI. Un percorso visto dalla CLI, passato tal quale, monterebbe una directory diversa o inesistente (M-11). Riguarda workspace, `/inputs` (sotto la radice di lavoro) e snapshot dei feed, in lettura e in scrittura. `/out` no: è un volume letto con `docker cp` dal client.

Progetto:

1. **Tre variabili, tutte o nessuna.** `CA_HOST_WORKSPACE`, `CA_HOST_WORK` e `CA_HOST_CACHE` danno il percorso host di tre montaggi con destinazione fissa nell'immagine: `/ca/workspace` in sola lettura, `/ca/work`, `/ca/cache`. Valgono solo dall'ambiente, mai da `.code-analyzer.yml` (ADR-0014). Se ne manca una: exit 2. `CA_HOST_OUTPUT` non serve: `/ca/output` è scritta solo dalla CLI e non è un sorgente di `bind_mount` (N-38).
2. **Traduzione per tipo, che fallisce chiusa (N-33).** `translate(kind, path)` con tipi chiusi: `workspace` solo sotto `/ca/workspace`, `inputs` solo sotto `/ca/work`, `snapshot` solo sotto `/ca/cache`. Usa `realpath(strict=True)` e `Path.is_relative_to`; un percorso fuori prefisso è `ScanAborted`, senza ripiego. Il traduttore si inietta nei cinque punti che chiamano `bind_mount`; il `guard` di `sync_feeds` resta sul percorso visto dalla CLI.
3. **Percorsi rifiutati all'avvio (N-32).** Exit 2 se un percorso host è uguale o antenato di `/`, `/run`, `/var/run`, `/proc`, `/sys`, DockerRootDir o del percorso reale del socket, se due radici coincidono o sono annidate, se `/ca/*` non risultano montaggi in `/proc/self/mountinfo`. `realpath(/ca/x)` deve essere `/ca/x`.
4. **Prova di identità (N-34, N-37).** Una sola volta, dopo la prima verifica di firma e prima di qualunque esecuzione con montaggi, compresi `sync_feeds` e `purge_feeds`. Su `/ca/work` e `/ca/cache`: nonce casuale a 128 bit in un file creato dalla CLI, letto da un container con l'uid della CLI, senza capability né rete. Su `/ca/workspace`: `st_dev`, `st_ino`, `st_mtime_ns` e hash dei nomi di primo livello. Fallisce se una radice contiene un socket. Output limitato in byte.
5. **Il socket resta alla sola CLI (N-32).** Un test controlla tutti gli argomenti dei comandi verso il runtime: mai il socket, il valore di `DOCKER_HOST`, `--volumes-from`, `--privileged`, `--pid`, `--ipc`. Il privilegio equivale a root sull'host e va dichiarato nella documentazione utente.
6. **Cablaggio e profilo (N-35, N-36, N-39).** In modalità immagine la radice di composizione imposta `work_dir=/ca/work`, `feeds_cache=/ca/cache`, `HOME`, `XDG_CACHE_HOME`, `DOCKER_CONFIG` e `--output-dir` sotto `/ca/output`. La CLI gira con `--user "$(id -u):$(id -g)"`, `--group-add` numerico del socket, `--cap-drop ALL`, `--read-only`, `no-new-privileges` e tmpfs su `/tmp`; uid 65534 rifiutato. All'avvio si rimuovono i soli `ca-oci-*` scaduti.
7. **Contenuto dell'immagine** (`deploy/docker/cli/`): CLI e `cosign` a versione e SHA-256 fissati, nessun plugin. La chiave pubblica (D-0005) si monta in sola lettura da un percorso host fidato, esterno a workspace, work e cache; non si prende dal repository analizzato. Sostituirla cambia il trust anchor e richiede un aggiornamento coordinato con la chiave privata della CI.

Fuori ambito: `DOCKER_HOST` remoto, dove la prova di identità fallisce e la scansione si annulla; Podman, ancora `UNPROVEN`.

Non verificato: snapshot LVM, ZFS o btrfs rispetto alla prova; Docker Desktop; daemon rootless o userns-remap; il costo del container di prova.

### Realizzazione (I-01, 2026-11-13)

Stato: **implementato.** `ca_plugins/hostpaths.py` (variabili, traduzione, controlli), `OciExecutor` (prova di identità, sorgenti tradotti nei cinque punti), `ca_cli/composition.py` e `deploy/docker/cli/`. Prove: `tests/unit/test_hostpaths.py` e `tests/e2e/test_packaging.py`.

Scostamenti e precisazioni rispetto al progetto:

- **`CA_CLI_IMAGE=1`**, impostata dal Dockerfile. "Tutte o nessuna" lascerebbe partire in modalità host una CLI nel container senza variabili, con percorsi che il daemon risolve sull'host. Con il marcatore, l'assenza delle tre variabili è exit 2.
- **Errori di configurazione alla prima esecuzione.** Le variabili si leggono all'avvio, ma l'errore esce quando serve il runtime: `gate` e `config validate` non usano container e funzionano senza.
- **Percorso reale del socket (punto 3).** Dal container non si conosce il percorso host del socket. Si rifiutano `/run` e `/var/run` e i loro antenati, e il percorso indicato da `DOCKER_HOST` visto dalla CLI. Un socket del daemon in una posizione insolita dell'host, sotto una radice montata, lo ferma il controllo dei socket del punto 4.
- **Socket nelle radici (punto 4).** Il controllo percorre le tre radici per intero, senza seguire i link, prima della prova.
- **Immagine della prova.** Il container di prova usa l'immagine del primo plugin verificato, con `python3` e un comando fisso. Tutte le immagini built-in hanno Python; un plugin esterno senza Python farebbe fallire la prova, quindi la scansione.
- **`purge_feeds`** non monta nulla se la prova non è ancora riuscita.
- **Scadenza di `ca-oci-*` (punto 6):** 24 ore dall'ultima modifica.
- **Client del runtime.** L'immagine contiene il client Docker 28.5.2, copiato dall'immagine ufficiale fissata per digest. Il progetto non lo nominava, ma senza client la CLI non parla con il daemon. È un componente in più per D2-14.
- **gVisor.** Sotto `runsc` device e inode visti dal container possono differire da quelli dell'host: la prova sul workspace fallirebbe chiusa. Non verificato.

Misure sulla macchina di riferimento: immagine di 327 MB; scansione di `python-app` dall'immagine `complete` con i 7 plugin `ok` e `verified`.

## Emendamento per K-06: collegamenti simbolici segnalati da un motore (2026-11-26)

Motivo: la prima volta che un repository reale ha incontrato la regola «un symlink riportato da uno scanner fa fallire il plugin» (sopra, «da rivedere se i repository pilota lo incontrano»). `vitejs/vite`, nel corpus del benchmark di ADR-0023, ha due file `.js` che sono collegamenti: eslint li segue e li segnala, l'host giustamente non li legge, e l'intero plugin fallisce. ruff fa lo stesso con un file `.py` collegato (provato); non segue le cartelle collegate.

- Il nucleo non cambia: il `SourceReader` continua a non seguire alcun collegamento, e un risultato su un collegamento continua a far fallire il plugin.
- Gli adattatori di ruff ed eslint scartano i risultati il cui percorso attraversa un collegamento simbolico del workspace (`through_symlink`, componente per componente). È la stessa regola che questo ADR dà per l'host: i collegamenti non sono analizzabili. La CLI già avvisa con `workspace-symlinks` che il loro contenuto non è analizzato.
- Gli altri adattatori non sono stati provati su un repository con collegamenti: chi legge i file da sé (bandit, semgrep, scancode, checkov, hadolint) può avere lo stesso problema. È un controllo da fare, non ancora un difetto osservato.
- Nello stesso lavoro: l'adattatore di eslint scriveva l'`uri` senza codifica percentuale, e una cartella chiamata `#` (anche questa in vite) faceva fallire il plugin. Ora codifica come fa ruff. Anche checkov, coverage, hadolint, osv-scanner, scancode e trivy costruiscono l'`uri` da un percorso grezzo: stesso controllo da fare.
