# ADR-0006: Database delle vulnerabilità in Fase 1

- Stato: Accettato il 2026-11-08 dall'utente
- Data: 2026-11-08
- Decisione umana richiesta: sì (flusso dei dati verso l'esterno)
- Riferimenti: §7.1, §7.2, §13, §15, §16 regola 7

## Contesto

Lacuna non elencata. osv-scanner e trivy sono in Fase 1 e hanno bisogno di un database di vulnerabilità. §7.2 ammette solo `none` o `feeds-only` verso "mirror interni", ma i mirror sono previsti in Fase 2. Così com'è, in Fase 1 questi due plugin non possono funzionare.

## Opzioni

1. **Rete verso gli endpoint pubblici durante la scansione.** Semplice, ma il plugin ha insieme sorgenti e rete, l'allowlist richiede un proxy di uscita e l'elenco dei pacchetti esce dal perimetro.
2. **Database incorporato nell'immagine.** Coperto dalla firma e senza rete, ma richiede ricostruzioni giornaliere e confligge con il digest fissato nella CLI.
3. **Sincronizzazione separata:** un passo con rete ma senza sorgenti scarica lo snapshot, poi la scansione lo monta in sola lettura e gira senza rete.
4. **Anticipare i mirror di Fase 2.** Aggiunge infrastruttura non necessaria a una CLI.

## Raccomandazione

Opzione 3, con l'invariante: **un container può avere il codice o la rete, mai entrambi**.

- Il manifest ha un blocco opzionale `feeds` con il comando di sincronizzazione e il percorso di montaggio (`/feeds`). `network` resta `none` per la scansione.
- La sincronizzazione usa la stessa immagine firmata del plugin, senza workspace né dati derivati dal repository.
- Snapshot in una cache per utente, riutilizzabile come cache CI. `scan` sincronizza se manca o è più vecchio di una soglia configurabile; `--offline` lo impedisce.
- Sincronizzazione fallita: si usa lo snapshot precedente con un avviso. Se non esiste alcuno snapshot, il plugin fallisce e la scansione è parziale.
- Il report registra origine e data dello snapshot per ogni plugin.
- Test: nessuna rete (§16); si usa uno snapshot congelato preparato da un job CI separato.
- In Fase 2 i mirror cambiano solo l'origine della sincronizzazione.

Le opzioni offline di osv-scanner e trivy vanno verificate sulle versioni fissate prima di chiudere il task.

## Conseguenze

- Durante la scansione non esce alcun dato sul codice o sulle dipendenze; la sincronizzazione scarica soltanto.
- Lo schema manifest cambia rispetto a §7.1, e `feeds-only` non viene usato in Fase 1.
- Uno snapshot avvelenato produrrebbe falsi negativi; i database non hanno sempre una firma propria. Rischio accettato per la Fase 1, da rivedere con i mirror.

## Emendamento dopo V-09

Data: 2026-11-08. Aggiunge requisiti misurati in V-05. La scelta (opzione 3) e l'invariante "codice o rete, mai entrambi" non cambiano.

Sincronizzazione, sempre senza workspace:

- osv-scanner: **non si usa `--download-offline-databases`**, perché scarica solo gli ecosistemi trovati nei file analizzati e quindi dipende dal repository. L'adattatore scarica direttamente `https://osv-vulnerabilities.storage.googleapis.com/<ecosistema>/all.zip` in `<snapshot>/osv-scalibr/<ecosistema>/all.zip`, nella stessa immagine firmata.
- L'elenco degli ecosistemi è fissato nel blocco `feeds` del manifest e non si ricava mai dal repository: npm e PyPI in Fase 1 (210 MB e 36 MB in V-05).
- trivy: `trivy fs --download-db-only --cache-dir D`, poi `trivy config --cache-dir D <directory vuota>` per le regole di configurazione (1,6 GB più 2,7 MB).

Scansione senza rete:

- osv-scanner: `OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY=D osv-scanner scan source --offline-vulnerabilities --no-resolve`. Senza `--no-resolve` tenta comunque la rete per risolvere `requirements.txt`.
- trivy: `trivy fs --offline-scan --skip-db-update --skip-check-update --skip-version-check --disable-telemetry --cache-dir D`.

Esiti di osv-scanner:

- Se manca il database di un ecosistema esce con 1, come quando trova vulnerabilità, e riporta risultati parziali. L'adattatore rileva `could not load db` e marca il plugin come fallito, anche per un ecosistema fuori elenco. Se i pilota lo incontrano in X-04 si allarga l'elenco.
- Senza pacchetti da analizzare esce con 128: è un esito vuoto, non un fallimento dell'analisi.

Restano aperti:

- Non è accertato se gli snapshot abbiano una firma verificabile. Vale il rischio già accettato nelle Conseguenze.
- La sola lettura è provata per trivy, non per osv-scanner: la prova P-03. Se osv-scanner non funzionasse con `/feeds` in sola lettura, il punto torna all'utente, perché tocca il montaggio deciso qui.

## Emendamento dopo A-01

Data: 2026-11-08. Esito della revisione del blocco `feeds`. La scelta (opzione 3) e l'invariante non cambiano.

- `network` ammette solo `none`: confermato. Riguarda il container di scansione; la sincronizzazione ha la rete per costruzione, senza workspace. `feeds-only` si aggiunge con i mirror, come aggiunta compatibile (ADR-0003).
- `feeds.sync_timeout` è obbligatorio e separato da `resources.timeout`: confermato, un download da 1,6 GB ha tempi diversi da una scansione. CPU, memoria e PID della sincronizzazione restano quelli di `resources`.
- `feeds.ecosystems` chiuso a `npm` e `PyPI`: confermato. I valori sono i nomi esatti del bucket OSV e l'enum chiuso impedisce che un manifest componga un URL arbitrario. Allargarlo è un'aggiunta compatibile (X-04).
- `ecosystems` vuoto significa che il plugin non scarica per ecosistema (trivy), non "nessun dato". Per osv-scanner lo controlla il test del manifest in P-03.

## Emendamento per R-09: spazio su disco e pulizia della sincronizzazione

Data: 2026-11-09. Attua A-01 e la parte di M-01 di S-01 che riguarda `/feeds`. La scelta (opzione 3) e l'invariante non cambiano. `/feeds` resta su disco: 1,6 GB di trivy non stanno in un tmpfs.

**Controllo durante la sincronizzazione**, in `OciExecutor.sync_feeds`:

- `FeedsSyncRequest` ottiene `max_bytes: int = Field(gt=0)`, obbligatorio, passato da `ensure_snapshot`.
- `_execute` riceve `guard: Callable[[], str | None] | None`. Con una guardia, `docker wait` gira in un `Popen` e il ciclo la chiama ogni `FEEDS_POLL_SECONDS = 1`. Se restituisce un motivo: `kill` del container ed esito `FAILED` con quel testo fisso. `ensure_snapshot` applica il percorso già previsto: cartella nuova scartata, snapshot precedente con avviso `feeds-sync-failed`, oppure plugin fallito.
- La guardia ferma la sincronizzazione se:
  1. spazio libero sul file system della cache (`statvfs`, `f_bavail * f_frsize`) inferiore a `FEEDS_MIN_FREE_BYTES = 2 GiB`. Vale anche prima dello start: sotto soglia il container non parte;
  2. byte allocati nella cartella (`st_blocks * 512`, somma con `scandir` senza seguire link) oltre `request.max_bytes`;
  3. più di `FEEDS_MAX_ENTRIES = 200_000` voci, che limita anche il costo del ciclo.
- Una sottodirectory illeggibile dall'host non ferma la guardia, che somma ciò che vede: la soglia su `statvfs` non dipende dalla visita. M-02 resta com'è, non bloccante.
- `container_args` riceve `file_size_limit: int | None`, che aggiunge `--ulimit fsize=<max_bytes>` alla sola sincronizzazione. Misurato su Docker 27.3.1: la scrittura si ferma al limite con SIGXFSZ. È un tetto per file, senza attesa.

Valore della soglia: T-03 ha misurato circa 800 MiB/s su ext4, quindi 2 GiB sono il doppio di ciò che si scrive tra due controlli a quel ritmo. È provvisoria come i `DEFAULT_MAX_BYTES` da 8 GiB, e X-04 la conferma insieme al picco reale della sincronizzazione.

**Pulizia (M-01).** I file scritti da 65534 dentro sottodirectory 0755 non sono eliminabili dall'host, quindi `_prune` e la pulizia di una sincronizzazione fallita lasciano snapshot interi senza errore. Questo è l'unico caso di M-01 non risolto dal tmpfs di `/out`.

- Porta `PluginExecutor`, nuovo metodo `purge_feeds(request: FeedsPurgeRequest) -> None`, con `FeedsPurgeRequest(manifest, snapshot_dir)`. Migliore sforzo: un fallimento non è un'eccezione. Lo implementano `OciExecutor`, `FakeExecutor` e `_FeedingExecutor` di `scan.py`.
- `OciExecutor.purge_feeds`: stesso digest, `--pull never`, nessuna rete, utente 65534, mount della sola cartella in `/feeds`, `--entrypoint python3` con un comando fisso nel codice del runner (`-I -S -c`, nessun dato dal manifest né dal repository) che dà `u+rwx` alle directory scendendo e rimuove tutto il contenuto, senza seguire symlink. Timeout di 300 secondi.
- `feeds.py`, funzione `_discard(path)`: `rmtree` con `ignore_errors`; se la cartella esiste ancora, `executor.purge_feeds`, poi di nuovo `rmtree`. Vale in `_prune` e nel ramo di sincronizzazione fallita. Non si chiama con un `ScanAborted` o un'interruzione in corso: lì l'immagine può non essere verificata, e la cartella resta alla prossima sincronizzazione, che la rimuove con `_prune`.
- L'immagine è quella appena usata per `sync_feeds`, quindi già verificata nella stessa esecuzione.
