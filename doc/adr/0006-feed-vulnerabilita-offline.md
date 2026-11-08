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
