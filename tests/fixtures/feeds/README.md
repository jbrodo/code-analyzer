# Snapshot congelato dei feed (F-05)

Gli E2E di rilevamento dei CVE (`tests/e2e/test_detection_cve.py`, T-08) non usano la rete: leggono
uno snapshot dei feed scaricato una volta, datato e con checksum SHA-256. Lo snapshot sta fuori dal
repository (1,9 GB: database di trivy 1,7 GB, osv-scanner npm 220 MB e PyPI 38 MB). Questa cartella
contiene solo la procedura. La usa il job `feeds-snapshot` della CI (O-03).
ADR-0006, spec §16 regola 7.

## Formato

```
<snapshot>/osv-scalibr/npm/all.zip         osv-scanner (nomi del bucket OSV)
<snapshot>/osv-scalibr/PyPI/all.zip
<snapshot>/trivy/db/trivy.db               trivy (+ metadata.json, policy/)
<snapshot>/enrichment/{epss,kev}/                          EPSS e KEV: `current.json` e `snap-*/data` (O-03)
<snapshot>/SNAPSHOT.json                   created_at, trivy_db_updated_at, sha256 e dimensione di ogni file
```

E' lo stesso albero che i plugin vedono in `/feeds` (cache `<cache>/<plugin>/snap-*` di
`ca_plugins/feeds.py`), con le due cartelle dei plugin affiancate.

## Procedura

1. **Scaricare** (unico passo con la rete), con il prodotto: `code-analyzer scan <repo>` senza
   `--offline` con i plugin osv-scanner e trivy ne sincronizza i feed nella cache per utente
   (`~/.cache/code-analyzer/feeds/<plugin>/snap-*`). Finche' I-04 non produce manifest
   impacchettati con digest non e' eseguibile da una installazione vera. I database dello snapshot
   attuale erano gia' scaricati (misure di P-03 e P-05); il download non e' stato rieseguito per
   F-05, quindi questo passo e' descritto e non provato qui.
2. **Congelare**, senza rete:

   ```
   python tests/fixtures/feeds/snapshot.py freeze --from-cache ~/.cache/code-analyzer/feeds --dest <snapshot>
   # oppure, da due cartelle gia' scaricate (osv-scalibr/ in --osv, trivy/ in --trivy)
   python tests/fixtures/feeds/snapshot.py freeze --osv <dir> --trivy <dir> --enrichment <dir> --dest <snapshot>
   ```

   `freeze` rifiuta una destinazione non vuota (uno snapshot non si sovrascrive), richiede i tre
   file obbligatori (`npm/all.zip`, `PyPI/all.zip`, `trivy.db`) e lo snapshot corrente di EPSS e
   KEV, che la stessa scansione del passo 1 sincronizza, e scrive `SNAPSHOT.json`.
3. **Verificare**: `python tests/fixtures/feeds/snapshot.py verify <snapshot>` ricalcola gli SHA-256
   (circa 7 s) e fallisce se un file manca, e' cambiato o e' stato aggiunto.
4. **Usare**: `CA_TEST_OSV_FEEDS=<snapshot> CA_TEST_TRIVY_FEEDS=<snapshot>` (le stesse variabili
   delle prove sulle singole immagini). Il laboratorio E2E verifica gli SHA-256 dei due sottoalberi,
   li collega con hard link (copia se e' un altro volume) in una cache per utente temporanea e
   scrive `current.json` con la data dello snapshot e il digest dell'immagine firmata. Con
   `--offline` il prodotto lo usa anche se vecchio e aggiunge l'avviso `feeds-stale`: e' previsto.

## Cosa prova e cosa no

- Prova che i CVE attesi (`expected-findings.yaml`) sono rilevati con questo snapshot: lo dice T-08,
  non il checksum. Un nuovo snapshot va accettato solo se T-08 resta verde: un CVE ritirato o
  riclassificato dal feed cambia gli attesi, non il test.
- Il checksum prova che il file non e' cambiato, non che il contenuto sia quello del feed pubblico.
- Se la data di `SNAPSHOT.json` e' vecchia, il test non lo segnala: invecchia da solo, come un
  lockfile. In CI lo rinnova il job `feeds-snapshot`, due volte alla settimana.
- Uno snapshot salvato prima di O-03 non ha EPSS e KEV: gli E2E lo accettano, e T-08 controlla che
  il report dica `enrichment-feed-missing`. Con uno snapshot nuovo controlla che la scansione usi
  proprio quei file (stesso SHA-256).
- Nessuna prova scarica i feed: in CI la cache predefinita punta a una cartella vuota e il job
  fallisce se alla fine contiene dei feed. Copre chi usa la CLI senza una cache propria, come
  faceva `test_scan_e2e.py` fino al 2026-11-26; non una prova che scaricasse altrove.

Prove della procedura: `pytest tests/fixtures/feeds` (file piccoli, senza rete).

## Snapshot ridotto di EPSS e KEV (F-04)

A differenza dei database di osv-scanner e trivy, questo sta nel repository: `enrichment/` contiene
i due file nel formato pubblicato (CSV di EPSS con l'intestazione di FIRST, JSON di KEV di CISA),
ridotti ai CVE delle fixture (`tests/fixtures/repos/*/expected-findings.yaml`) piu' due CVE reali
di controllo. ADR-0024, spec §16 regola 7. Lo legge `enrichment_snapshot.py`; le prove sono in
`tests/unit/test_feeds_fixture_snapshot.py`.

- **Fonte.** La cache per utente della CLI, sincronizzata dai feed pubblici il 2026-11-17 (EPSS
  `v2026.06.15` del 2026-11-17, KEV `2026.11.17`). I valori EPSS sono quelli pubblicati. Di KEV
  restano solo `cveID`, `dateAdded` e `knownRansomwareCampaignUse`, i campi che il nucleo legge.
- **Voci inventate.** Nessun CVE delle fixture e' in KEV. Per provare il ramo KEV, CVE-2021-44906
  e CVE-2018-18074 sono state **aggiunte** al catalogo con data 2026-11-17: sono dati di prova, non
  un fatto. `SYNTHETIC_KEV` in `enrichment_snapshot.py` le elenca e un test controlla che siano le
  sole. Le altre due voci KEV (CVE-2021-44228, CVE-2026-115731) sono reali.
- **Copertura.** Tutti i 13 CVE delle fixture hanno un EPSS. CVE-2021-23337 e' sopra la soglia di
  0,1 dell'override EPSS (ADR-0021), gli altri sotto; CVE-2024-29041 e' anche sotto il minimo di P
  (0,01).
- **Uso.** `snapshot_feeds()` da' la porta `EnrichmentFeeds` per i test dello scoring;
  `seed_cache(dir, downloaded_at)` scrive lo snapshot nella cache dei feed, da leggere con
  `load_enrichment(..., limits=LIMITS)`. Con i limiti di produzione (`limits.json`: almeno 100 000
  voci EPSS e 500 KEV) lo snapshot e' rifiutato come implausibile, ed e' voluto: per questo non
  vale per una CLI lanciata da un E2E, che con `--offline` lo scarterebbe. Il rinnovo con i feed
  della CI e' O-03.
- **Aggiornarlo.** Se cambia l'elenco dei CVE delle fixture il primo test fallisce: aggiungere la
  riga EPSS presa da uno snapshot pubblico e scrivere qui la data.
