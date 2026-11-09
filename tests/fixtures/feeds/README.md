# Snapshot congelato dei feed (F-05)

Gli E2E di rilevamento dei CVE (`tests/e2e/test_detection_cve.py`, T-08) non usano la rete: leggono
uno snapshot dei feed scaricato una volta, datato e con checksum SHA-256. Lo snapshot sta fuori dal
repository (1,9 GB: database di trivy 1,7 GB, osv-scanner npm 220 MB e PyPI 38 MB). Questa cartella
contiene solo la procedura. E' provvisoria finche' O-03 (job CI dello snapshot) non la sostituisce.
ADR-0006, spec §16 regola 7.

## Formato

```
<snapshot>/osv-scalibr/npm/all.zip         osv-scanner (nomi del bucket OSV)
<snapshot>/osv-scalibr/PyPI/all.zip
<snapshot>/trivy/db/trivy.db               trivy (+ metadata.json, policy/)
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
   python tests/fixtures/feeds/snapshot.py freeze --osv <dir> --trivy <dir> --dest <snapshot>
   ```

   `freeze` rifiuta una destinazione non vuota (uno snapshot non si sovrascrive), richiede i tre
   file obbligatori (`npm/all.zip`, `PyPI/all.zip`, `trivy.db`) e scrive `SNAPSHOT.json`.
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
  lockfile. Il rinnovo e' una scelta (O-03), non automatica.

Prove della procedura: `pytest tests/fixtures/feeds` (file piccoli, senza rete).
