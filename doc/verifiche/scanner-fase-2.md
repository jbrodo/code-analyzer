# Fase 2 — Verifica iniziale dei fatti

Esiti dei task V di `doc/plan/fase-2.md`. Ogni dato indica se è misurato qui o letto alla fonte, con la data. Non è un parere legale: le valutazioni di licenza restano di D2-14.

## V-05 — Feed EPSS e KEV

Verificato il 2026-11-13, scaricando i file e leggendo le pagine indicate.

### EPSS

| Voce | Valore | Origine |
| --- | --- | --- |
| Distribuzione | `https://epss.empiricalsecurity.com/epss_scores-current.csv.gz`, che risponde 302 verso il file del giorno (`epss_scores-2026-11-13.csv.gz`). Il vecchio host `epss.cyentia.com` risponde 301 verso quello nuovo | Misurato |
| Storico | Archivio `github.com/empiricalsec/epss_scores`, dal 2021-04-14. La pagina non dà un URL per data | Letto: <https://www.first.org/epss/data> |
| Formato | CSV compresso con gzip. Prima riga di commento `#model_version:v2026.06.15,score_date:2026-11-13T12:03:22Z`, poi intestazione `cve,epss,percentile` | Misurato |
| Dimensione | 2,85 MB compresso, 12,4 MB decompresso, 406.184 CVE | Misurato |
| Frequenza | Giornaliera. La FAQ indica la pubblicazione poco dopo le 13:30 UTC; il file scaricato ha `Last-Modified` 13:30:36 UTC | Letto: <https://www.first.org/epss/faq>; misurato |
| Integrità | Nessun checksum né firma pubblicati. L'`ETag` è l'MD5 del file (verificato): prova il trasferimento, non l'origine | Misurato |
| API | Esiste un'API oltre al CSV. Non verificata: il piano usa il file giornaliero | Letto |
| Termini d'uso | Nessuna licenza dei dati dichiarata. "free of charge, with no registration required"; "Attribution is requested when EPSS data is used in publications or products". Il sito porta la nota generale "Copyright © 2015—2026 by Forum of Incident Response and Security Teams, Inc. All Rights Reserved" | Letto: <https://www.first.org/epss/data>, <https://www.first.org/epss/faq> |

I punteggi sono generati da Empirical Security e pubblicati da FIRST (EPSS SIG).

### KEV

| Voce | Valore | Origine |
| --- | --- | --- |
| Distribuzione | `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`; esiste anche il CSV in `/sites/default/files/csv/` | Misurato |
| Formato | JSON con `title`, `catalogVersion` (`2026.11.10`), `dateReleased`, `count` e `vulnerabilities[]`. Campi di ogni voce: `cveID`, `vendorProject`, `product`, `vulnerabilityName`, `dateAdded`, `shortDescription`, `requiredAction`, `dueDate`, `knownRansomwareCampaignUse`, `notes`, `cwes`, `forensicTriage` | Misurato |
| Dimensione | JSON 1,85 MB, 1.779 voci; CSV 1,11 MB. Il server non invia `Content-Length` | Misurato |
| Frequenza | Senza cadenza fissa: il catalogo cambia quando CISA aggiunge una voce. Da agosto 2026 le date di aggiunta distinte sono 51, cioè circa un aggiornamento ogni due giorni | Misurato su `dateAdded` |
| Integrità | Nessun checksum né firma. `ETag` e `Last-Modified` soltanto | Misurato |
| Termini d'uso | CC0 1.0. Le informazioni dei collegamenti a terzi restano sotto le condizioni dei rispettivi siti; l'uso non autorizza il logo CISA o il sigillo DHS né implica approvazione | Letto: <https://www.cisa.gov/sites/default/files/licenses/kev/license.txt> |

### Ridistribuzione di OSV e trivy-db

Serve a D2-05 (mirror) e a D2-14.

| Fonte | Termini | Origine |
| --- | --- | --- |
| OSV | Licenza per sorgente. Per gli ecosistemi della Fase 2: PyPI Advisory Database CC-BY 4.0, GitHub Advisory Database CC-BY 4.0. La pagina non ha una dichiarazione generale sulla ridistribuzione degli archivi aggregati e non dice quale sorgente alimenta npm. Altre sorgenti hanno licenze diverse, tra cui CC-BY-SA 4.0 (Ubuntu, Alpine) e CC-BY-NC-ND 4.0 (Chainguard): non sono negli ecosistemi sincronizzati oggi | Letto: <https://google.github.io/osv.dev/data/> |
| trivy-db | Il repository è Apache-2.0 (dal badge del README; il file `LICENSE` non è stato letto). Il README non dichiara le licenze dei dati aggregati (NVD, Red Hat, Debian e altri) né parla di ridistribuzione. Database pubblicato in `ghcr.io/aquasecurity/trivy-db:2`, costruito ogni 6 ore | Letto: README di `aquasecurity/trivy-db` |
| trivy, sorgenti per linguaggio | La documentazione indica l'uso commerciale ammesso per le sorgenti di Python e Node.js (GitHub Advisory Database), senza nominare le licenze. Per le sorgenti dei sistemi operativi non c'è alcuna indicazione | Letto: <https://trivy.dev/latest/docs/scanner/vulnerability/> |

### Conseguenze per il piano

- **E-02, E-03 (adattatori):** nessun ostacolo. I due file insieme sono meno di 5 MB compressi: la sincronizzazione è trascurabile rispetto a trivy-db e OSV. EPSS va scaricato seguendo il redirect; il vecchio host non va usato.
- **Finestra di aggiornamento:** EPSS esce una volta al giorno dopo le 13:30 UTC, KEV senza orario. Una sincronizzazione giornaliera come quella di ADR-0006 è sufficiente; lo snapshot registra `score_date` e `catalogVersion`, che identificano il contenuto meglio della data di scaricamento.
- **Integrità (ADR-0024):** nessuna delle due fonti pubblica checksum o firme. Il rischio dello snapshot avvelenato non si chiude verificando la fonte: restano TLS, i controlli di forma e di dimensione sul contenuto e, per il mirror, la firma apposta da noi.
- **Attribuzione di EPSS:** FIRST la chiede nei prodotti. Va in documentazione e, quando esiste, nella UI dove compare il punteggio (U-04, W-05).
- **Mirror (D2-05, E-05), da portare a D2-14:**
  - KEV: CC0, ridistribuibile.
  - EPSS: nessuna licenza dichiarata e nota "All Rights Reserved" sul sito. La ridistribuzione in un mirror non è concessa in modo esplicito: serve una valutazione, o si lascia EPSS fuori dal mirror.
  - OSV per PyPI e GitHub Advisory: CC-BY 4.0, ridistribuibile con attribuzione. Va chiarito quale sorgente copre npm.
  - trivy-db: le licenze dei dati aggregati non sono dichiarate nel README. Valutazione necessaria prima di ridistribuire il database.
- **Non verificato:** l'API di EPSS; i termini generali del sito FIRST (`/about/policies/terms`); il file `LICENSE` di trivy-db; le licenze delle singole sorgenti di trivy-db.
