# ADR-0024: Feed EPSS e KEV, cache, mirror e firma

- Stato: Proposto. La parte su mirror e firma attende D2-05; il resto è una scelta tecnica e procede (E-01..E-04, E-06)
- Data: 2026-11-13
- Decisione umana richiesta: sì, D2-05 (aperta) per il mirror
- Riferimenti: §5 passo 6, §6.1, §13, §19; ADR-0001, 0005, 0006, 0014; fatti in `doc/verifiche/scanner-fase-2.md` (V-05)

## Contesto

§6.1 calcola P di una vulnerabilità da KEV e da EPSS. Nessuno dei due è un feed di un plugin: li consuma il nucleo nel passo `enrich`. ADR-0006 ha definito la sincronizzazione dei database dei plugin (container con rete e senza workspace, cache per utente, puntatore atomico) e ha lasciato aperto il rischio dello snapshot avvelenato.

V-05 ha misurato le fonti: EPSS è un CSV compresso di 2,85 MB (12,4 MB decompresso, 406 mila righe), pubblicato una volta al giorno; KEV è un JSON di 1,85 MB con 1.779 voci, aggiornato senza cadenza fissa. Nessuna delle due fonti pubblica checksum o firme. KEV è CC0; EPSS non dichiara una licenza dei dati e chiede attribuzione.

## Opzioni per lo scaricamento

1. Un container con rete e senza workspace, come per i database dei plugin (ADR-0006). Richiede un'immagine in più, da firmare e valutare, per scaricare due file.
2. Il processo della CLI scarica i due file, in un passo che non riceve il workspace, e li legge come dati non fidati.

## Raccomandazione

Opzione 2.

L'invariante di ADR-0006, "un container ha il codice o la rete, mai entrambi", protegge dal codice di terzi degli scanner. Qui non c'è codice di terzi: scarica e legge codice del pacchetto, e il processo della CLI usa già la rete per il registry e per `cosign`. I due formati sono semplici e si leggono con la libreria standard. Resta vero ciò che conta dell'invariante: nulla di ciò che deriva dal repository analizzato raggiunge la rete.

### Confini

- **Porta nel nucleo.** `ca_core/scoring/feeds/` definisce i modelli e la porta di lettura: punteggio EPSS di una CVE, presenza in KEV, identità degli snapshot. Nessun I/O, nessun import di rete (`lint-imports`).
- **Adattatore in `ca_plugins`**, accanto a `feeds.py`: scarica, valida, mette in cache e carica in memoria. Lo collega la radice di composizione (ADR-0001).
- **Sincronizzazione senza workspace.** La funzione di sincronizzazione non riceve il percorso del workspace né dati letti da esso. L'elenco delle CVE del repository non lascia mai il processo: si scarica l'intero file e si cerca in locale. L'API di EPSS, che chiederebbe le singole CVE, non si usa.
- **`--offline`** impedisce la sincronizzazione, come per gli altri feed.
- **Il server non scarica feed** in Fase 2: i punteggi arrivano nel report (ADR-0016).

### Lettura difensiva

Lo snapshot scaricato è un dato non fidato. Si accetta solo se supera tutti i controlli; altrimenti si scarta per intero e resta quello precedente.

| Controllo | EPSS | KEV |
| --- | --- | --- |
| Trasporto | HTTPS; redirect seguiti solo verso host dell'origine configurata | HTTPS, nessun redirect verso altri host |
| Dimensione scaricata | Tetto in byte, applicato durante la lettura | Idem |
| Decompressione | Tetto sui byte decompressi, applicato durante la lettura | Non compresso |
| Forma | Riga di commento con `model_version` e `score_date`; intestazione `cve,epss,percentile`; ogni riga con CVE valida e due numeri tra 0 e 1 | JSON con `catalogVersion`, `dateReleased`, `vulnerabilities[]`; ogni voce con `cveID` valido e `dateAdded` |
| Numero di voci | Tetto massimo e minimo | Idem |
| Plausibilità | Rifiutato se le voci calano oltre una soglia rispetto allo snapshot precedente | Idem |

Tetti e soglie stanno nella configurazione del pacchetto, non nel codice e non in `.code-analyzer.yml`. Valori di partenza, da confermare in E-02 e E-03 sui file reali: 32 MiB scaricati e 128 MiB decompressi per EPSS, 32 MiB per KEV; minimo 100.000 voci per EPSS e 500 per KEV; calo massimo del 20%.

I campi di testo di KEV (descrizione, azione richiesta, note) non entrano nel report: servono solo `cveID`, `dateAdded` e `knownRansomwareCampaignUse`.

### Cache e soglia di età

- Stessa cache per utente e stesso meccanismo di `feeds.py`: una cartella nuova per sincronizzazione, puntatore scambiato in modo atomico solo dopo la validazione, cache rifiutata se non è dell'utente o è scrivibile da altri.
- Il puntatore registra origine, ora di scaricamento, SHA-256 del file e l'identità del contenuto: `score_date` e `model_version` per EPSS, `catalogVersion` e `dateReleased` per KEV. L'identità del contenuto dice quanto è vecchio il dato meglio dell'ora di scaricamento.
- Soglia di età: un giorno, come per gli altri feed. Oltre la soglia si risincronizza; se la sincronizzazione fallisce o si è in `--offline`, si usa lo snapshot esistente con l'avviso `feeds-stale`.
- Senza alcuno snapshot: vedi "Feed assente".

### Origine

- L'origine predefinita, `public`, è nel pacchetto: gli URL di V-05.
- Si cambia solo con un flag della CLI o con una variabile d'ambiente, mai da `.code-analyzer.yml` (ADR-0014): un repository non può indicare da dove prendere i dati che ne determinano il punteggio. Nomi di flag e variabile in E-04, validi per tutti i feed (OSV, trivy, EPSS, KEV).
- L'origine è un'etichetta nel report, non un URL.

### Mirror e firma (D2-05, aperta)

Raccomandazione, progettata ma non pubblicata (D2-16):

- Il mirror è un artefatto OCI per insieme di feed, firmato con `cosign`. Contiene i file e un indice con SHA-256, dimensione, identità del contenuto e fonte di ciascuno.
- Con origine `mirror` la verifica della firma è obbligatoria e fallisce chiusa, come per le immagini dei plugin (ADR-0005): chiave pubblica da un percorso fidato, mai dal repository. Dopo la firma si controllano gli SHA-256 dell'indice.
- La firma è nostra: prova che lo snapshot è quello che il mirror ha pubblicato, non che la fonte fosse integra. Chi costruisce il mirror applica gli stessi controlli di "Lettura difensiva" prima di firmare.
- Contenuto ammesso nel mirror, secondo V-05: KEV sì (CC0); OSV per PyPI e GitHub Advisory sì, con attribuzione (CC-BY 4.0); EPSS e trivy-db solo dopo la valutazione di D2-14, perché la ridistribuzione non è concessa in modo esplicito. Un mirror senza EPSS è possibile: quell'origine resta `public`.

Senza D2-05 la Fase 2 usa la cache locale e quella della CI, come oggi.

### Snapshot avvelenato

Né FIRST né CISA firmano i file. Con origine `public` restano: TLS verso l'host dell'origine, i controlli di forma, dimensione e plausibilità, e la tracciabilità (SHA-256 e identità del contenuto nel report). Un file plausibile ma alterato non si riconosce.

Effetto massimo: una voce aggiunta a KEV porta P a 1,0 per quella CVE; una voce tolta o un EPSS abbassato riduce P fino al minimo. Cambia l'ordinamento e, dopo il Gate 2, può cambiare un livello. Non esegue codice e non tocca gli altri fattori. Rischio residuo accettato per la Fase 2 e riportato a S-01.

### Feed assente

P non usa mai un valore inventato.

- La porta distingue tre risposte per EPSS: punteggio presente; CVE non presente nello snapshot; snapshot assente. Per KEV: presente, non presente, snapshot assente.
- L'evidenza del fattore P registra quale delle tre si è verificata e l'identità dello snapshot usato. Un `epss` nullo con stato `feed-absent` non si confonde con una CVE che EPSS non ha valutato.
- Il valore di P in assenza di EPSS è una costante dichiarata nella configurazione di scoring e fissata da ADR-0021, non una stima.
- La scansione resta `complete`: il report porta l'avviso `enrichment-feed-missing` con il nome del feed, e i punteggi in ombra di quella scansione sono marcati come calcolati senza quel feed. Vale la stessa regola di D2-09: copertura ridotta dichiarata, non un fallimento.
- Più CVE sullo stesso finding: si usa il massimo, con l'evidenza di ciascuna.

### Nel report

Per ogni feed: origine, ora di scaricamento, SHA-256, identità del contenuto (E-06, C-04). Bastano a riprodurre un punteggio a posteriori con lo stesso snapshot.

### Attribuzione

FIRST chiede di citare EPSS nei prodotti che lo usano. L'attribuzione va nella documentazione utente e nella UI dove compare il punteggio (U-04).

## Conseguenze

- Nessuna immagine e nessuna dipendenza in più: libreria standard per HTTPS, gzip, CSV e JSON.
- La CLI apre due connessioni in più per scansione al massimo una volta al giorno; in CI la cache dei feed le evita come per gli altri database.
- I test usano lo snapshot congelato di F-04 e non toccano la rete (`AGENTS.md` regola 7).
- Il rischio dello snapshot avvelenato lasciato aperto da ADR-0006 resta aperto per l'origine `public`, con effetto delimitato e dichiarato; si chiude solo con un mirror firmato costruito da una fonte fidata.
- Se D2-05 esclude il mirror, E-05 esce e questa sezione resta come progetto non realizzato.
