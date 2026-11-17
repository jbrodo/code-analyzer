# Fase 2 — Qualità e impatto

Piano di lavoro derivato da `doc/PROJECT.md` §13 e da `doc/adr/`, scritto il 2026-11-10 dopo la chiusura della Fase 1 (X-07, `doc/verifiche/gate-1.md`).

Obiettivo: alla lista unica di finding della Fase 1 si aggiungono l'impatto (scoring G·P·E·C nelle Varianti A e B, calcolate in ombra), gli architectural smell di `ca-graph`, i plugin di qualità, IaC e copertura, i feed EPSS e KEV, la baseline con i finding nuovi e la scansione incrementale delle PR. Si aggiungono anche un server con API REST e database, la UI dell'elenco finding e le integrazioni con GitHub e GitLab. Il Gate 2 valida l'ordinamento con i team e porta alla scelta della variante predefinita.

## 0. Stato del repository alla stesura

Verificato leggendo il codice e la configurazione:

- Pacchetti presenti: `ca-core`, `ca-plugins`, `ca-cli`. Assenti `ca-graph`, `ca-api`, `ca-workflows`, `ca-integrations`, `web/`, `integrations/`, `golden-set/`.
- `pyproject.toml`: `import-linter` ha tre contratti, uno per pacchetto. `ca_core` non può importare rete, processi, FastAPI, SQLAlchemy né Temporal, e `ca_cli` non può importare server né database. `requires-python = ">=3.14"`.
- `ca_core/scoring/` contiene solo `levels.py`: la tabella dei livelli provvisori (`LevelTable`, ADR-0009) è un dataclass con valori predefiniti nel codice. Non esistono `base.py`, `variant_a.py`, `variant_b.py` né `feeds/`.
- `ca_core/models/config.py`: `service`, `scoring` (`variant: A|B`) e `agents` sono validati e inerti; `gate.mode` accetta `new-findings-only`, che viene valutato come `all`.
- `ca_core/models/finding.py`: `LevelSource` ha solo `tool_severity | policy | default`, `impact` e `score` sono sempre nulli. Manca un campo per i passi di correzione.
- `ca_core/models/scan_report.py`: `warnings[].code` è una stringa libera con pattern, quindi un nuovo codice di avviso non cambia lo schema.
- `osv_scanner_adapter.py`: se il log contiene `could not load db` il plugin è dichiarato fallito, anche per un ecosistema fuori elenco. Il manifest fissa `ecosystems: [npm, PyPI]`.
- `bandit_adapter.py`: `--skip B105,B106,B107`. B101 è attivo.
- `tests/e2e/test_detection.py`: tre `xfail` strict, due con `LICENSE_LINES` (riga mancante nei finding di licenza su file) e uno sull'avviso di gitleaks letto da `invocations`.
- `deploy/docker/`: solo `plugin-base/` e gli script di build, firma e impacchettamento. Non esiste `deploy/docker/cli/`.
- `.github/workflows/`: `verify.yml`, `e2e.yml`, `feeds-snapshot.yml`. `verify.yml` esegue lint e test di `web/` con Bun.

Dedotto dai documenti senza verificarlo: licenze di hadolint, psycopg, MinIO e delle grammatiche tree-sitter; termini d'uso di EPSS e KEV; requisiti di GitHub Marketplace e del catalogo CI/CD di GitLab. Li verificano V-02 e V-05.

## 1. Come leggere il piano

Stato di ogni task:

| Stato | Significato |
| --- | --- |
| `LIBERO` | Presuppone al più ADR tecnici. Non attende alcuna decisione dell'utente |
| `IPOTESI` | Presuppone la raccomandazione di una decisione dell'utente (sezione 3). Può partire: la sezione 3 indica cosa si rifà se la raccomandazione viene respinta |
| `BLOCCATO` | Non può partire o chiudersi finché la decisione indicata non è presa |

Un blocco si propaga lungo le dipendenze: la sezione 3 elenca anche i task bloccati indirettamente.

Gli ID di questo piano sono della Fase 2. Quando si cita un task della Fase 1 si scrive `F1:` davanti, per esempio `F1:I-06`. I riporti dalla Fase 1 hanno un ID nuovo e indicano l'origine tra parentesi.

Gli ADR nuovi hanno numeri provvisori, da 0016 a 0030 (sezione 4). Un task che scrive un ADR è `LIBERO` per la stesura; se l'ADR contiene una decisione dell'utente, i task che lo attuano sono `IPOTESI` o `BLOCCATO` finché la decisione non è presa.

## 2. Collegamento al Gate 2 (§13)

§13 dice: "ordinamento validato dai team (metodo Martini et al., ECSA 2018); scelta della variante predefinita". ADR-0009 e §5 assegnano al Gate 2 anche la scansione PR incrementale sotto i 10 minuti, che §13 non ripete (sezione 5, incoerenza 2). Le condizioni seguenti traducono il gate in misure. Le soglie numeriche di G2.b sono una proposta da confermare con D2-03.

| Condizione misurabile | Come si misura | Task che la producono | Decisioni necessarie |
| --- | --- | --- | --- |
| **G2.a** Entrambe le varianti calcolate in ombra | Su ogni repository del gate, il 100% dei finding ha i fattori e il punteggio di A e di B registrati nel report (e nel DB, se c'è il server), con la versione della configurazione di scoring | K-11, K-14, X-02 | D2-10, D2-11 |
| **G2.b** Ordinamento validato dai team | Per ogni team del protocollo, campione stratificato di finding del proprio repository, ordinato dal team senza vedere punteggi né variante. Proposta: accordo tra l'ordinamento di ciascuna variante e quello del team misurato con tau di Kendall e sovrapposizione sui primi 10. Soglia proposta: tau ≥ 0,5 e almeno 6 dei primi 10 in comune per la variante migliore, su almeno 3 team. Con D2-03 (2026-11-10) il valutatore è uno solo, l'utente, su 2 o 3 repository propri: la soglia si applica per repository e l'esito è registrato come scostamento | X-01, X-03, X-04, X-06 | D2-03 |
| **G2.c** Variante predefinita scelta | Decisione dell'utente registrata in §18 e in un ADR, motivata dai valori di G2.b e dalle differenze di livello misurate in X-02 | X-06, X-08 | §18, decisa dall'utente sui dati |
| **G2.d** Scansione PR incrementale < 10 minuti | Durata totale dal report in modalità `--pr` su ciascuno dei 3 pilota della Fase 1, con la regola di misura di `doc/verifiche/gate-1.md` (stessa macchina, snapshot fissato, sincronizzazione esclusa), su una PR di riferimento definita in X-05 | V-06, K-16, K-17, L-01, X-05 | D2-01 per la fonte della baseline |

X-08 registra l'esito delle quattro condizioni. X-09 chiude la fase sulle voci di §13 e sulla Definition of Done di §17. La UI, l'API e le integrazioni sono voci di §13 ma non condizioni del gate: servono a X-09, e servono a G2.b solo se il protocollo di D2-03 usa la UI.

Definition of Done in Fase 2 (§17), con gli adattamenti:

- Copertura ≥ 80% sul codice nuovo di `ca-core`: già imposta da `--cov-fail-under=80` in `pyproject.toml`. Va estesa a `ca-graph`, `ca-api` e `ca-integrations` in G-01, B-01 e N-01.
- Telemetria: durate nel report come in Fase 1; per il server, strumentazione minima in B-13 (ADR-0016). Lo stack OpenTelemetry con Grafana resta in Fase 4 insieme a Helm (sezione 5, incoerenza 22).
- Auto-analisi: con i livelli della Fase 2 va rifatta in X-07. D-0015 è approvata (2026-11-10), ma i 6 finding di licenza effettiva della Fase 1 restano aperti finché non sono coperti da eccezioni in `.code-analyzer.yml`: lo fa X-10, prima di X-07.
- Comandi di §16 regola 5: `bun run --cwd web lint` e `bun run --cwd web test` sono elencati in `AGENTS.md` e in CI.

## 3. Decisioni dell'utente

Decise dall'utente il 2026-11-10: D2-01, D2-03, D2-09, D2-10, D2-11, D2-16. Decisa il 2026-11-13: D2-08. Decise il 2026-11-16: D2-02, D2-04, D2-07, e la risposta a S5-A1. Decise il 2026-11-17: D2-14 per hadolint, solo per uso interno, e D2-05. Confermate il 2026-11-13 anche le eccezioni per i 6 finding di licenza (X-10). Le altre restano aperte.

| Decisione | Esito |
| --- | --- |
| D2-01 | Opzione 2: il server riceve i report prodotti dalla CLI in CI. Niente Temporal né scansioni sul server in Fase 2 |
| D2-03 | Non ci sono team da coinvolgere. Validatore unico: l'utente ordina alla cieca i finding di 2 o 3 repository propri in Python o JS/TS, con campione e metriche di G2.b. La variante predefinita che ne esce è provvisoria, da rivalidare con utenti reali. Il Gate 2 si chiude con lo scostamento dichiarato rispetto a §13 ("validato dai team"). Repository indicati il 2026-11-13: `orario-scuola` e `birds-cataloger`, un terzo facoltativo ancora da indicare (`doc/verifiche/gate-2.md`) |
| D2-08 | Opzione 2 (2026-11-13): B101 scartato nei soli file di test, riconosciuti con regole di percorso fisse nell'adattatore |
| D2-09 | Opzione 2: un ecosistema fuori elenco senza database è un avviso e il plugin resta `ok`. In più `gate` stampa su stderr gli avvisi del report. Vedi l'emendamento di ADR-0006 |
| D2-10 | Opzione 1: il gate resta sui livelli provvisori di ADR-0009 fino al Gate 2; A e B si calcolano entrambe in ombra |
| D2-11 | Corpus fisso di repository pubblici con commit fissati, distribuzione versionata nel pacchetto. Corpus piccolo all'inizio, una decina di repository con i 3 pilota inclusi. ADI calcolato e servito dall'API, trend in Fase 4 |
| D2-16 | Opzione 1: nessuna destinazione in Fase 2, solo il registry locale. I-04, I-07, E-05 e N-09 restano bloccati |
| D2-05 | (2026-11-17) Solo fonti pubbliche e cache, come ADR-0024: EPSS dal file giornaliero di FIRST e KEV dal JSON di CISA, scaricati dalla CLI con i controlli di forma, dimensione e plausibilità. Nessun mirror in Fase 2: E-05 esce, il design resta nell'ADR. La ridistribuzione di EPSS (licenza dei dati non dichiarata, chiede attribuzione) si valuta in D2-14 solo se un mirror servirà. Rischio residuo accettato: le fonti non pubblicano firme né checksum, uno snapshot plausibile ma alterato non si riconosce (effetto massimo: P di una CVE a 1,0 o al minimo; nessun codice eseguito), riportato a S-01 |
| D2-02 | (2026-11-16) Come ADR-0019: OIDC generico, token in memoria nella SPA e server senza sessioni; ruoli `lettore`, `triage`, `approvatore`, `amministratore`; un tenant in esercizio |
| D2-04 | (2026-11-16) Come ADR-0028: tier ed esposizione registrati sul server da un `amministratore` e passati a `scan` come file di contesto; il blocco `service` del repository vale solo se il file manca |
| D2-07 | (2026-11-16) pg8000 come driver; `ArtifactStore` con adattatore su file system **e adattatore S3 già in Fase 2** (ADR-0030). Nessun server di object storage incluso nel prodotto |
| D2-14 (hadolint) | (2026-11-17, Riccardo Roveda) hadolint approvato **per uso interno e per il registry locale**. Non è un'approvazione alla distribuzione: la licenza copyleft forte di hadolint, che D-0013 mette tra quelle da approvare, obbliga alla distribuzione di accompagnare l'immagine con il testo della licenza e l'offerta della sorgente. Quella decisione resta di I-07. Non è un parere legale. Gli altri motori e componenti nuovi restano da valutare in D2-14 sugli SBOM di rilascio |
| S5-A1 | (2026-11-16) Limite inferiore al livello di una dipendenza in funzione del CVSS, in configurazione: i feed possono alzare un livello, non azzerarlo. Da scrivere in ADR-0021 (A-06) |

Restano aperte: D2-06, D2-12, D2-13, D2-14, e la conferma del perimetro di D2-15.

Testo originale della tabella, con opzioni e motivazioni: ordine consigliato **D2-01** e **D2-03** per prime. D2-01 determina se servono Temporal, l'esecuzione sul server e un adattatore Kubernetes; D2-03 è l'unica che blocca il Gate 2 fin dal primo task (X-01). Seguono D2-10 e D2-02, che fermano il percorso dello scoring e del server.

| Decisione | Oggetto, opzioni e raccomandazione | Proprietario | Task bloccati direttamente | Bloccati indirettamente | Gate 2 |
| --- | --- | --- | --- | --- | --- |
| **D2-01** (decisa il 2026-11-10) Orchestrazione e modalità server (ADR-0016) | §5, §14 e §2 portano Temporal in Fase 2, mentre ADR-0002 ha reso la pipeline indipendente. Opzioni: (1) Temporal e scansioni eseguite dal server, con adattatore Kubernetes e gVisor (obbligatorio sul server, ADR-0004), clone con credenziali e webhook; (2) il server **riceve i report prodotti dalla CLI in CI**, senza eseguire scansioni e senza Temporal; (3) server con coda semplice in PostgreSQL che esegue la CLI. **Raccomandata (2)**: il Gate 2 ha bisogno di finding con punteggio consultabili e confrontabili, non di esecuzione sul server; si evitano gVisor su Kubernetes, le credenziali di clone e un componente durevole. Temporal entra quando servono le scansioni sul server (notturne, webhook), da rivalutare in Fase 3 o 4 | Utente | B-01, B-03, L-03, B-12, I-03, A-15 nella parte sui componenti | B-*, W-03, I-06, T-05, O-04 | Cambia la fonte della baseline per G2.d |
| **D2-02** Autenticazione, RBAC e tenant (ADR-0019, lacune 3 e 11) | Quale IdP OIDC; ruoli; tenant operativi. Raccomandazione: OIDC generico (nessun IdP cablato nel codice), IdP finto nei test e nel compose; ruoli `lettore`, `triage`, `approvatore` (eccezioni e falsi positivi), `amministratore`; pipeline autenticate con l'OIDC dei provider CI e associazione per claim `repository`; uno schema PostgreSQL per tenant progettato dalla prima migrazione, un solo tenant in esercizio nel pilota | Utente, con parere `security` (S-01) | B-04, B-05, W-03, I-05 | B-03, B-08..B-12, T-05, I-06 | Non blocca, se G2.b non usa la UI |
| **D2-03** (decisa il 2026-11-10) Team e protocollo del Gate 2 | Chi sono i team, quali repository (i 3 pilota pubblici non hanno un team raggiungibile), dimensione del campione, metrica e soglia. Raccomandazione: almeno 3 team, ciascuno con un proprio repository Python o JS/TS; campione di 30 finding per repository, stratificato per categoria e livello; ordinamento cieco rispetto alla variante; tau di Kendall e sovrapposizione sui primi 10, soglia come in G2.b; esiti in `doc/verifiche/gate-2.md`, solo conteggi e misure se i repository sono riservati. Il metodo di Martini et al. (ECSA 2018) va trascritto in ADR come protocollo, e l'utente conferma che la trascrizione è fedele | Utente | X-01 | X-02, X-03, X-04, X-06, X-08, X-09 | Blocca G2.a (repository), G2.b e G2.c |
| **D2-04** Catalogo servizi per C ed E (§18, ADR-0028) | Opzioni: (1) catalogo esterno (per esempio un file di catalogo per repository o un servizio); (2) **tier ed esposizione registrati sul server per repository** da un `amministratore` (tabella `repositories` di §4.3), con il blocco `service` di `.code-analyzer.yml` ammesso solo in modalità locale e segnalato come non fidato; (3) solo `.code-analyzer.yml`. **Raccomandata (2)**: il file sta nel repository analizzato, quindi chi lo modifica può abbassare C ed E e quindi il punteggio (ADR-0014). Senza registrazione: C = 0,7 e E = 0,3 (§6.1) | Utente | B-10, K-04, K-05 | K-11, K-14, X-02 | Cambia i valori di G2.a e G2.b |
| **D2-05** Feed EPSS/KEV e mirror (ADR-0024) | Fonte, termini d'uso, dove sta il mirror, firma degli snapshot. Raccomandazione: EPSS dal file giornaliero pubblicato da FIRST, KEV dal JSON di CISA, entrambi con sincronizzazione separata come ADR-0006; in Fase 2 solo la cache locale e quella della CI, come oggi; il mirror come artefatto OCI firmato con cosign, così la verifica riusa ADR-0005, si progetta ma si pubblica solo su una destinazione che rispetti D2-16. La ridistribuzione dei database (OSV, trivy-db, EPSS, KEV) in un mirror è una valutazione di licenze e va aggiunta a D2-14 | Utente; Riccardo Roveda per la parte di ridistribuzione (D2-14) | E-05 | Nessuno: E-02..E-04 procedono con la sola cache | Non blocca: P di A usa EPSS e KEV anche senza mirror |
| **D2-06** Dove gira il server del pilota | Il Gate 2 con la UI richiede un server raggiungibile dai team. Raccomandazione: un solo host interno con il compose di I-05, nessun Kubernetes (Helm è in Fase 4) | Utente | I-06 | Nessuno | Solo se G2.b usa la UI |
| **D2-07** Object storage e licenze dei componenti server (ADR-0030) | §2 indica S3/MinIO; MinIO server risulterebbe AGPL-3.0, vietata da D-0013 in un prodotto distribuito (da verificare in V-02). Raccomandazione: porta `ArtifactStore` con adattatore su file system per il pilota e adattatore S3 generico; nessun server di object storage incluso nel prodotto finché la Fase 4 non sceglie il packaging. Stessa verifica per il driver PostgreSQL | Utente; Riccardo Roveda per le licenze | B-07 | B-03, B-06, B-11 | Non blocca |
| **D2-08** (decisa il 2026-11-13: opzione 2) Rumore di B101 (bandit) | 47.276 finding su 47.718 nel pilota saleor, quasi tutti `assert` nei test. Opzioni: (1) disattivare B101 come B105..B107; (2) **scartare B101 solo nei file di test** (percorsi fissati nell'adattatore, non dal repository) e tenerlo altrove; (3) tenerlo e lasciare che lo scoring lo porti in basso. **Raccomandata (2)**: un `assert` nel codice di produzione sparisce con `-O` ed è un problema reale, nei test no | Utente | P-07 | Nessuno | Riduce il rumore nel campione di G2.b |
| **D2-09** (decisa il 2026-11-10: opzione 2, più la stampa degli avvisi in `gate`) osv-scanner su un ecosistema senza database (emenda ADR-0006) | Oggi un `pom.xml` rende `partial` qualunque scansione. Opzioni: (1) allargare l'elenco degli ecosistemi (Maven, Go, crates…), che anticipa dati della Fase 4; (2) **per un ecosistema fuori elenco, avviso `feeds-ecosystem-missing` con ecosistema e numero di pacchetti, plugin `ok` e copertura ridotta dichiarata nel report**; il fallimento resta per un ecosistema in elenco senza database; (3) lasciare il fallimento. **Raccomandata (2)**: lo stesso trattamento della copertura ridotta di gitleaks, e la scansione Python o JS/TS con un `pom.xml` accessorio torna `complete` | Utente (ADR-0006 è una sua decisione) | P-06 | Nessuno | Può rendere `partial` le scansioni dei repository dei team |
| **D2-10** (decisa il 2026-11-10) Quale livello usa il gate durante l'ombra (ADR-0021) | §6 sceglie la variante per repository, §13 dice "modalità ombra entrambe". Opzioni: (1) **fino al Gate 2 il gate resta sui livelli provvisori di ADR-0009, A e B si calcolano entrambe in ombra; dopo la scelta della variante predefinita il livello da punteggio diventa attivo**; (2) la variante di `scoring.variant` è attiva da subito e l'altra in ombra; (3) gate sul massimo dei due livelli. **Raccomandata (1)**: le CI dei pilota non cambiano esito prima che l'ordinamento sia validato, e il passaggio dei livelli (ADR-0009, "molti finding cambieranno livello") avviene una volta sola, documentato | Utente | K-14, L-02 | X-02, X-07 | Definisce cosa misura G2.a |
| **D2-11** (decisa il 2026-11-10) Benchmark della Variante B (ADR-0023) | §6.2 normalizza l'intensità "con quantili sulla distribuzione di benchmark", ma il benchmark non esiste. Raccomandazione: corpus fisso di repository pubblici Python e JS/TS con commit fissati, pilota inclusi; distribuzione salvata come dato versionato nel pacchetto; ricalcolo solo esplicito. Si decide anche se l'ADI per modulo (§6.2) entra in Fase 2 solo come valore calcolato e servito dall'API, con il trend lasciato alla Fase 4 | Utente | K-06 | K-07, K-11, G-13 | Blocca la parte B di G2.a |
| **D2-12** GitLab: dove si pubblica e si prova il componente | Il repository è su GitHub, ma un componente del catalogo CI/CD vive in un progetto GitLab; ADR-0004 non supporta le CI senza daemon. Raccomandazione: progetto specchio su un'istanza GitLab scelta dall'utente, runner con Docker-in-Docker per gli E2E | Utente | N-08 | N-09 | Non blocca |
| **D2-13** Rilascio dell'immagine CLI e dell'Action (estende D-0005) | Nome dell'immagine CLI e forma di distribuzione dell'Action: sottocartella del monorepo (`uses: <owner>/code-analyzer/integrations/github-action@ref`) o repository dedicato, come suggerisce `org/code-analyzer-action@v1` in §12.1 e come richiede il Marketplace (da verificare in V-02). Raccomandazione: Action nella sottocartella del monorepo, usata solo dalla CI di questo repository; nessun repository dedicato né Marketplace finché vale la decisione del 2026-11-10 sulla pubblicazione. Il nome dell'immagine CLI segue la destinazione di D2-16 (con GHCR sarebbe `ghcr.io/jbrodo/code-analyzer/cli`) | Utente | N-09 | Nessuno | Non blocca |
| **D2-15** Perimetro della UI di Fase 2 (ADR-0029, lacune 1 e 2) | Decisa: UI centrata sull'elenco finding, portfolio in Fase 4. Da confermare il perimetro proposto: elenco finding con filtri, dettaglio con fattori e passi di correzione, triage ed eccezioni, stato della scansione (parziale compresa), selettore di repository. Esclusi aggregati, trend e grafici | Utente | Nessuno: U-01 e A-14 procedono in `IPOTESI` | W-04..W-08 | Non blocca |
| **D2-14** Licenze dei motori e dei componenti nuovi (emenda ADR-0015) | D-0015, approvata il 2026-11-10, copre le 7 immagini della Fase 1. §7.3 chiede di verificare la licenza di ogni motore prima di includerlo in un'immagine distribuita: servono la stessa valutazione per ruff, eslint con typescript-eslint, checkov, hadolint, tree-sitter e grammatiche, i componenti del server e l'immagine CLI, e la ridistribuzione dei database in un mirror (D2-05). Raccomandazione: stessa procedura di D-0015, sugli SBOM della build di rilascio, con i risultati di V-02 come materiale; immagini, digest e SBOM conservati insieme per ogni rilascio | Riccardo Roveda (responsabile; non un agente) | I-07 | N-09 per i plugin nuovi, E-05 | Non blocca: i pilota e i team usano il prodotto internamente |
| **Nessuna pubblicazione** (decisione dell'utente del 2026-11-10) | Per ora non si pubblica nulla, né su GHCR né altrove, salvo che la destinazione sia privata e gratuita. Resta in più l'approvazione esplicita di ogni pubblicazione | Utente | I-04, I-07, E-05, N-09 | Nessuno | Non blocca |
| **D2-16** (decisa il 2026-11-10) Destinazione privata e gratuita delle immagini (estende D-0005) | D-0005 indica GHCR, valido solo se rispetta la decisione del 2026-11-10. Dimensione da ospitare, secondo il coordinatore: circa 2,3 GB non compressi per le 7 immagini della Fase 1 (scancode 718 MB, semgrep 482 MB), più l'immagine CLI e i 6 plugin nuovi. Questi valori non sono nei documenti del repository e non li ho verificati; i documenti non dicono nemmeno se un registry privato GHCR di quella dimensione resti gratuito, e non l'ho controllato perché servirebbero chiamate esterne. Un registry privato richiede anche credenziali di lettura nei runner, e la verifica cosign richiede l'accesso al registry (ADR-0005). Opzioni: (1) **nessuna destinazione in Fase 2**: sviluppo, E2E e Gate 2 usano il registry locale di `deploy/compose/registry.yaml`, con le scansioni dei repository dei team eseguite sulla macchina di riferimento; (2) registry privato sull'host del pilota (D2-06), con autenticazione, TLS e volume persistente: privato e gratuito, raggiungibile solo dalla rete interna; (3) GHCR privato, solo dopo che l'utente ha verificato che quota e costi restano a zero. **Raccomandata (1)**, con (2) solo se i team devono far girare l'Action nelle proprie CI. Il Gate 2 non richiede alcuna pubblicazione | Utente | I-04, I-07, E-05, N-09, I-06 per la sola parte del registry | Nessuno | Non blocca con (1) |
| **Eccezioni per i 6 finding di licenza** | D-0015 accetta il rischio residuo, ma i 6 finding restano aperti finché non sono eccezioni. Raccomandazione: eccezioni con `approved_by: Riccardo Roveda`, motivazione che rimanda all'approvazione di D-0015 e scadenza 2027-05-09 come le altre eccezioni di licenza | Riccardo Roveda | X-10 | X-07 | Non blocca |

Stato di D-0015: approvata il 2026-11-10 da Riccardo Roveda, che accetta come rischio residuo i punti "Da chiarire" di `doc/verifiche/gate-1.md` (semgrep, `git`, `libgomp1`, `unrar`); non è un parere legale. ADR-0015 è `Accettato`. Non è più una decisione aperta. Il primo rilascio (I-04, cioè F1:I-06) resta bloccato dalla decisione dell'utente del 2026-11-10 (nessuna pubblicazione salvo destinazione privata e gratuita) e da D2-16, non più da D-0015.

La configurazione dei linter (eseguire la configurazione del repository o no) non è una decisione dell'utente: è una scelta tecnica di ADR-0026, con il parere di `security` in S-03.

Dipendenza da rendere visibile: **la GitHub Action e il componente GitLab di §12 presuppongono immagini raggiungibili dai runner**. La CLI e i plugin si scaricano da un registry con firma verificata (ADR-0005). Il piano non dà per scontata alcuna pubblicazione: sviluppo e test di Action e componente (N-04, N-05, N-07, N-08) usano il registry locale di `deploy/compose/registry.yaml` avviato nel job, con le immagini costruite e firmate nello stesso job con la chiave di prova, come fa già `e2e.yml`. Quel registry è su loopback, senza volume, e non è un registry di rilascio. Resta bloccata solo la messa a disposizione per repository esterni (I-04, I-07, N-09), dalla decisione del 2026-11-10 e da D2-16; per i plugin nuovi anche da D2-14. Fino ad allora l'Action e il componente funzionano solo nelle pipeline che costruiscono le immagini da sé.

### Effetti se una raccomandazione non viene accolta

| Decisione | Alternativa | Effetto sul piano |
| --- | --- | --- |
| D2-01 | Temporal ed esecuzione sul server | Nuovi task: pacchetto `ca-workflows` con le activity attorno ai passi esistenti (ADR-0002 regge), adattatore `PluginExecutor` per Kubernetes con gVisor (ADR-0004), clone con credenziali di una GitHub App, webhook `/v1/webhooks/*`, Temporal nel compose, test con il test server di Temporal (§14). S-01 si estende all'esecuzione sul server. B-03 resta per l'ingestione dalla CI. Il percorso critico del server si allunga, quello del gate no |
| D2-01 | Coda in PostgreSQL | Come la riga precedente senza Temporal: un worker esegue la CLI. Restano l'adattatore gVisor e le credenziali di clone |
| D2-02 | IdP specifico o niente RBAC | Con un IdP cablato, B-04 e W-03 si specializzano. Senza RBAC, `approved_by` resta una dichiarazione anche sul server e `PATCH` delle eccezioni va tolto da B-09 e W-06 |
| D2-03 | Validazione sui pilota pubblici senza team | G2.b non è misurabile come chiede §13: serve un sostituto (per esempio, annotazione da parte di `security` e dell'utente) e il gate va riscritto |
| D2-04 | Catalogo esterno | Nuovo adattatore e nuovo formato (ADR-0028), K-05 legge da lì. B-10 perde la registrazione del tier |
| D2-04 | Solo `.code-analyzer.yml` | B-10 si semplifica. Il punteggio diventa manipolabile dal branch: S-01 lo registra come rischio residuo |
| D2-05 | Nessun mirror in Fase 2 | E-05 esce, E-04 si riduce alla configurazione dell'origine. "Cache e mirror" di §13 resta a metà |
| D2-07 | MinIO incluso | Va approvato da Riccardo Roveda come eccezione alla policy D-0013 prima di I-03 |
| D2-08 | Disattivare B101 | Una riga in `SKIP` di P-07. Gli `assert` in produzione non sono più segnalati |
| D2-08 | Tenere B101 | P-07 esce. Il campione di G2.b va filtrato a mano o il rumore entra nella valutazione |
| D2-09 | Allargare gli ecosistemi | P-06 diventa un'estensione dell'enum `feeds.ecosystems` (aggiunta compatibile) e della sincronizzazione, con spazio disco e tempi da rimisurare |
| D2-10 | Variante attiva da subito | K-14 attiva il livello da punteggio; L-05 documenta subito il cambio; le CI dei pilota e del progetto (X-07) cambiano esito prima della validazione |
| D2-10 | Massimo dei due livelli | K-14 calcola il massimo; il confronto di G2.b resta valido, ma il gate è più severo |
| D2-11 | Nessun benchmark | La Variante B usa soglie fisse al posto dei quantili, cioè non segue più la pubblicazione di riferimento: va scritto in ADR-0023 |
| D2-16 | Registry privato sull'host del pilota | Si aggiunge a I-06 un registry con autenticazione, TLS e volume persistente, e a N-04 l'accesso con credenziali di sola lettura; S-04 valuta la custodia delle credenziali nei runner dei team |
| D2-16 | GHCR privato | I-04 e I-07 diventano eseguibili dopo l'approvazione di ogni pubblicazione; N-04 deve autenticare il pull e la verifica cosign con un token di lettura |
| D2-14 | Motori nuovi non approvati | Il plugin respinto resta per uso interno o esce; I-07 si riduce. Per hadolint serve un'alternativa per i Dockerfile (trivy e checkov li coprono già in parte) |
| D2-12 | Nessuna istanza GitLab | N-08 e la parte GitLab di N-09 escono; il componente resta non provato |
| D2-15 | UI più ampia | Ogni vista aggiunta richiede endpoint nuovi: torna ad A-14 e C-08 prima di W-* |

## 4. ADR da scrivere prima dell'implementazione

Numeri provvisori. Ogni ADR segue la forma esistente: contesto, opzioni, raccomandazione o decisione, conseguenze.

| ADR | Titolo | Lacune e incoerenze coperte | Decisione dell'utente | Task |
| --- | --- | --- | --- | --- |
| 0016 | Modalità server e orchestrazione in Fase 2 | Temporal (§2, §5, §14), webhook, telemetria del server | D2-01 | A-01 |
| 0017 | Flusso del contratto OpenAPI | Lacuna 12 | No | A-02 |
| 0018 | Modello dati relazionale e multi-tenancy | Lacuna 11; `id` del finding non più uguale al fingerprint; precedenza tra stato sul server ed eccezioni del repository | No (dipende da D2-02 per i tenant) | A-03 |
| 0019 | Autenticazione e RBAC | Lacuna 3; `approved_by` autenticato | D2-02 | A-04 |
| 0020 | `ca-graph`: isolamento, schema del grafo, smell | tree-sitter su codice non fidato fuori dal container (§7.3 "interno"); definizioni e soglie di Cyclic, Hub-Like, Unstable Dependency; nuovo `kind` del fingerprint | No | A-05 |
| 0021 | Scoring Variante A, ombra, livelli e override | Lacune 4, 5, 6, 7; soglie in configurazione (§6.3 contro §16 regola 3); override non definiti | D2-10 | A-06 |
| 0022 | Esposizione e churn | E di §6.1 (raggiungibilità, entrypoint); churn a 90 giorni con clone superficiale | No | A-07 |
| 0023 | Variante B: intensità, benchmark, ADI | Benchmark mancante; fonte delle metriche dei code smell | D2-11 | A-08 |
| 0024 | Feed EPSS e KEV, cache, mirror e firma | §13 "cache e mirror"; rischio dello snapshot avvelenato lasciato aperto da ADR-0006 | D2-05 | A-09 |
| 0025 | Baseline, modalità PR e finding nuovi | Fonte della baseline; plugin eseguiti solo sui file cambiati; configurazione dal branch base (ADR-0014) | Dipende da D2-01 | A-10 |
| 0026 | Plugin di qualità, IaC e coverage | Configurazione dei linter; ingresso dei report di copertura; correlazione tra tool sugli stessi problemi | No | A-11 |
| 0027 | Integrazioni CI | Forma dell'Action (ADR-0010); commenti PR e check run; chi importa `ca-integrations` (ADR-0001); PR da fork | D2-12, D2-13 | A-12 |
| 0028 | Catalogo servizi | §18; fonte non fidata di C ed E | D2-04 | A-13 |
| 0029 | UI dell'elenco finding: perimetro e dati | Lacune 1 e 2; passi di correzione assenti dal modello (§1) | D2-15 | A-14 |
| 0030 | Componenti del server e object storage | Licenze di object storage e driver | D2-07 | A-15 |

Emendamenti agli ADR esistenti (A-16): 0001 (nuovi pacchetti e contratti `import-linter`), 0002 (secondo D2-01), 0006 (D2-09, origine dei mirror), 0008 (nuovi `kind` per smell e copertura, senza cambiare `fp1` per quelli esistenti), 0009 (superata dai livelli da punteggio secondo D2-10), 0010 (`--pr`, `--base`, `--variant`, invio al server), 0013 (riga nei finding di licenza su file), 0015 (D2-14, motori e componenti nuovi).

## 5. Incoerenze e lacune della specifica

Trovate durante la stesura. Ognuna ha un ADR o una decisione nella tabella precedente.

1. **Temporal.** §2, §5 ("Dalla Fase 2 il workflow Temporal") e §14 lo portano in Fase 2, ma §13 non elenca né Temporal né l'esecuzione sul server. D2-01.
2. **Gate 2 incompleto.** §13 non cita la scansione PR incrementale < 10 minuti, che §5 e ADR-0009 assegnano al Gate 2. Il piano la include come G2.d; A-17 corregge §13.
3. **Variante attiva o ombra.** §6 sceglie la variante per repository, §13 dice "ombra entrambe". D2-10.
4. **Soglie nel codice.** §6.3 mette le soglie "in `scoring/levels.py`", §16 regola 3 e `AGENTS.md` le vogliono in configurazione. Anche la tabella provvisoria attuale è nel codice. ADR-0021, C-03.
5. **Fattori e override non definiti.** Lacune 5, 6 e 7. In più: "percorso sorgente→sink confermato", "hotspot", "codice critico modificato spesso" non hanno una definizione operativa; "segreto valido esposto" richiede una verifica online vietata da ADR-0006 e ADR-0012, quindi l'override non è applicabile in Fase 2. ADR-0021.
6. **Variante B senza dati.** Il benchmark per i quantili non esiste e nessun motore di code smell con metriche è indicato: ruff ed eslint sono linter, e solo alcune loro regole (complessità, lunghezza, parametri) portano una metrica. ADR-0023, D2-11.
7. **Raggiungibilità.** E di §6.1 parte da "raggiungibile da un entrypoint" senza dire cos'è un entrypoint né a che granularità si misura. ADR-0022.
8. **C ed E dal repository.** `service.tier` e `service.internet_facing` stanno in `.code-analyzer.yml`, che è un input non fidato (ADR-0014): chi modifica il branch abbassa il punteggio. §4.3 mette il tier anche in `repositories`, cioè due fonti. D2-04.
9. **Passi di correzione.** §1 promette "i passi per risolverlo", ma `Finding` (§4.1) non ha un campo per questo. ADR-0029, C-01.
10. **Multi-tenancy e pgvector.** §4.3 chiede uno schema per tenant, mentre il packaging SaaS è in Fase 4 (lacuna 11). pgvector serve solo dalla Fase 3. ADR-0018.
11. **API e due fonti di eccezioni.** §9.2 non ha l'elenco di repository e scansioni né il dettaglio di un finding (lacuna 2). `PATCH /v1/findings/{id}` gestisce le eccezioni, ma anche `.code-analyzer.yml` le contiene: manca la precedenza. ADR-0018, ADR-0029.
12. **Action.** §12.1 passa ancora `--fail-on` a `scan` (ADR-0010 lo correggeva). `org/code-analyzer-action@v1` presuppone un repository dedicato, `integrations/github-action/` una sottocartella. D2-13, ADR-0027.
13. **GitLab.** Il componente deve vivere in un progetto GitLab, il monorepo è su GitHub; ADR-0004 non supporta le CI senza daemon. D2-12.
14. **`ca-graph` "interno".** §7.3 lo mette tra i plugin senza container, ma tree-sitter analizza codice non fidato con un parser in C: contro il principio di ADR-0004. ADR-0020.
15. **Ingresso della copertura.** "Import LCOV / Cobertura dalla CI": il manifest (§7.1) ha solo `workspace`, `sbom` e `config` come ingressi, e un report di copertura prodotto dalla CI non è un file del repository. ADR-0026.
16. **MinIO.** §2 lo indica, ma la sua licenza (AGPL-3.0, da verificare) è nell'elenco vietato di D-0013 per un prodotto distribuito. D2-07.
17. **Versione di Python.** §2 dice 3.12+, `pyproject.toml` richiede 3.14 e la CI usa 3.14; `ruff` ha `target-version = "py312"`. Da allineare in A-17.
18. **Chi chiama `ca-integrations`.** ADR-0001 non consente a `ca-cli` di importarlo, ma senza server i commenti PR partono dalla CI. ADR-0027 e A-16.
19. **"I team".** §13 non dice chi valida l'ordinamento. D2-03.
20. **Trend dell'ADI.** §6.2 chiede l'ADI "con trend tra versioni", che è una vista da portfolio (Fase 4). D2-11.
21. **Scansioni notturne.** §4.3 e §5 citano il tipo "notturna", nessuna fase prevede una pianificazione. Fuori ambito (sezione 6).
22. **Telemetria.** §15 chiede dashboard Grafana nel chart Helm, che è in Fase 4. ADR-0016 limita la Fase 2 alla strumentazione.
23. **ADR-0006 e Java.** ADR-0006 tratta un ecosistema senza database come fallimento e indica di allargare l'elenco, ma Java è in Fase 4. D2-09.
24. **`--variant` e `scoring.variant`.** §9.1 ha un flag, §8 una chiave del repository; manca la precedenza. ADR-0021 e A-16 su ADR-0010.
25. **Duplicati tra tool.** ADR-0008 non fonde SAST di scanner diversi sulla stessa riga. Con checkov, hadolint e trivy sugli stessi Dockerfile e manifest il problema cresce e falsa l'ordinamento di G2.b. ADR-0026, K-21.

## 6. Fuori ambito (Fase 3 e successive)

- Dashboard portfolio, aggregati e trend in UI, grafici del grafo: Fase 4 (decisione dell'utente).
- Java/Kotlin, Go, C#, Rust: Fase 4 (decisione dell'utente). Resta fuori anche la verifica sul perché trivy non riporta vulnerabilità dal `pom.xml` (prova Java di `gate-1.md`).
- `ca-decision`, `ca-agents`, golden set, `POST /v1/findings/{id}/agents/run`, tabelle `decisions`, `agent_runs`, `golden_labels`, `embeddings` e pgvector: Fase 3. Le annotazioni dei team raccolte in X-04 possono alimentare il golden set, ma non lo costruiscono.
- Renovate e Dependabot (§12.3), VEX e `vex_statements`: Fase 3.
- Helm, Kubernetes, packaging SaaS e self-hosted, bundle offline dei feed, stack OpenTelemetry con Grafana: Fase 4.
- Con la raccomandazione di D2-01: Temporal, `ca-workflows`, esecuzione delle scansioni sul server, adattatore Kubernetes con gVisor, webhook `/v1/webhooks/*`, scansioni notturne.
- `explain`, `plugin list|verify|run`, `sbom --format spdx`: non sono voci di §13 per la Fase 2. Restano omessi come in ADR-0010, salvo decisione contraria.
- `trufflehog` e la verifica della validità dei segreti (lacuna 7).
- Firecracker (ADR-0004).

## 7. Ordine e parallelismo

Prima i fatti (V) e le decisioni (A), poi i contratti (C: schemi, porte, modello relazionale, OpenAPI) e gli attesi (F), infine le implementazioni che li consumano. Ogni task che consuma un contratto ne dipende esplicitamente (ADR-0003). Backend e frontend procedono in parallelo dal momento in cui C-08 (OpenAPI) è chiuso: il frontend lavora sui tipi generati e su risposte simulate dagli esempi dell'OpenAPI nei test, il backend implementa le route sullo stesso contratto.

Le ondate elencano i task che possono procedere insieme a dipendenze soddisfatte, supponendo prese le decisioni. Sono calcolate sul grafo delle dipendenze della sezione 8; ogni ondata è parallelizzabile al suo interno. `*` = `BLOCCATO`, `°` = `IPOTESI`.

| Ondata | Task |
| --- | --- |
| 1 | A-01, A-02, I-01, K-19, K-20, P-07°, U-01°, V-01, V-05, V-06, X-01*, X-10° |
| 2 | A-03, A-09, A-10, A-14°, I-04*, U-02, U-03, V-02, V-03, V-04, V-07 |
| 3 | A-04, A-05, A-11, A-12, A-13, A-15, F-02, F-06, S-05, T-02, V-08, W-01 |
| 4 | A-07, B-01°, C-02, C-05, C-09, F-03, G-01, I-05°, N-01, P-01°, P-02°, P-03°, P-04°, S-01, S-02, S-03, S-04 |
| 5 | A-06, B-13°, C-06, F-01, G-02, G-03, I-03°, K-21, N-02, N-03, N-06, P-05° |
| 6 | A-08, A-16, B-07°, C-01, E-01, F-04, G-04, G-09, K-16, L-04 |
| 7 | A-17, C-03, C-04, C-07, E-02°, E-03°, G-05, G-06, G-07, G-08, G-11, G-12, I-02, K-06°, P-06°, U-04 |
| 8 | B-02°, C-08, E-04°, E-06, F-05, G-10, G-13°, K-01, K-17, O-03 |
| 9 | B-04°, C-10, E-05*, K-02, K-03, K-04°, K-05°, K-07°, K-08, K-09, K-10, K-12, K-18, O-01, T-01, T-03, W-02 |
| 10 | B-05°, K-11, K-13, K-15, L-01, L-03°, T-06, W-03°, W-04°, W-07° |
| 11 | B-03°, B-08°, B-10°, K-14°, N-04, N-07°, T-04, W-05° |
| 12 | B-06°, B-09°, B-11°, B-12°, L-02°, N-08*, O-02, W-06°, X-05, X-07 |
| 13 | I-06*, I-07*, L-05, N-05, S-06, T-05°, U-05, W-08°, X-02 |
| 14 | N-09*, O-04°, X-03 |
| 15 | X-04 |
| 16 | X-06 |
| 17 | X-08 |
| 18 | X-09 |

Vincoli di parallelismo oltre le dipendenze:

- `pyproject.toml` radice: G-01, B-01 e N-01 aggiungono pacchetti al workspace e contratti a `import-linter`. Vanno coordinati, o in serie nell'ordine delle ondate.
- `schemas/`: i task C-* generano file distinti, ma C-01 e C-04 toccano modelli che si importano a vicenda (`scan-report` contiene i finding). Rigenerare con l'export prima di ogni merge.
- P-01..P-05 toccano ciascuno solo la propria cartella `builtin/<nome>/`: sono il blocco parallelo più ampio dopo i contratti, come in Fase 1.
- K-02..K-10 toccano file distinti di `ca_core/scoring/` e procedono in parallelo; K-11 li compone e non va iniziato prima che siano chiusi.
- W-04..W-07 toccano viste distinte di `web/`; il client generato (W-02) è l'unico punto condiviso.
- `ca-graph` (G-*) e lo scoring (K-*) si incontrano solo nei contratti C-02 e C-06.

## 8. Task

Formato: `Stato` come da sezione 1. `Spec` e `ADR` indicano la sezione della specifica e gli ADR presupposti. I test indicati nell'accettazione sono scritti nello stesso task, salvo quelli assegnati a `test`. Ogni task che aggiunge una dipendenza ne verifica licenza e manutenzione e aggiorna l'SBOM (§16 regola 2).

### V — Verifica iniziale dei fatti

Esito in `doc/verifiche/scanner-fase-2.md`. Questi task possono usare la rete (§16 regola 7 riguarda i test) e girano solo su repository pubblici o di prova.

#### V-01 — Fissare le versioni candidate
- Agente: `devops`. Stato: **chiuso il 2026-11-13**; esito in `doc/verifiche/scanner-fase-2.md`. Da portare a D2-07 e D2-14: psycopg e hadolint hanno licenze che D-0013 mette tra quelle da approvare.
- Percorsi: `doc/verifiche/scanner-fase-2.md`.
- Dipende da: nessuno.
- Accettazione: tabella con versione esatta, checksum o digest di rilascio, data e stato di manutenzione per ruff, eslint con typescript-eslint e un formattatore SARIF, checkov, hadolint, py-tree-sitter e le grammatiche Python, JavaScript, TypeScript e TSX, FastAPI, SQLAlchemy, Alembic, un driver PostgreSQL, una libreria JWT/OIDC, testcontainers, React, Vite, TypeScript, Bun, un generatore di tipi dall'OpenAPI, una libreria di test dei componenti. Temporal SDK solo se D2-01 cade.
- Spec: §2, §7.3, §16 regola 2. ADR: 0007, 0015.

#### V-02 — Licenze sul testo della versione fissata
- Agente: `devops`. Stato: **chiuso il 2026-11-13**; esito in `doc/verifiche/scanner-fase-2.md`. Tutti i checksum coincidono. Per D2-14 e D2-07: hadolint e psycopg da approvare, MinIO vietato, formattatore SARIF di eslint senza testo di licenza nel pacchetto.
- Percorsi: `doc/verifiche/scanner-fase-2.md`.
- Dipende da: V-01.
- Accettazione: licenza letta dal file al tag fissato per ogni voce di V-01 e per MinIO, con collegamento e confronto con D-0013. In evidenza i casi da sottoporre a D2-14: hadolint, driver PostgreSQL, MinIO, grammatiche tree-sitter, schemi dei report GitLab. Registra anche i requisiti di GitHub Marketplace (posizione di `action.yml`) e del catalogo CI/CD di GitLab. Non è il parere legale.
- Spec: §7.3, §12. ADR: 0013, 0015.

#### V-03 — Output reali dei nuovi motori
- Agente: `devops`. Stato: **chiuso il 2026-11-13**; esito in `doc/verifiche/scanner-fase-2.md`, campioni in `tests/fixtures/plugin-output/fase-2/`. typescript-eslint non accetta TypeScript 7; le metriche stanno solo nel testo dei messaggi; il formattatore SARIF di eslint non va usato.
- Percorsi: `doc/verifiche/scanner-fase-2.md`, `tests/fixtures/plugin-output/`.
- Dipende da: V-01.
- Accettazione: campioni reali e, per ruff, eslint, checkov, hadolint: SARIF disponibile o formato nativo necessario, campi di severità, `uri` relativi o assoluti, metriche presenti nei messaggi delle regole di complessità e dimensione (servono alla Variante B), formato dei report LCOV e Cobertura prodotti da coverage.py, pytest-cov, istanbul/nyc e vitest.
- Spec: §6.2, §7.1. ADR: 0007.

#### V-04 — Comportamento offline e con le restrizioni del container
- Agente: `devops`. Stato: **chiuso il 2026-11-13**; esito in `doc/verifiche/scanner-fase-2.md`. Tutti girano con il profilo dei plugin; nessuno è sicuro con le impostazioni predefinite. `.checkov.yaml` del repository si applica anche con `--config-file`.
- Percorsi: `doc/verifiche/scanner-fase-2.md`.
- Dipende da: V-01.
- Accettazione: ciascun motore gira con `network: none`, workspace in sola lettura e il profilo di F1:V-07. In particolare: cache di ruff con workspace in sola lettura, chiamate di rete e telemetria di checkov e come disattivarle, eslint con una configurazione inclusa nell'immagine senza `node_modules` del repository, hadolint senza configurazione esterna.
- Spec: §7.2. ADR: 0004, 0006.

#### V-05 — Feed EPSS e KEV
- Agente: `devops`. Stato: **chiuso il 2026-11-13**; esito in `doc/verifiche/scanner-fase-2.md`. Da portare a D2-14: EPSS non ha una licenza dichiarata, trivy-db non dichiara le licenze dei dati.
- Percorsi: `doc/verifiche/scanner-fase-2.md`.
- Dipende da: nessuno.
- Accettazione: per EPSS e KEV, URL di distribuzione, formato, dimensione, frequenza di aggiornamento, checksum o firma disponibili, termini d'uso letti alla fonte con collegamento. Per OSV e trivy-db, i termini di ridistribuzione dei dati, che servono a D2-05.
- Spec: §6.1, §19. ADR: 0006.

#### V-06 — Misura preliminare di una scansione PR
- Agente: `test`. Stato: **chiuso il 2026-11-13**; esito in `doc/verifiche/scanner-fase-2.md`. La scansione completa più lenta dura 221 s: G2.d regge anche senza restringere i plugin ai file cambiati.
- Percorsi: `doc/verifiche/scanner-fase-2.md`.
- Dipende da: nessuno (CLI della Fase 1).
- Accettazione: sui 3 pilota della Fase 1, durata per plugin della scansione completa e, a mano, di una scansione limitata ai file di una PR reale scelta e registrata. Indica quali plugin si possono restringere ai file cambiati (SAST, qualità) e quali devono vedere tutto il repository (dipendenze, licenze da SBOM), e quanto margine resta sotto i 10 minuti. Serve ad A-10.
- Spec: §5. ADR: 0009, 0010.

#### V-07 — tree-sitter sui pilota
- Agente: `backend`. Stato: **chiuso il 2026-11-13**; esito in `doc/verifiche/scanner-fase-2.md`. Meno di 6 s e 42 MB sul pilota più grande, 5 file con errori su 5.259; gli alias di `tsconfig` vanno risolti o il grafo TypeScript perde gran parte degli archi interni.
- Percorsi: `doc/verifiche/scanner-fase-2.md`, codice usa e getta fuori dal repository.
- Dipende da: V-01.
- Accettazione: tempo, memoria e numero di file con errori di parsing per Python, JS, TS e TSX sui 3 pilota; casi di import non risolvibili staticamente (dinamici, alias di `tsconfig`, `__init__` impliciti). Serve ad A-05.
- Spec: §2, §3. ADR: 0004.

#### V-08 — Consolidamento
- Agente: `architect`. Stato: **chiuso il 2026-11-16**; esito in `doc/verifiche/scanner-fase-2.md`, sezione V-08. Nessun ADR `Accettato` da riaprire: gli esiti smentiti sono presupposti impliciti, recepiti da ADR-0020, 0023, 0026 e 0030 e dalle accettazioni di G-02, P-01, P-03 e P-04. Elenco per D2-14 nella stessa sezione.
- Percorsi: `doc/verifiche/scanner-fase-2.md`, `doc/adr/`.
- Dipende da: V-02, V-03, V-04, V-05, V-06, V-07.
- Accettazione: per ogni esito che contraddice un ADR esistente o una raccomandazione di questo piano, un emendamento o una nota in sezione 3. Elenco dei motori e componenti da portare a D2-14.
- Spec: §7.3. ADR: tutti.

### A — Decisioni e allineamento della specifica

Ogni ADR registra le decisioni dell'utente quando arrivano e le indica nella tabella di `doc/adr/README.md`.

#### A-01 — ADR-0016: modalità server e orchestrazione
- Agente: `architect`. Stato: **chiuso il 2026-11-13**; ADR-0016 `Accettato` (D2-01 decisa il 2026-11-10).
- Percorsi: `doc/adr/0016-*.md`.
- Dipende da: nessuno.
- Accettazione: opzioni di D2-01 con effetti su §5, §14, ADR-0002 e ADR-0004; con l'opzione raccomandata: `POST /v1/scans` come ingestione di report, idempotenza, limiti di dimensione, nessuna esecuzione sul server; strumentazione minima del server (durate e metriche via OpenTelemetry SDK, esportazione opzionale), senza stack.
- Spec: §2, §5, §9.2, §14, §15. ADR: 0002, 0004.

#### A-02 — ADR-0017: flusso del contratto OpenAPI
- Agente: `architect`. Stato: **chiuso il 2026-11-13**; ADR-0017 `Proposto` in attesa delle prove di B-01, C-08 e W-02.
- Percorsi: `doc/adr/0017-*.md`.
- Dipende da: nessuno.
- Accettazione: OpenAPI esportata da FastAPI in `schemas/openapi.json`, versionata, con `--check` in CI come gli altri schemi (ADR-0003); i tipi del frontend generati dal file in `schemas/`, mai scritti a mano, e controllo di deriva in CI; versione nel percorso (`/v1`) e regole di compatibilità; formato di errore unico.
- Spec: §2, §9.2. ADR: 0003.

#### A-03 — ADR-0018: modello dati relazionale e multi-tenancy
- Agente: `architect`. Stato: **chiuso il 2026-11-13**; ADR-0018 `Proposto` in attesa delle prove di C-07 e B-02. Aggiunge la tabella `finding_events` e la parte `graph` dell'ingestione.
- Percorsi: `doc/adr/0018-*.md`.
- Dipende da: A-01.
- Accettazione: tabelle di §4.3 necessarie in Fase 2 (`tenants`, `repositories`, `scans`, `findings`, `finding_occurrences`, `components`, `graph_nodes`, `graph_edges`, `exceptions`), escluse quelle di Fase 3; schema per tenant con `tenants` globale e migrazioni Alembic per schema; `id` opaco distinto dal fingerprint, unicità `(repository_id, fingerprint)`; `first_seen` e `last_seen` dal DB; precedenza tra stato e eccezioni sul server e `exceptions` di `.code-analyzer.yml`; dove si salvano i punteggi in ombra; conservazione dello storico.
- Spec: §4.1, §4.3. ADR: 0003, 0008, 0014.

#### A-04 — ADR-0019: autenticazione e RBAC
- Agente: `architect`. Stato: **stesura chiusa il 2026-11-16**; ADR-0019 `Accettato` (D2-02 decisa il 2026-11-16). Per S-01: token dell'utente nella SPA o cookie di sessione dal server. Per B-04: i nomi dei claim dei provider CI sono da confermare alla fonte.
- Percorsi: `doc/adr/0019-*.md`.
- Dipende da: A-03.
- Accettazione: OIDC per gli utenti con flusso per la SPA; OIDC dei provider CI per l'invio dei report, con verifica di emittente, audience e claim del repository; nessun token a lunga durata (§9.2); ruoli e matrice permessi per endpoint; `approved_by` di un'eccezione creata sul server è l'utente autenticato.
- Spec: §9.2. ADR: 0014.

#### A-05 — ADR-0020: `ca-graph`
- Agente: `architect`. Stato: **chiuso il 2026-11-16**; ADR-0020 `Proposto`. Estrazione in container firmato, smell sull'host; uscita `graph` nel manifest e `kind` `architecture` (C-01, C-02, A-16). Le definizioni degli smell sono trascritte a memoria: vanno confrontate con le pubblicazioni di §19 prima di G-05.
- Percorsi: `doc/adr/0020-*.md`.
- Dipende da: V-07.
- Accettazione: dove gira l'estrazione con tree-sitter (raccomandato: container firmato senza rete come un plugin, che emette il grafo nel formato di C-02; rilevamento degli smell sull'host, su dati); schema del grafo con `confidence`; definizione e soglie di Cyclic, Hub-Like e Unstable Dependency con riferimento alle pubblicazioni di §19, soglie in configurazione; granularità (modulo, pacchetto); `kind` del fingerprint per gli smell, senza cambiare `fp1` per i `kind` esistenti; churn estratto nello stesso container con git ombra come gitleaks (ADR-0012, emendamento per P-07).
- Spec: §3, §5 passo 4, §6.2, §7.3. ADR: 0001, 0004, 0007, 0008, 0012.

#### A-06 — ADR-0021: scoring Variante A, ombra, livelli e override
- Agente: `architect`. Stato: **stesura chiusa il 2026-11-17**, ADR `Proposto` (D2-10 era già decisa). Fissa: formula e arrotondamento a due decimali prima delle soglie; intervalli semiaperti; configurazione di scoring in un file completo (predefinito nel pacchetto, sovrascrittura del tenant o `--scoring-config`, mai `.code-analyzer.yml`), con impronta nella versione registrata; tabella G e P per ogni categoria con fallback dichiarati (CVSS assente 0,75; senza feed P 0,1; churn ignoto 0,3, minimo 0,1); definizione operativa di ciascun override, che alza un minimo senza cambiare il punteggio, e «segreto valido» non applicato; `percorso confermato` = `codeFlows` nel SARIF; `levels.source` `provisional|score` per D2-10; precedenza `--variant`, poi `scoring.variant`, poi il file; Variante B uguale ad A su qualità e architettura finché non c'è ADR-0023; sei casi per la tabella di regressione. **Aperto:** i valori numerici sono ipotesi da calibrare in X-02; che semgrep emetta `codeFlows` con le regole del prodotto è da verificare in K-12; ADR-0023 (Variante B).
- Percorsi: `doc/adr/0021-*.md`.
- Dipende da: A-07.
- Accettazione: G e P per ogni categoria, compresi secret, test, health, quality, licenze e IaC, con fallback se manca CVSS v4 (lacuna 5); intervalli semiaperti `[70,100]`, `[40,70)`, `[15,40)`, `[0,15)` (lacuna 6); definizione operativa di ciascun override di §6.3 e dichiarazione che "segreto valido" non si applica (lacuna 7); dove si registrano A e B (lacuna 4); pesi, soglie e override in un file di configurazione di scoring, con default nel pacchetto e sovrascrittura del tenant, mai da `.code-analyzer.yml`; precedenza tra `--variant` e `scoring.variant`; opzioni di D2-10.
- Spec: §6, §6.1, §6.3, §8, §9.1, §16 regola 3. ADR: 0009, 0012, 0013, 0014.

#### A-07 — ADR-0022: esposizione e churn
- Agente: `architect`. Stato: **chiuso il 2026-11-17**; ADR-0022 `Proposto`. Scostamento dalla sezione 3 da far vedere all'utente: con esposizione assente E vale 0,6 e non 0,3, per non premiare chi non registra il repository; il valore sta nella configurazione di scoring.
- Percorsi: `doc/adr/0022-*.md`.
- Dipende da: A-05.
- Accettazione: entrypoint per Python e JS/TS (dichiarati nei metadati del pacchetto, `__main__`, applicazioni web riconoscibili), raggiungibilità a livello di modulo sul grafo, uso di una dipendenza come import da un modulo raggiungibile; quando E vale 0,3 (ignota) e 0,2 (dipendenza di sviluppo); churn a 90 giorni come percentile per file, comportamento con clone superficiale (copertura ridotta dichiarata, mai un valore inventato).
- Spec: §6.1, §6.2. ADR: 0012.

#### A-08 — ADR-0023: Variante B
- Agente: `architect`. Stato: `LIBERO` (stesura); la chiude D2-11.
- Percorsi: `doc/adr/0023-*.md`.
- Dipende da: A-06.
- Accettazione: per ogni regola di code smell, metriche e soglie (dalle regole di ruff ed eslint che le espongono, V-03); indice di intensità e quantili sul benchmark; G degli architectural smell per tipo e dimensione; P come combinazione di churn e densità di violazioni con i pesi in configurazione; C come PageRank normalizzato; ADI per modulo; motori separati per code e architectural smell; nessuna presentazione degli smell come predittori di bug di concorrenza.
- Spec: §6.2. ADR: 0020, 0021.

#### A-09 — ADR-0024: feed EPSS e KEV, cache e mirror
- Agente: `architect`. Stato: **stesura chiusa il 2026-11-13**; ADR-0024 `Proposto`, la parte su mirror e firma attende D2-05.
- Percorsi: `doc/adr/0024-*.md`.
- Dipende da: V-05.
- Accettazione: sincronizzazione senza workspace come ADR-0006; porta in `ca_core/scoring/feeds/` e adattatore di rete fuori dal nucleo (ADR-0001); cache e soglia di età; origine dei feed solo da pacchetto, flag o ambiente (ADR-0014); mirror e firma degli snapshot secondo D2-05; comportamento con feed assente (P di A senza EPSS dichiarato nell'evidenza, mai un valore inventato).
- Spec: §5 passo 6, §6.1, §13. ADR: 0001, 0005, 0006, 0014.

#### A-10 — ADR-0025: baseline, modalità PR e finding nuovi
- Agente: `architect`. Stato: **chiuso il 2026-11-13**; ADR-0025 `Proposto`. Decide che in Fase 2 nessun plugin si restringe ai file cambiati (V-06) e che la baseline è un report passato alla CLI: K-16, C-01, C-04 e F-06 vanno letti con la sezione "Effetti sul piano" dell'ADR.
- Percorsi: `doc/adr/0025-*.md`.
- Dipende da: A-01, V-06.
- Accettazione: fonte della baseline (report del branch base dal server o da un artefatto della CI, oppure scansione del base nello stesso job, con il costo misurato in V-06); stati nuovo, esistente, risolto e `baselineState` SARIF; quali plugin si limitano ai file cambiati e quali no; `gate.mode: new-findings-only` reale; configurazione letta dal branch base in modalità PR (ADR-0014); clone necessario (`fetch-depth`).
- Spec: §5 passi 2 e 9, §8, §9.1, §12.1. ADR: 0008, 0009, 0010, 0011, 0014.

#### A-11 — ADR-0026: plugin di qualità, IaC e coverage
- Agente: `architect`. Stato: **chiuso il 2026-11-16**; ADR-0026 `Proposto`. Chiavi nuove per C-05 (`plugins.<nome>.disable_rules`, `plugins.coverage`), campi nuovi per C-01 (gruppo di correlazione, metrica), `kind` `coverage` e righe di ADR-0009 per A-16.
- Percorsi: `doc/adr/0026-*.md`.
- Dipende da: V-03, V-04.
- Accettazione: configurazione dei linter (raccomandato: regole incluse nell'immagine; la configurazione del repository non si esegue mai, perché `eslint.config.js` è codice; il repository può solo disattivare regole tramite le opzioni per plugin di `.code-analyzer.yml`); report di copertura letti come file del workspace indicati in `plugins.coverage`, con contenimento controllato e parser senza entità esterne; quali finding produce la copertura (soglie in configurazione); correlazione tra checkov, hadolint e trivy sugli stessi problemi senza cambiare `fp1` (gruppo di correlazione, non fusione); livello predefinito dei finding di qualità.
- Spec: §7.3, §8. ADR: 0004, 0007, 0008, 0014.

#### A-12 — ADR-0027: integrazioni CI
- Agente: `architect`. Stato: **stesura chiusa il 2026-11-16**; ADR-0027 `Proposto`, D2-12 e D2-13 ne chiudono la parte di pubblicazione. Comandi nuovi `notify` ed `export` e `ca-cli` che importa `ca-integrations` (A-16). I fatti sui provider sono da verificare alla fonte in N-04 e N-07.
- Percorsi: `doc/adr/0027-*.md`.
- Dipende da: A-01, A-10.
- Accettazione: forma dell'Action secondo ADR-0010 (`scan`, upload SARIF con `if: always()`, `gate`); commenti PR e check run: chi li scrive (CLI in CI o server), con quale token e permessi minimi; dove sta il codice che chiama le API di GitHub e GitLab e quale radice di composizione lo importa (emendamento di ADR-0001); un solo commento aggiornato per PR, solo finding nuovi; PR da fork e `pull_request_target`; report nativi GitLab; daemon necessario per GitLab (ADR-0004).
- Spec: §12.1, §12.2. ADR: 0001, 0004, 0010, 0011.

#### A-13 — ADR-0028: catalogo servizi
- Agente: `architect`. Stato: **stesura chiusa il 2026-11-16**; ADR-0028 `Accettato` (D2-04 decisa il 2026-11-16). Il contesto del servizio arriva a `scan` come file (`--service-context`); `GET /v1/service-context` per C-08. Per A-07: il valore di E senza registrazione proposto in sezione 3 premia chi non registra il repository.
- Percorsi: `doc/adr/0028-*.md`.
- Dipende da: A-03.
- Accettazione: fonte di tier ed esposizione secondo D2-04, valori predefiniti, e come il report dichiara la fonte usata per C ed E di ogni finding.
- Spec: §4.3, §6.1, §8, §18. ADR: 0014.

#### A-14 — ADR-0029: UI dell'elenco finding, perimetro e dati
- Agente: `architect`. Stato: **stesura chiusa il 2026-11-13** in `IPOTESI` (D2-15); ADR-0029 `Proposto`. Da aggiungere al piano dopo A-16: il testo di aiuto delle regole negli adattatori della Fase 1.
- Percorsi: `doc/adr/0029-*.md`.
- Dipende da: U-01, A-02.
- Accettazione: per ogni vista di U-01, gli endpoint e i campi che servono; endpoint aggiunti a §9.2 (elenco repository, elenco scansioni, dettaglio finding); campo per i passi di correzione nel `Finding` e sua fonte (`help` delle regole SARIF, testi delle regole proprie), reso sempre come testo; ordinamento predefinito e paginazione.
- Spec: §1, §4.1, §9.2, §13. ADR: 0017.

#### A-15 — ADR-0030: componenti del server e object storage
- Agente: `architect`. Stato: **stesura chiusa il 2026-11-16**; ADR-0030 `Accettato` (D2-07 decisa il 2026-11-16): l'utente ha scelto l'adattatore S3 già in Fase 2, che la stesura rinviava. Driver proposto con licenza ammessa; quello di riferimento resta sostituibile se approvato in D2-14.
- Percorsi: `doc/adr/0030-*.md`.
- Dipende da: V-02, A-01.
- Accettazione: porta `ArtifactStore` e adattatori; driver PostgreSQL scelto con la licenza verificata; nessun componente con licenza vietata da D-0013 incluso nel prodotto senza approvazione.
- Spec: §2, §15. ADR: 0001, 0013.

#### A-16 — Emendamenti agli ADR esistenti
- Agente: `architect`. Stato: `LIBERO`; la parte su ADR-0006 è `IPOTESI` (D2-09).
- Percorsi: `doc/adr/0001-*.md`, `0002`, `0006`, `0008`, `0009`, `0010`, `0013`, `doc/adr/README.md`.
- Dipende da: A-01, A-05, A-06, A-09, A-10, A-11.
- Accettazione: gli emendamenti elencati in sezione 4, ciascuno con data e motivo; `README.md` aggiornato; lacune 1–6, 11 e 12 marcate come risolte con l'ADR che le chiude.
- Spec: §3, §5, §9.1. ADR: tutti.

#### A-17 — Allineare `doc/PROJECT.md`
- Agente: `architect`. Stato: `LIBERO`.
- Percorsi: `doc/PROJECT.md`.
- Dipende da: A-01..A-16.
- Accettazione: §2 (Temporal, MinIO, versione di Python), §3 (pacchetti e cartelle nuovi), §5, §6.3, §8, §9, §12.1 (forma dell'Action), §13 (Gate 2 con G2.d) e §14 coerenti con gli ADR; nessuna incoerenza della sezione 5 lasciata senza riferimento.
- Spec: tutte. ADR: 0016..0030.

### U — UX e UI

`ux-ui` scrive in `doc/ux/`.

#### U-01 — Mappa delle pagine e flussi della Fase 2
- Agente: `ux-ui`. Stato: **chiuso il 2026-11-13** in `IPOTESI` (D2-15); `doc/ux/fase-2.md`, con le lacune per A-14 nella sezione 6 e due domande aperte per D2-15.
- Percorsi: `doc/ux/fase-2.md`.
- Dipende da: nessuno.
- Accettazione: pagine di D2-15 e loro navigazione; flussi di triage, dettaglio con passi di correzione, eccezione con motivazione e scadenza, stato della scansione; stati di caricamento, vuoto, errore e scansione parziale; per ogni vista, dati necessari, con le lacune segnalate ad `architect`. Separazione visibile tra finding nuovi ed esistenti. Nessuna vista di portfolio.
- Spec: §1, §4.1, §6, §13. ADR: nessuno.

#### U-02 — Design token e componenti di base
- Agente: `ux-ui`. Stato: **chiuso il 2026-11-13**; `doc/ux/tokens.json` e `doc/ux/componenti.md`. I contrasti dei token sono verificati da `doc/ux/check_tokens.py`, eseguito nei test.
- Percorsi: `doc/ux/`.
- Dipende da: U-01.
- Accettazione: token (colori, tipografia, spaziature) in un file leggibile da `frontend`; componenti di base (tabella densa, filtri, badge di livello con testo e non solo colore, pannello di dettaglio, dialogo).
- Spec: §1. ADR: nessuno.

#### U-03 — Criteri di accessibilità
- Agente: `ux-ui`. Stato: **chiuso il 2026-11-13**; `doc/ux/accessibilita.md`, con la verifica (automatica o manuale) indicata per ogni criterio.
- Percorsi: `doc/ux/`.
- Dipende da: U-01.
- Accettazione: criteri WCAG 2.2 AA applicati alle viste di U-01, navigazione da tastiera della tabella, contrasto, verificabili con test automatici in W-08 e con la revisione U-05.
- Spec: §1. ADR: nessuno.

#### U-04 — Punteggio spiegabile e confronto in ombra
- Agente: `ux-ui`. Stato: `LIBERO`.
- Percorsi: `doc/ux/`.
- Dipende da: U-01, A-06, A-08.
- Accettazione: come si mostrano G, P, E, C, pesi, soglie, evidenze e fonte di ciascun fattore accanto al punteggio; come si distinguono livello attivo e punteggi in ombra di A e B senza suggerire quale sia migliore (serve al protocollo di G2.b).
- Spec: §6.2. ADR: 0021, 0023.

#### U-05 — Revisione visiva e di accessibilità
- Agente: `ux-ui`. Stato: `LIBERO`.
- Percorsi: lettura di `web/`; esito in `doc/ux/`.
- Dipende da: W-04, W-05, W-06, W-07.
- Accettazione: scostamenti da U-01..U-04 elencati per gravità e corretti o accettati dall'utente.
- Spec: §1. ADR: nessuno.

### C — Contratti

Ogni contratto precede i task che lo implementano (ADR-0003). Il modello in `ca_core` è il generatore, il file in `schemas/` è l'artefatto per i consumatori, `schema_export --check` verde.

#### C-01 — Contratto `finding` della Fase 2
- Agente: `architect`. Stato: **chiuso il 2026-11-17**, con una parte da rivedere; `finding` 1.2. `LevelSource` con `score` e `override`; `baseline_state` (`new`, `existing`: un finding risolto non è un finding, sta nel report), `previous_path` solo con `existing`, `pathless_key`; `remediation` (testo semplice, fonte `tool`, `rule` o `derived`, al più 10 riferimenti http o https, nessun carattere di controllo) come ADR-0029; `variant_scores` (al più uno per variante, con fattori della stessa variante). **Da rivedere con ADR-0021 (A-06, non ancora scritto):** la forma dei punteggi in ombra è il minimo che ADR-0018 già fissa (punteggio, livello da punteggio, fattori con evidenza); la definizione dei fattori e dei livelli può cambiarla. Dipendenza formale non soddisfatta: C-01 dipende da A-06.
- Percorsi: `packages/ca-core/src/ca_core/models/finding.py`, `schemas/finding.schema.json`.
- Dipende da: A-06, A-10, A-14.
- Accettazione: `LevelSource` con `score` e `override` (aggiunta compatibile); punteggi in ombra per variante secondo ADR-0021; stato rispetto alla baseline; campo dei passi di correzione; `id` opaco. Casi validi e non validi in `tests/contract/`.
- Spec: §4.1. ADR: 0003, 0008, 0021, 0025, 0029.

#### C-02 — Contratto `graph`
- Agente: `architect`. Stato: **chiuso il 2026-11-17**; `ca_core/models/graph.py`, `schemas/graph.schema.json` (1.0) e test di contratto e di equivalenza. Porta anche entrypoint, churn per modulo e stato della storia (ADR-0022). `plugin-manifest` passa a 1.1 con l'uscita `graph`; il runner la recupera come le altre.
- Percorsi: `packages/ca-core/src/ca_core/models/graph.py`, `schemas/graph.schema.json`.
- Dipende da: A-05.
- Accettazione: nodi, archi con `confidence ∈ {dichiarato, dedotto, osservato}`, metriche per nodo, limiti di dimensione; è il formato emesso dal container di estrazione e letto dall'host.
- Spec: §3, §4.3. ADR: 0003, 0020.

#### C-03 — Contratto della configurazione di scoring
- Agente: `architect`. Stato: **chiuso il 2026-11-17**. `models/scoring_config.py` (nessun campo con un predefinito: i valori stanno solo nel file), `schemas/scoring-config.schema.json` versione 1.0, file predefinito `ca_core/scoring/default.json` (inserito nel wheel), `scoring/config.py` (`parse_config`, `load_default`, `config_version` = `<version>+<12 caratteri dell'impronta del contenuto normalizzato>`). Contiene soglie dei livelli, `levels.source` (`provisional` per D2-10), mappa di severità, G, P, E, C e i sei override con i loro parametri; nessun campo per «segreto valido». Il modello rifiuta soglie non decrescenti e mappe o fattori non monotoni. File di sovrascrittura completo, mai fuso. Il formato è JSON perché `ca-core` non ha un parser YAML; la CLI potrà accettare YAML (L-02). **Non fatto:** i parametri della Variante B (ADR-0023); la lettura da server per tenant (B-*); la tabella provvisoria di `scoring/levels.py` (ADR-0009) resta nel codice finché non esiste il livello da punteggio.
- Percorsi: `packages/ca-core/src/ca_core/models/scoring_config.py`, `schemas/scoring-config.schema.json`, default nel pacchetto `ca-core`.
- Dipende da: A-06, A-08.
- Accettazione: pesi, soglie dei livelli, mappe di severità, override, parametri della Variante B, versione; il file predefinito supera lo schema; nessun valore di scoring resta nel codice di `scoring/`.
- Spec: §6, §16 regola 3. ADR: 0021, 0023.

#### C-04 — Contratto `scan-report` della Fase 2
- Agente: `architect`. Stato: **chiuso il 2026-11-17**; `scan-report` 1.2, tutti i campi nuovi facoltativi (i report della Fase 1 restano validi). `scan` (tipo `full` o `pr`, commit base, numero della PR), `baseline` (stato `valid`, `missing` o `rejected` con codice del motivo, fonte, conteggi di nuovi ed esistenti, elenco dei risolti, quelli non valutati perché il loro plugin è fallito), `effective_config` (la configurazione per intero: la CLI la scrive già), `scoring` (variante attiva, versione della configurazione, ombra), `service_context` (valore e fonte di tier ed esposizione, ADR-0028), `enrichment` (snapshot EPSS e KEV con origine, data e SHA-256). Invarianti nel modello e provate: i conteggi quadrano con lo stato dei finding, nessuno stato senza una baseline valida, una baseline solo per una scansione `pr`. `service` e `scoring` restano tra le sezioni inerti finché non esistono K-04 e K-14: non le tolgo da `inert_sections` prima.
- Percorsi: `packages/ca-core/src/ca_core/models/scan_report.py`, `schemas/scan-report.schema.json`.
- Dipende da: C-01, A-09, A-10.
- Accettazione: modalità `full | pr`, commit base, conteggi nuovi, esistenti e risolti; variante attiva e versione della configurazione di scoring; snapshot EPSS e KEV con origine e data; fonte di C ed E; `service` e `scoring` non più tra le sezioni inerti.
- Spec: §5, §9.1. ADR: 0010, 0024, 0025.

#### C-05 — Contratto `code-analyzer-config` della Fase 2
- Agente: `architect`. Stato: **chiuso il 2026-11-17**; schema 1.1: `plugins.{ruff,eslint,checkov,hadolint}.disable_rules`, `plugins.coverage.reports`, `service.tier` limitato a 1..3. Il modo effettivo del gate resta nel report (C-04). Nessuna chiave per attivare regole, soglie, pesi o file di configurazione dei motori: i test lo provano.
- Percorsi: `packages/ca-core/src/ca_core/models/config.py`, `schemas/code-analyzer-config.schema.json`.
- Dipende da: A-10, A-11, A-13.
- Accettazione: opzioni per ruff, eslint, coverage (percorsi dei report, regole disattivate); `gate.mode` effettivo; trattamento di `service` secondo D2-04; nessuna chiave che consenta al repository di cambiare immagini, rete, isolamento o pesi di scoring.
- Spec: §8. ADR: 0014, 0025, 0026, 0028.

#### C-06 — Porte nuove del nucleo
- Agente: `architect`. Stato: **chiuso il 2026-11-17**; `ca_core/ports.py` e `fakes.py`. Quattro porte con fake in memoria, `lint-imports` verde, modelli che passano un giro di JSON (ADR-0002): `EnrichmentFeeds` (EPSS e KEV con le tre risposte di ADR-0024 e l'identità degli snapshot), `GitHistory` (churn con stato della storia e `changed_files`), `BaselineSource` (dove sta il report del commit base, con la fonte; la validazione resta a K-16), `ArtifactStore` (put da flusso con tetto e digest, open, exists, delete idempotente, nessuna sovrascrittura; `validate_artifact_key` per gli adattatori). Invarianti nei modelli: un churn senza storia completa non ha conteggi (ADR-0022), un punteggio solo con `found`, una baseline `found` solo con posizione e fonte. **Sovrapposizione con E-01:** la porta dei feed è definita qui; E-01 la usa e ci mette gli adattatori e il modello dei dati in `scoring/feeds/`. I flussi di byte dell'archivio non sono serializzabili: l'archivio serve ai passi del server, non ai passi della pipeline. Nessun adattatore reale ancora: restano G-11 (storia), E-02..E-04 (feed), K-16/K-17/B-12 (baseline), B-07 (archivio).
- Percorsi: `packages/ca-core/src/ca_core/ports.py`, `packages/ca-core/src/ca_core/fakes.py`.
- Dipende da: A-05, A-07, A-09, A-10.
- Accettazione: porte per feed di arricchimento, storia git (file cambiati, churn), fonte della baseline, archivio degli artefatti, ciascuna con un fake in memoria; ingressi e uscite serializzabili (ADR-0002); `lint-imports` verde.
- Spec: §5. ADR: 0001, 0002.

#### C-07 — Modello relazionale e prima migrazione
- Agente: `backend`. Stato: **chiuso il 2026-11-17**. `ca_api/db/models.py`: le nove tabelle di tenant di ADR-0018 (`repositories`, `scans`, `findings`, `finding_occurrences`, `components`, `graph_nodes`, `graph_edges`, `exceptions`, `finding_events`) senza schema esplicito, e `tenants` nello schema globale; nessuna tabella di Fase 3. Indice unico `(repository_id, fingerprint)`, digest del report unico per repository, vocabolari chiusi, formato di fingerprint e digest, `tier` 1..3, scansione `pr` con commit base, e un vincolo che impedisce a un'eccezione del repository di essere segnata come verificata. Identificativi UUID versione 7. Migrazioni Alembic con due rami (`global`, `tenant`), DDL esplicito e congelato (non legge i modelli), una tabella `alembic_version` per schema di tenant; applicate e annullate su PostgreSQL 16 in container. **Non fatto:** la conversione esplicita tra modello relazionale e modello Pydantic (B-03).
- Percorsi: `packages/ca-api/src/ca_api/db/`, migrazioni Alembic.
- Dipende da: A-03, A-04, A-13, C-01.
- Accettazione: tabelle di ADR-0018 per schema di tenant, indice unico `(repository_id, fingerprint)`, migrazione applicata e annullata su un PostgreSQL di test; nessuna tabella di Fase 3.
- Spec: §4.3. ADR: 0018.

#### C-08 — OpenAPI v1
- Agente: `backend`. Stato: **chiuso il 2026-11-17** per le route di ADR-0029. `ca_api/problem.py` (formato di errore unico `application/problem+json`, enum dei codici, il 422 predefinito di FastAPI sostituito, mai il valore ricevuto), `ca_api/models.py` (pagine, riepiloghi, finding in forma breve, dettaglio, richieste di triage come unione discriminata per `action`, `approved_by` assente) e `ca_api/routes.py` (15 operazioni con `operationId` stabili, `x-required-roles` dalla matrice di ADR-0019, sicurezza `oidc` come bearer JWT, risposte 401/403/404/422/500 e quelle specifiche di `POST /scans`: 200, 201, 409, 413). Le route rispondono 501 `not-implemented` con il formato unico. `schemas/openapi.json` versione 1.1.0; `Finding`, `Graph`, `ServiceContextFile` e i componenti di `scan-report` sono quelli del nucleo (provato contro `schemas/`, a meno di `$id`, `default: null` e 3.0/3). Esempi validati contro i propri schemi. **Nuova dipendenza:** `python-multipart` 0.0.34 (licenza permissiva, rilasci fino al 2026-11-16) per `POST /scans`; i limiti di dimensione li applica B-03 mentre legge. **Non fatto:** l'endpoint della baseline per la modalità PR (B-12, ADR-0025) non è in ADR-0029 e non è dichiarato; i tipi TypeScript generati (W-02); `info.version` sale a 1.1.0 per le nuove operazioni.
- Percorsi: `packages/ca-api/src/ca_api/`, `schemas/openapi.json`.
- Dipende da: A-02, A-04, A-14, C-01, C-04.
- Accettazione: route e modelli di ADR-0029 dichiarati con risposte, errori ed esempi, anche senza implementazione; export con `--check`; schemi di `Finding` e `ScanReport` riusati, non duplicati; sicurezza OIDC dichiarata.
- Spec: §9.2. ADR: 0017, 0019, 0029.

#### C-09 — Formati in uscita delle integrazioni
- Agente: `architect`. Stato: **chiuso il 2026-11-17**. Schemi GitLab `sast` e `dependency_scanning` fissati al tag v15.2.5 in `vendor_schemas` (licenza permissiva, letta in V-02; manifest e ancora dell'hash aggiornati) con test di contratto; `ca_integrations.limits` e `ca_integrations.models` (commento con marcatore non falsificabile, check run, annotazioni, elemento `codequality`) con i limiti. **Non verificati:** i limiti di GitHub (a memoria, da leggere alla fonte in N-02 e N-03) e le versioni di CycloneDX che GitLab accetta (N-06). `codequality` non ha uno schema ufficiale: il modello è il formato Code Climate.
- Percorsi: `packages/ca-integrations/`, schemi GitLab fissati in `vendor_schemas` se la licenza lo consente.
- Dipende da: A-12, V-02.
- Accettazione: versioni fissate dei formati GitLab `sast`, `dependency_scanning`, `codequality` e CycloneDX; modello del commento PR e del riepilogo della check run con i limiti di dimensione.
- Spec: §12.1, §12.2. ADR: 0003, 0027.

#### C-10 — Test di contratto sui nuovi schemi
- Agente: `test`. Stato: `LIBERO`.
- Percorsi: `tests/contract/`.
- Dipende da: C-01, C-02, C-03, C-04, C-05, C-08, C-09.
- Accettazione: per ogni schema nuovo o cambiato, casi validi e non validi validati sui file in `schemas/` senza importare i modelli, e un test di equivalenza modello e schema come in Fase 1.
- Spec: §14. ADR: 0003.

### F — Fixture e attesi

#### F-01 — Fixture del grafo
- Agente: `test`. Stato: **chiuso il 2026-11-17**; `tests/fixtures/repos/graph-python` e `graph-js-ts` (33 archi interni ciascuna, 34 moduli) con `expected-graph.yaml` e `tests/fixtures/expected-graph.schema.json`. Un ciclo di moduli e uno di pacchetti, un hub, una dipendenza instabile e un negativo per ciascuno (utility molto importata, modulo che importa molto, chain aciclica, dipendenza verso un pacchetto più stabile), più un modulo di test che non deve contare. **Gli attesi sono scritti dal progetto e non copiati dall'output dell'estrattore**; i test confermano che l'estrattore dà gli stessi archi e che estrazione più metriche dà gli stessi numeri. Nota per G-06 e G-07: con la definizione di ADR-0020 e mediana pari a 0 qualunque modulo con un arco in entrata e uno in uscita supera la mediana, quindi gli attesi dell'hub valgono con `hub_min_degree: 6`, scritto nel file; è la guardia contro il rumore che l'ADR lascia in configurazione.
- Percorsi: `tests/fixtures/repos/`.
- Dipende da: C-02.
- Accettazione: repository Python e JS/TS con un ciclo, un hub e una dipendenza instabile noti, più un caso negativo per ciascuno, e attesi in formato verificabile automaticamente.
- Spec: §6.2, §13. ADR: 0020.

#### F-02 — Fixture di qualità e IaC
- Agente: `test`. Stato: **chiuso il 2026-11-16**; fixture `quality-python`, `quality-js-ts` e `iac-app` in `tests/fixtures/repos/`, con attesi osservati eseguendo ruff 0.17.5, eslint 10.14.0, checkov 3.4.5, hadolint 2.15.1 e trivy 0.76.2. Undici problemi di `iac-app` sono visti da due o tre strumenti e portano la chiave `correlation`, nuova nello schema degli attesi (K-21). Le tre fixture restano fuori dagli E2E finché i plugin non esistono: le collega T-03. Provate di passaggio: ruff accetta `--no-respect-gitignore` e `--ignore-noqa` con `--isolated`, hadolint accetta `--disable-ignore-pragma`, checkov con i file passati uno per uno risolve anche i controlli tra risorse del campione.
- Percorsi: `tests/fixtures/repos/`.
- Dipende da: V-03.
- Accettazione: problemi noti per ruff, eslint, checkov (Dockerfile, Kubernetes, Terraform) e hadolint, con attesi; almeno un problema rilevato sia da trivy sia da checkov, per la correlazione.
- Spec: §7.3. ADR: 0026.

#### F-03 — Fixture di copertura
- Agente: `test`. Stato: **chiuso il 2026-11-17**; `tests/fixtures/coverage/` con report validi (LCOV di coverage.py e di vitest, Cobertura con e senza DTD, report vuoto con valori non numerici) e ostili (entità, espansione di entità, DTD esterna, percorsi che escono dal workspace, formato corrotto), più `expected.yaml` con gli esiti. I limiti di dimensione, di elementi e di profondità non sono versionati: li genera il test di P-05 (elencati in `generated_limits`).
- Percorsi: `tests/fixtures/`.
- Dipende da: A-11.
- Accettazione: report LCOV e Cobertura validi, e ostili (entità XML, dimensione eccessiva, percorsi che escono dal workspace), con esiti attesi.
- Spec: §7.3. ADR: 0026.

#### F-04 — Snapshot congelato di EPSS e KEV
- Agente: `test`. Stato: `LIBERO`.
- Percorsi: `tests/fixtures/feeds/`.
- Dipende da: V-05, C-06.
- Accettazione: snapshot ridotto con i CVE delle fixture, alcuni in KEV e con EPSS sopra e sotto 0,1; nessuna rete nei test.
- Spec: §16 regola 7. ADR: 0024.

#### F-05 — Tabella di regressione dello scoring
- Agente: `test`. Stato: **parziale, 2026-11-17**. `tests/fixtures/scoring/cases.json`, con valori ricavati a mano da ADR-0021 e ADR-0022 e non dal codice: G per ogni categoria (26 casi), P (6), E (7), C (4), override (5), i sei punteggi dell'ADR e i bordi 14,99, 15, 39,99, 40, 69,5, 69,99, 69,995 e 70. **Non fatto:** i casi della Variante B (ADR-0023 non esiste); i casi di P per qualità e SAST sono nei test unitari, non nella tabella.
- Percorsi: `tests/fixtures/scoring/`.
- Dipende da: C-03.
- Accettazione: casi con fattori, punteggio e livello attesi per A e B, per ogni categoria, ogni override e i bordi 15, 40 e 70 (incluso 69,5); i valori attesi si ricavano da ADR-0021 e ADR-0023, non dal codice.
- Spec: §6.3, §14. ADR: 0021, 0023.

#### F-06 — Costruttore di repository per le PR
- Agente: `test`. Stato: **chiuso il 2026-11-16**; `tests/fixtures/builders/pr_repository.py` con i suoi test. Copre anche le due aggiunte di ADR-0025: file rinominato con un finding e commit di `main` diverso dal base. La PR che indebolisce il gate è un secondo branch sopra il primo.
- Percorsi: `tests/fixtures/builders/`.
- Dipende da: A-10.
- Accettazione: repository git con branch base e branch PR che contengono finding nuovi, esistenti, risolti e spostati di riga (stesso fingerprint), e una PR che modifica `.code-analyzer.yml` per indebolire il gate.
- Spec: §5. ADR: 0008, 0014, 0025.

### G — `ca-graph`

#### G-01 — Pacchetto `ca-graph`
- Agente: `backend`. Stato: **chiuso il 2026-11-17**; pacchetto nel workspace con scheletro (`deps`, `smells`, `pagerank`, `treesitter`). Contratti `import-linter`: indipendente da `ca_plugins` e `ca_integrations`, senza rete né processi, parser importabile solo da `ca_graph.treesitter`, che a sua volta non importa `ca_core`. tree-sitter è un extra `extract`, non una dipendenza.
- Percorsi: `packages/ca-graph/`, `pyproject.toml`.
- Dipende da: A-05.
- Accettazione: pacchetto nel workspace, contratti `import-linter` (`ca_graph` verso `ca_core`, `ca_cli` verso `ca_graph`, nessuna rete né processi), copertura misurata.
- Spec: §3. ADR: 0001.

#### G-02 — Estrattore Python
- Agente: `backend`. Stato: **chiuso il 2026-11-17**; `ca_graph/treesitter/python.py` e `extract.py`. Import assoluti e relativi, pacchetti con e senza `__init__.py` (arco `dedotto`), `TYPE_CHECKING`, `importlib.import_module` letterale come arco dinamico e calcolato contato; radici di sorgenti da `src` e dai file di progetto. Test sui casi di V-07 e su quelli ostili. Il grafo è valido contro lo schema e il modello. Mancano le fixture F-01 (i test costruiscono i workspace da soli) e le misure sui pilota.
- Percorsi: `packages/ca-graph/src/ca_graph/treesitter/`.
- Dipende da: G-01, C-02.
- Accettazione: import assoluti e relativi, pacchetti con e senza `__init__.py` (V-07); import non risolvibili marcati, mai inventati; output conforme a C-02 sui fixture di F-01 e sui casi di V-07.
- Spec: §3. ADR: 0020.

#### G-03 — Estrattore JS/TS/TSX
- Agente: `backend`. Stato: **chiuso il 2026-11-17**; `ca_graph/treesitter/javascript.py`. Tutte le forme di import, alias di `tsconfig` letti come dati non fidati con `extends` limitato, pacchetti del workspace, convenzione `.js` → `.ts`, `import()` e `require()` letterali o contati. Limiti noti elencati in ADR-0020, «Realizzazione»; ognuno dà un arco mancante contato, mai uno inventato. Il contratto `graph` passa a 1.1 (`files_skipped_name`).
- Percorsi: `packages/ca-graph/src/ca_graph/treesitter/`.
- Dipende da: G-01, C-02.
- Accettazione: `import`, `export … from`, `require` e `import()` con stringa letterale, alias di `tsconfig` letti come dati; output conforme a C-02.
- Spec: §3. ADR: 0020.

#### G-04 — Grafo delle dipendenze tra moduli
- Agente: `backend`. Stato: **chiuso il 2026-11-17**; `ca_graph/deps.py` sull'host, sui dati del grafo (nessun parser). `build` dà le adiacenze ordinate di moduli e pacchetti, `with_metrics` riempie `metrics` dei moduli e l'elenco `packages`. Ca e Ce contano nodi distinti, tra pacchetti solo gli archi tra cartelle diverse, `I = Ce/(Ca+Ce)` con 0 per un nodo isolato; i moduli di test fuori per default, gli archi di soli tipi dentro, entrambi opzioni. Deterministico in qualunque ordine di moduli e archi. Provato sulle fixture F-01.
- Percorsi: `packages/ca-graph/src/ca_graph/deps.py`.
- Dipende da: G-02, G-03.
- Accettazione: grafo per modulo e per pacchetto, metriche di accoppiamento e instabilità; determinismo (stesso input, stesso grafo).
- Spec: §3, §6.2. ADR: 0020.

#### G-05 — Smell Cyclic Dependency
- Agente: `backend`. Stato: **chiuso il 2026-11-17**; `ca_graph/smells/cycles.py`. Componenti fortemente connesse (Tarjan iterativo, provato su 20.000 nodi e contro un algoritmo ingenuo su grafi casuali) a livello di modulo e di pacchetto, dimensione minima e livelli attivi in `SmellConfig`, evidenza con livello, dimensione, archi e membri (al più 20). Le fixture F-01 danno il ciclo di 3 moduli e quello di 2 pacchetti in entrambe le lingue, e nessuno dei negativi. **Le definizioni degli smell sono ancora trascritte a memoria** (nota di ADR-0020, richiesta di A-05): vanno confrontate con le pubblicazioni prima di fidarsi dei primi risultati.
- Percorsi: `packages/ca-graph/src/ca_graph/smells/`.
- Dipende da: G-04, F-01.
- Accettazione: cicli di F-01 trovati, casi negativi assenti, soglie lette dalla configurazione, dimensione del ciclo nell'evidenza.
- Spec: §6.2. ADR: 0020.

#### G-06 — Smell Hub-Like Dependency
- Agente: `backend`. Stato: **chiuso il 2026-11-17**; `smells/hub.py`: fan-in e fan-out entrambi sopra la mediana (stretta), sbilanciamento sotto `hub_balance` e grado minimo `hub_min_degree`, tutti in `SmellConfig`. Provato che senza la guardia il rumore di grado 1/1 compare (`billing/c`, `catalog/price`), e che con la guardia a 6 resta solo l'hub vero; utility e punti d'ingresso non lo sono mai. Stessa avvertenza sulla definizione trascritta a memoria.
- Percorsi: `packages/ca-graph/src/ca_graph/smells/`.
- Dipende da: G-04, F-01.
- Accettazione: come G-05 per gli hub.
- Spec: §6.2. ADR: 0020.

#### G-07 — Smell Unstable Dependency
- Agente: `backend`. Stato: **chiuso il 2026-11-17**; `smells/unstable.py`: un pacchetto con una dipendenza verso uno con instabilità *maggiore*; l'uguaglianza non conta, quindi un ciclo tra pacchetti pari non genera questo smell. Grado e dipendenze minime in `SmellConfig`. F-01: `stable → volatile` trovata, negativi assenti. Stessa avvertenza.
- Percorsi: `packages/ca-graph/src/ca_graph/smells/`.
- Dipende da: G-04, F-01.
- Accettazione: come G-05 per le dipendenze instabili.
- Spec: §6.2. ADR: 0020.

#### G-08 — PageRank
- Agente: `backend`. Stato: **chiuso il 2026-11-17**; `ca_graph/pagerank.py`. Arco A→B = «A dipende da B», nodi pendenti con massa distribuita su tutti, parametri in `PageRankConfig`, uscita grezza che somma a 1 e `normalized` che divide per il massimo (il più critico vale 1). Provato su valori noti (due moduli, ciclo, stella, assenza di archi), su proprietà con hypothesis (distribuzione, intervallo, indipendenza dall'ordine byte per byte) e su F-01. **La normalizzazione per il massimo è una mia scelta**: §6.2 dice solo «normalizzato in [0,1]» e ADR-0023 (A-08) non esiste ancora; min-max darebbe 0 a un grafo uniforme.
- Percorsi: `packages/ca-graph/src/ca_graph/pagerank.py`.
- Dipende da: G-04.
- Accettazione: PageRank normalizzato in [0,1], parametri in configurazione, verificato su grafi con risultato noto e con test di proprietà.
- Spec: §6.2. ADR: 0020, 0023.

#### G-09 — Esecuzione isolata dell'estrazione
- Agente: `devops`, con `backend`. Stato: **chiuso il 2026-11-17** per sviluppo e uso interno (firma e SBOM non fatti: servono cosign e syft). `builtin/ca_graph/`, immagine costruita e provata nel profilo duro con uscita identica all'estrazione in processo, 126 MB, circa 0,15 s sulle fixture. Il contesto di build include l'estrattore da `packages/ca-graph` tramite `deploy/docker/stage-context.sh` e `context.sources`, senza copiare il codice. Il manifest e l'adattatore condividono lo stesso limite di 64 MiB; un grafo oltre il limite è exit 5, un limite di file superato è exit 3. Il harness di contratto dei plugin ora conosce `.graph.json`.
- Percorsi: `packages/ca-plugins/src/ca_plugins/builtin/ca_graph/`, `deploy/docker/`.
- Dipende da: G-02, G-03.
- Accettazione: immagine firmata con manifest, licenze e SBOM; gira con `network: none` e workspace in sola lettura; emette il grafo nel formato di C-02 entro `max_bytes`; test di contratto sul grafo emesso. Se ADR-0020 sceglie l'esecuzione sull'host, il task diventa la sola misura dei limiti sui pilota.
- Spec: §7.2, §7.3. ADR: 0004, 0005, 0020.

#### G-10 — Passo `build_graph` e finding di architettura
- Agente: `backend`. Stato: **chiuso il 2026-11-17**; `ca_graph/step.py`, agganciato in `ca_cli/scan.py` e a `normalize` con `extra_findings`. Fingerprint `kind` `architecture` stabile al variare delle righe e quando un ciclo cresce (provato), livello provvisorio `basso`/`default`, esclusioni applicate al grafo, passo idempotente e puro rispetto alle porte, fallimento dell'estrazione come finding `health` e scansione parziale. `scan` scrive `code-analyzer.graph.json`. ADR-0008 emendato. Gli smell usano ancora i predefiniti, senza la guardia dell'hub (X-02).
- Percorsi: `packages/ca-core/src/ca_core/pipeline/`, `packages/ca-graph/`.
- Dipende da: G-05, G-06, G-07, G-09, C-06, A-16.
- Accettazione: passo idempotente e serializzabile come gli altri (ADR-0002); smell normalizzati in `Finding` con `category: architecture`, fingerprint stabile al variare delle righe; fallimento dell'estrazione come finding `health`.
- Spec: §5 passo 4. ADR: 0002, 0008, 0020.

#### G-11 — Churn e densità di violazioni
- Agente: `backend`. Stato: **chiuso il 2026-11-17** per il churn; **densità di violazioni non fatta**. `ca_graph/treesitter/history.py` (stdlib, nell'immagine): git dir ombra come in ADR-0012 (config scritta dal plugin, `HEAD` validato, estensioni ammesse in elenco, collegamenti ai soli dati), un solo `git log --no-merges --no-renames -z --name-only` con tetti su commit (200 mila), byte (256 MiB) e durata (120 s, il processo si termina con il suo gruppo), finestra di 90 giorni **che finisce alla data del commit analizzato**; stato `completa`, `superficiale` (un clone superficiale è comunque `completa` se i commit di confine sono più vecchi della finestra) o `assente` (nessun `.git`, non replicabile, fallimento o tetto superato: mai un grafo troncato). Il grafo ha `churn` per modulo (0 per i file non toccati) solo con storia completa. L'immagine di `ca-graph` ora contiene git (pacchetto Debian non fissato, come per gitleaks; avvisi di licenza aggiornati) e `pids` sale a 32. Provato su repository veri (date fisse, merge, rinomine, nomi insoliti, clone superficiale, `.git` non ammessi, configurazione ostile che non viene eseguita, tetti, timeout) e sull'immagine reale con il profilo completo (`tests/integration/test_ca_graph_image.py`, 5 test). Sull'host `scoring/churn.py::ChurnIndex`: percentile come quota di file con churn strettamente minore, test fuori popolazione, ignoto senza storia completa. **Non fatto:** la densità di violazioni per file (la definisce ADR-0023, non ancora scritto); le rinomine non si seguono (scelta di ADR-0022); il commit analizzato è HEAD del workspace; non provato su un clone grande (X-05 misura i tempi).
- Percorsi: `packages/ca-plugins/src/ca_plugins/builtin/ca_graph/`, `packages/ca-core/src/ca_core/`.
- Dipende da: A-07, C-06, G-09.
- Accettazione: churn a 90 giorni per file calcolato nel container con git ombra, senza eseguire comandi da configurazione git ostile (test come in F1:P-07); clone superficiale dichiarato come copertura ridotta; densità di violazioni per file dai finding di qualità.
- Spec: §6.1, §6.2. ADR: 0012, 0022.

#### G-12 — Raggiungibilità
- Agente: `backend`. Stato: **chiuso il 2026-11-17** per il calcolo sul grafo. `ca_graph/reachability.py` (`GraphReachability`: stati `raggiungibile`, `solo-test`, `non-raggiungibile`, `ignota` con il motivo; archi di soli tipi non seguiti; entrypoint più vicino; `non-raggiungibile` solo se non ci sono import non risolti, nessun file del linguaggio letto in parte e c'è almeno un entrypoint per quel linguaggio; uso delle dipendenze dal nome normalizzato più la tabella `import_names.py` versionata, mai «non usata»); tipi e protocollo `Reachability`/`NoReachability` in `ca_core.scoring.reach`. **Entrypoint nell'estrattore** (`treesitter/entrypoints.py`, che prima emetteva sempre un elenco vuoto): `pyproject.toml` (`scripts`, `gui-scripts`, `entry-points`, Poetry), `setup.cfg`, `package.json` (`main`, `module`, `bin`, `exports`; `scripts` e `setup.py` mai letti), prodotti della build cercati sotto `src/` e altrimenti contati in `entrypoint_missing`; dedotti: `__main__.py`, blocco `if __name__`, `manage.py`/`wsgi.py`/`asgi.py`, applicazioni di framework noti (serve anche l'import del framework), `src/main.*`, `src/index.*`, `index.html`. Verificato su F-01: `graph-js-ts` ha un entrypoint, `graph-python` nessuno (libreria: tutto `ignota`, come prevede l'ADR). **Non fatto:** transitive e dipendenze di sviluppo dichiarate da lockfile o SBOM (restano a K-04/K-15, serve l'SBOM); il conteggio degli import non risolti è per tutto il grafo e non per linguaggio, quindi un solo import calcolato rende `ignota` ogni modulo non raggiunto; il riconoscimento dei framework è per testo (import più chiamata), non per AST, e l'elenco è piccolo; l'immagine del plugin non è stata ricostruita; nessun collegamento ancora al passo `score`.
- Percorsi: `packages/ca-graph/src/ca_graph/`.
- Dipende da: A-07, G-04, C-06.
- Accettazione: entrypoint e moduli raggiungibili secondo ADR-0022, dipendenze usate da moduli raggiungibili, valore "ignota" quando i dati mancano; verificato su F-01.
- Spec: §6.1. ADR: 0022.

#### G-13 — ADI per modulo
- Agente: `backend`. Stato: `LIBERO`.
- Percorsi: `packages/ca-graph/src/ca_graph/`.
- Dipende da: G-05, G-06, G-07, G-08, A-08.
- Accettazione: ADI calcolato per modulo secondo ADR-0023, nel report e, con il server, nel DB; nessun trend in UI.
- Spec: §6.2. ADR: 0023.

### P — Plugin

Ogni plugin include manifest, adattatore in Python standard senza importare `ca-core`, `Dockerfile`, licenze, SBOM e test di contratto su output reali (§16 regola 4), come in Fase 1. D2-14 ferma la pubblicazione delle loro immagini (I-07), non lo sviluppo né l'uso interno: per questo i P-* nuovi sono `IPOTESI` (D2-14).

#### P-01 — ruff
- Agente: `backend`. Stato: **chiuso il 2026-11-17** per sviluppo e uso interno; la pubblicazione dell'immagine resta in I-07 (D2-14). Plugin `builtin/ruff/` con adattatore, manifest, Dockerfile con hash, licenze e fixture registrata; immagine costruita e provata nel profilo duro. Il nucleo guadagna `metric` e il livello di qualità limitato a `medio`; la CLI passa `disable_rules`. Dettagli in ADR-0026, «Realizzazione». Mancano firma, SBOM e misure sui pilota.
- Percorsi: `packages/ca-plugins/src/ca_plugins/builtin/ruff/`.
- Dipende da: A-11, F-02, T-02.
- Accettazione: SARIF con `category: quality`, `tool_severity`, `uri` relativi, metriche delle regole di complessità e dimensione nell'evidenza; regole incluse e disattivazioni da `.code-analyzer.yml`; nessuna scrittura nel workspace; `ruff.toml` e `pyproject.toml` ostili nel workspace senza effetto (V-04); problemi di F-02 rilevati.
- Spec: §7.3. ADR: 0007, 0026.

#### P-02 — eslint
- Agente: `backend`. Stato: **chiuso il 2026-11-17** alle stesse condizioni di P-01. Test con eslint reale e un repository ostile (configurazione eseguibile, `node_modules` ostile, direttive in linea): nulla del repository viene eseguito o letto.
- Percorsi: `packages/ca-plugins/src/ca_plugins/builtin/eslint/`.
- Dipende da: A-11, F-02, T-02.
- Accettazione: come P-01 per JS, TS e TSX, con configurazione e parser TypeScript inclusi nell'immagine; la configurazione del repository non viene caricata (test con un `eslint.config.js` ostile nel workspace).
- Spec: §7.3. ADR: 0007, 0026.

#### P-03 — checkov
- Agente: `backend`. Stato: **chiuso il 2026-11-17** per sviluppo e uso interno; la pubblicazione resta in I-07 (D2-14). Plugin `builtin/checkov/`: l'adattatore copia nel tmpfs i soli file utili senza i nomi dei file di configurazione di checkov (la strada che V-04 indicava come sicura) e lo esegue sulla copia; i controlli saltati da un commento tornano finding. Provato con checkov 3.4.5 reale (configurazione ostile, collegamenti simbolici, file troppo grandi) e nell'immagine costruita (339 MB, 34 risultati sulla fixture in 3 s). Il JSON senza `--quiet` pesa 300 KB sulla fixture, perché porta anche i controlli superati: scartati dall'adattatore, la memoria la limita il container (X-05).
- Percorsi: `packages/ca-plugins/src/ca_plugins/builtin/checkov/`.
- Dipende da: A-11, F-02, T-02.
- Accettazione: SARIF con `category: iac`, telemetria e controlli di versione disattivati, nessuna rete; `.checkov.yaml` ostile nel workspace senza effetto e nessun frammento di codice in `/out` (V-03, V-04); Dockerfile, Kubernetes e Terraform di F-02 rilevati.
- Spec: §7.3. ADR: 0007, 0026.

#### P-04 — hadolint
- Agente: `backend`. Stato: **chiuso il 2026-11-17** per sviluppo e uso interno. Plugin `builtin/hadolint/`: binario statico scaricato con controllo dell'SHA-256 durante la build, testo della licenza scaricato dal tag del sorgente e **non copiato nel repository** (così l'auto-analisi non apre un finding), offerta della sorgente scritta nelle note di terzi. Provato con hadolint 2.15.1 reale: `.hadolint.yaml` ostile (anche in sottocartella) e variabili `HADOLINT_*` senza effetto, `--disable-ignore-pragma` ignora `ignore` e `global ignore`, errori di sintassi come finding `DL1000`. Immagine costruita e provata nel profilo duro (175 MB, 8 risultati in 0,08 s). Stato precedente: `LIBERO` per sviluppo e uso interno (2026-11-17, D2-14 per hadolint decisa). La pubblicazione dell'immagine resta in I-07 e richiede, oltre al resto, testo della licenza e offerta della sorgente del binario nell'immagine.
- Percorsi: `packages/ca-plugins/src/ca_plugins/builtin/hadolint/`.
- Dipende da: A-11, F-02, T-02.
- Accettazione: SARIF con `category: iac`, Dockerfile trovati nel workspace, `.hadolint.yaml` ostile nel workspace senza effetto (V-04), problemi di F-02 rilevati.
- Spec: §7.3. ADR: 0007, 0026.

#### P-05 — coverage
- Agente: `backend`. Stato: **chiuso il 2026-11-17** per sviluppo e uso interno (I-07 resta fermo su D2-14, ma questo plugin non ha motori di terzi: solo l'interprete e Debian). Plugin `builtin/coverage/` con libreria standard sola: XML con `pyexpat` sui byte e rifiuto di ogni dichiarazione di entità in qualunque codifica (S3-A1), apertura del report senza seguire collegamenti simbolici e con contenimento anche dei percorsi intermedi, tetti su byte, elementi e profondità, unione riga per riga di più report. Nucleo: `kind` `coverage` (ADR-0008), categoria `test` con livello limitato a `medio`. Immagine costruita e provata nel profilo duro. **Lacuna:** l'avviso `coverage-report-missing` di ADR-0026 non esce, perché il contratto dei plugin non ha un canale per gli avvisi (solo SARIF); un report assente dà zero finding senza dirlo. Serve un'estensione del contratto, da decidere.
- Percorsi: `packages/ca-plugins/src/ca_plugins/builtin/coverage/`.
- Dipende da: A-11, F-03, C-05, T-02.
- Accettazione: LCOV e Cobertura letti dai percorsi di `plugins.coverage`, con contenimento nel workspace; finding `category: test` secondo ADR-0026; i report ostili di F-03 fanno fallire il plugin senza effetti; report assente dichiarato, non un fallimento.
- Spec: §7.3. ADR: 0007, 0014, 0026.

#### P-06 — osv-scanner su ecosistema senza database (riporto dalla Fase 1)
- Agente: `backend`. Stato: **chiuso il 2026-11-10** (D2-09 decisa); CI verde su `main` (`e2e` 42916043217).
- Percorsi: `packages/ca-plugins/src/ca_plugins/builtin/osv_scanner/`, `tests/fixtures/`.
- Dipende da: A-16.
- Accettazione: un repository Python o JS/TS con un `pom.xml` dà una scansione `complete` con avviso `feeds-ecosystem-missing` che nomina l'ecosistema; un ecosistema in elenco senza database fa ancora fallire il plugin; test su entrambi i casi senza rete.
- Spec: §7.2. ADR: 0006.

#### P-07 — B101 di bandit (riporto dalla Fase 1)
- Agente: `backend`. Stato: **chiuso il 2026-11-13** (D2-08 decisa lo stesso giorno, opzione 2); CI verde su `main` (`e2e` 43430902706). Misura su saleor (`1d707dc`, immagine ricostruita, profilo completo): B101 da 47.276 a 22, risultati di bandit 85, SARIF da 19,2 MB a 30 KB, 62 s.
- Percorsi: `packages/ca-plugins/src/ca_plugins/builtin/bandit/`.
- Dipende da: nessuno.
- Accettazione: B101 scartato nei soli file di test, riconosciuti con regole di percorso fisse nell'adattatore; un `assert` in un modulo di produzione resta un finding; il conteggio su saleor viene rimisurato e registrato.
- Spec: §7.3. ADR: 0007, 0009.

### E — Feed di arricchimento

#### E-01 — Modello e porta dei feed
- Agente: `backend`. Stato: **chiuso il 2026-11-17** (con C-06 per la porta). `ca_core/scoring/feeds/`: `limits.json` con i tetti di ADR-0024 (nella configurazione del pacchetto), `parse_epss` e `parse_kev` (lettura difensiva: intestazione, righe, intervalli, duplicati, numero di voci; di KEV si leggono solo `cveID`, `dateAdded` e `knownRansomwareCampaignUse`), controllo di plausibilità del calo, `SnapshotFeeds` con le tre risposte. Verificato sui file veri del 2026-11-17: 407.165 voci EPSS in 0,55 s e 1.781 voci KEV.
- Percorsi: `packages/ca-core/src/ca_core/scoring/feeds/`.
- Dipende da: C-06.
- Accettazione: modello dei dati EPSS e KEV e dello snapshot (origine, data, integrità), ricerca per CVE, nessun I/O nel nucleo (`lint-imports`).
- Spec: §3, §6.1. ADR: 0001, 0024.

#### E-02 — Adattatore EPSS
- Agente: `backend`. Stato: **chiuso il 2026-11-17** insieme a E-03 in `ca_plugins/enrichment.py`: HTTPS con redirect solo verso lo stesso host (al massimo 5), tetto di byte durante la lettura, tetto sulla decompressione gzip (provato con una bomba), cache per utente con puntatore atomico, riconvalida e SHA-256 a ogni lettura, symlink mai seguiti, soglia di un giorno, `--offline` (`feeds-stale`), fallimento con snapshot precedente (`feeds-sync-failed`), nessuno snapshot (`enrichment-feed-missing`, risposte `snapshot-absent`). Provato contro i server veri il 2026-11-17 (1,9 s, poi dalla cache). **Non fatto:** il collegamento alla CLI (K-15/E-06).
- Percorsi: `packages/ca-plugins/src/ca_plugins/`.
- Dipende da: E-01, A-09.
- Accettazione: sincronizzazione senza workspace, controllo di integrità e di dimensione, cache con soglia di età, `--offline` la impedisce, lettura difensiva del file; test sullo snapshot di F-04 senza rete.
- Spec: §6.1. ADR: 0006, 0024.

#### E-03 — Adattatore KEV
- Agente: `backend`. Stato: **chiuso il 2026-11-17**, vedi E-02.
- Percorsi: `packages/ca-plugins/src/ca_plugins/`.
- Dipende da: E-01, A-09.
- Accettazione: come E-02 per KEV.
- Spec: §6.1. ADR: 0006, 0024.

#### E-04 — Origine configurabile dei feed
- Agente: `backend`. Stato: **chiuso in parte il 2026-11-17** (D2-05 decisa il 2026-11-17). Si riduce alla configurazione dell'origine; nessuna verifica di firma dello snapshot perché non c'è un mirror. Fatto per EPSS e KEV: `CA_FEEDS_EPSS_URL` e `CA_FEEDS_KEV_URL` (https, senza credenziali, un errore non ripete l'URL; l'origine nel report è `public` o `mirror`, mai l'URL). **Non fatto:** l'origine di OSV e trivy, il flag della CLI e il collegamento alla CLI.
- Percorsi: `packages/ca-plugins/src/ca_plugins/feeds.py`, `packages/ca-cli/`.
- Dipende da: E-02, E-03.
- Accettazione: origine di OSV, trivy, EPSS e KEV da pacchetto, flag o ambiente, mai da `.code-analyzer.yml`; con un mirror cambia solo l'origine (ADR-0006); verifica della firma dello snapshot se D2-05 la prevede.
- Spec: §13. ADR: 0005, 0006, 0014, 0024.

#### E-05 — Pubblicazione del mirror
- Agente: `devops`. Stato: **ESCE dalla Fase 2** (D2-05, 2026-11-17: nessun mirror). Resta qui il design di ADR-0024 per un lavoro futuro, che richiederebbe D2-16 e la valutazione di D2-14 sulla ridistribuzione.
- Percorsi: `.github/workflows/`, `deploy/`.
- Dipende da: E-04.
- Accettazione: snapshot firmati secondo ADR-0024 resi disponibili sulla destinazione di D2-16, verificabili dalla CLI con E-04; nessuna pubblicazione senza approvazione esplicita.
- Spec: §13, §15. ADR: 0005, 0024.

#### E-06 — Feed nel report
- Agente: `backend`. Stato: **chiuso il 2026-11-17**. `enrichment` nel report con feed, origine (`public` o `mirror`), ora di scaricamento, SHA-256 e identità del contenuto; avvisi `enrichment-feed-missing`, `feeds-stale` e `feeds-sync-failed` per feed; `scoring-with-fallbacks` col numero dei finding calcolati con un valore di ripiego. Senza un trasporto collegato (le prove) la scansione usa solo la cache e lo dichiara.
- Percorsi: `packages/ca-core/src/ca_core/pipeline/`, `packages/ca-cli/`.
- Dipende da: E-02, E-03, C-04.
- Accettazione: origine e data degli snapshot EPSS e KEV nel report; avviso se mancano o sono vecchi.
- Spec: §6.1. ADR: 0010, 0024.

### K — Scoring, livelli, baseline nel nucleo

#### K-01 — Interfaccia di scoring e configurazione
- Agente: `backend`. Stato: **chiuso il 2026-11-17** per l'interfaccia: `scoring/base.py` (`ScoringModel`, `ScoringContext` con la sola configurazione, `Factor` con evidenza, `impact` e `round_score` a due decimali metà verso l'alto) e `resolve_config(flag, tenant)` (il file della riga di comando, poi quello del tenant, poi il pacchetto; mai fusi; un file invalido è un errore, mai un ripiego sul predefinito). **Non fatto:** la lettura del file da percorso o da variabile d'ambiente nella CLI (L-02) e dal server (B-*); `ScoringContext` cresce con i dati di K-03, K-04 e K-05.
- Percorsi: `packages/ca-core/src/ca_core/scoring/base.py`, `packages/ca-core/src/ca_core/scoring/`.
- Dipende da: C-01, C-03, C-06.
- Accettazione: `ScoringModel` e `ScoringContext` di §6; caricamento della configurazione di C-03 con precedenza tra pacchetto, tenant e flag; nessun valore di scoring nel codice.
- Spec: §6. ADR: 0021.

#### K-02 — Variante A: G
- Agente: `backend`. Stato: **chiuso il 2026-11-17**. `scoring/variant_a.py::factor_g` per ogni categoria secondo ADR-0021 (CVSS più recente per versione diviso 10, senza CVSS 0,75; severità con il G più alto tra le due scale degli strumenti, senza severità 0,5; licenze dal verdetto e dal flag `distributed` che la policy ora scrive nell'evidenza; segreto, salute). Fallback sempre nell'evidenza. 26 casi G ricavati a mano da ADR-0021 in `tests/fixtures/scoring/cases.json`, che copre anche F-05 per G, i sei punteggi dell'ADR e i bordi; non coperti da F-05: P, E, C, override e Variante B.
- Percorsi: `packages/ca-core/src/ca_core/scoring/variant_a.py`.
- Dipende da: K-01, F-05.
- Accettazione: G per ogni categoria secondo ADR-0021, fallback senza CVSS v4, casi di F-05 verdi.
- Spec: §6.1. ADR: 0021.

#### K-03 — Variante A: P
- Agente: `backend`. Stato: **chiuso il 2026-11-17**. `variant_a.factor_p` per ogni categoria: dipendenze con KEV 1,0, altrimenti `max(epss, 0,01)`, una CVE non elencata vale il minimo, feed assente `feed_missing` (e mai sotto, anche con un solo feed assente), nessuna CVE valida `feed_missing`, più CVE il massimo con l'evidenza di ciascuna; SAST 0,8 con percorso confermato e 0,4 altrimenti; IaC, segreti, licenze e salute dalla configurazione; qualità, architettura e test dal percentile di churn con il minimo, e `churn unknown` se la storia non è completa. **«Percorso confermato» ridefinito:** il SARIF di semgrep non contiene `codeFlows` nemmeno con `--dataflow-traces` (provato sull'immagine il 2026-11-17), quindi la definizione di ADR-0021 non sarebbe mai scattata. Ora vale: il risultato viene da una regola `mode: taint` **del prodotto** (l'adattatore la riconosce dai file di regole dell'immagine e scrive `properties.taint`, contratto `plugin-sarif-properties` 1.2; la normalizzazione lo scrive come `path_confirmed`); i risultati delle regole del repository non lo ottengono mai. `ScoringContext` porta ora `feeds` e `churn`. **Non fatto:** l'immagine di semgrep non è stata ricostruita con la modifica; ADR-0021 va aggiornato su questo punto.
- Percorsi: `packages/ca-core/src/ca_core/scoring/variant_a.py`.
- Dipende da: K-01, E-01, G-11.
- Accettazione: KEV, EPSS con minimo 0,01, percorso SAST secondo ADR-0021, percentile di churn; feed assente dichiarato nell'evidenza; casi di F-05 verdi.
- Spec: §6.1. ADR: 0021, 0022, 0024.

#### K-04 — Fattore E
- Agente: `backend`. Stato: **chiuso il 2026-11-17** per il fattore. `scoring/exposure.py::factor_e`: raggiungibilità dal protocollo `Reachability` (modulo, più membri come un ciclo con lo stato migliore, cartelle per gli smell di pacchetto, uso della dipendenza dal purl npm o PyPI anche per le licenze dei componenti), esposizione dal contesto del servizio (K-05), valori 1,0, 0,6, 0,3 e 0,2 dalla configurazione; esposizione assente come interno; finding senza modulo come raggiungibili salvo i percorsi di test (0,2); senza grafo `ignota` con il motivo `grafo-assente`. L'evidenza porta regola, stato, entrypoint, motivo ed esposizione con la sua fonte. `ScoringContext` porta ora anche `reachability`; `Reachability` ha in più `package`. **Non fatto:** le dipendenze di sviluppo o di test dichiarate da lockfile o SBOM (E = 0,2): servono dati che arrivano con K-15; un purl di un ecosistema diverso da npm e PyPI vale `ignota`; il collegamento al grafo vero nel passo `score` (K-14).
- Percorsi: `packages/ca-core/src/ca_core/scoring/`.
- Dipende da: K-01, G-12, C-05.
- Accettazione: valori 1,0, 0,6, 0,3, 0,2 secondo ADR-0022, esposizione dalla fonte di D2-04, fonte registrata nell'evidenza; comune alle due varianti.
- Spec: §6.1, §6.2. ADR: 0022, 0028.

#### K-05 — Variante A: C
- Agente: `backend`. Stato: **chiuso il 2026-11-17**. `scoring/service.py`: `resolve_service_context(file, service)` con la precedenza di ADR-0028 per singolo valore (file `catalog`, blocco `service` `repository`, predefinito `default`), avvisi `service-config-ignored` e `service-from-repository`, e `factor_c` (tier 1, 2, 3 dalla configurazione; assente: `c.missing`; fonte e tier nell'evidenza). Nuovo contratto `service-context` 1.0 (`models/service_context_file.py`, schema, test di contratto e di equivalenza): il file di ADR-0028 non aveva ancora uno schema, anche se l'ADR lo assegnava a C-05. `ScoringContext` porta ora il contesto del servizio (predefinito: tutto `default`). **Non fatto:** il flag `scan --service-context` con le regole del percorso come la baseline, il comando `service-context` verso il server (B-10), e il collegamento al report (`service_context`) nel passo `score`/`enrich` (K-14, K-15).
- Percorsi: `packages/ca-core/src/ca_core/scoring/variant_a.py`.
- Dipende da: K-01, C-05.
- Accettazione: tier dalla fonte di D2-04, default 0,7, fonte registrata.
- Spec: §6.1. ADR: 0028.

#### K-06 — Distribuzione di benchmark della Variante B
- Agente: `backend`, con `test`. Stato: `LIBERO`.
- Percorsi: `packages/ca-core/src/ca_core/scoring/`, dato versionato nel pacchetto, procedura in `doc/verifiche/`.
- Dipende da: A-08, P-01, P-02.
- Accettazione: corpus di D2-11 con commit fissati, distribuzione per metrica calcolata con una procedura ripetibile e salvata come dato versionato; il ricalcolo è un'azione esplicita.
- Spec: §6.2. ADR: 0023.

#### K-07 — Variante B: G dei code smell
- Agente: `backend`. Stato: `LIBERO`.
- Percorsi: `packages/ca-core/src/ca_core/scoring/variant_b.py`.
- Dipende da: K-01, K-06.
- Accettazione: indice di intensità con quantili sul benchmark, casi di F-05 verdi.
- Spec: §6.2. ADR: 0023.

#### K-08 — Variante B: G degli architectural smell
- Agente: `backend`. Stato: `LIBERO`.
- Percorsi: `packages/ca-core/src/ca_core/scoring/variant_b.py`.
- Dipende da: K-01, G-10.
- Accettazione: severità per tipo per dimensione normalizzata, motore separato da K-07, casi di F-05 verdi.
- Spec: §6.2. ADR: 0023.

#### K-09 — Variante B: P
- Agente: `backend`. Stato: `LIBERO`.
- Percorsi: `packages/ca-core/src/ca_core/scoring/variant_b.py`.
- Dipende da: K-01, G-11, P-01, P-02.
- Accettazione: combinazione di churn e densità di violazioni con pesi in configurazione, casi di F-05 verdi.
- Spec: §6.2. ADR: 0023.

#### K-10 — Variante B: C
- Agente: `backend`. Stato: `LIBERO`.
- Percorsi: `packages/ca-core/src/ca_core/scoring/variant_b.py`.
- Dipende da: K-01, G-08.
- Accettazione: PageRank del componente normalizzato; per le categorie diverse da `quality` e `architecture` si usa la Variante A, verificato da test.
- Spec: §6.2. ADR: 0023.

#### K-11 — Calcolo in ombra di entrambe le varianti
- Agente: `backend`. Stato: **chiuso il 2026-11-17** per A e per la struttura di B. `scoring/models.py`: A completa; B coincide con A su qualità e architettura con il fallback `variante-b-non-definita` nell'evidenza finché ADR-0023 non esiste, e usa A per il resto. K-07..K-10 (Variante B) restano fermi su ADR-0023 e D2-11. Esempio di ADR-0021 verificato (49,00, alto).
- Percorsi: `packages/ca-core/src/ca_core/scoring/`.
- Dipende da: K-02, K-03, K-04, K-05, K-07, K-08, K-09, K-10, C-04.
- Accettazione: per ogni finding fattori e punteggio di A e di B registrati come da ADR-0021, con la versione della configurazione; determinismo.
- Spec: §6, §13. ADR: 0021, 0023.

#### K-12 — Livelli da punteggio
- Agente: `backend`. Stato: **chiuso il 2026-11-17**. `levels.level_from_score(score, thresholds)`: intervalli semiaperti, arrotondamento a due decimali prima del confronto (69,995 diventa 70,00 e quindi critico), soglie dalla configurazione. Bordi 15, 40 e 70, 69,5 e 69,99 verdi. La tabella provvisoria di ADR-0009 è intatta. Gli override sono K-13.
- Percorsi: `packages/ca-core/src/ca_core/scoring/levels.py`.
- Dipende da: K-01, F-05.
- Accettazione: intervalli semiaperti con soglie da configurazione; la tabella provvisoria di ADR-0009 resta disponibile secondo D2-10; bordi di F-05 verdi.
- Spec: §6.3. ADR: 0009, 0021.

#### K-13 — Override
- Agente: `backend`. Stato: **chiuso il 2026-11-17**. `scoring/overrides.py`: i sei override di ADR-0021 con livelli e soglie dalla configurazione, che alzano un minimo e mai il punteggio; nessuno scatta su un dato assente (raggiungibilità `ignota`, nessuno snapshot, nessun churn, esposizione solo di default); nessun override per il segreto valido (nessun campo di configurazione, provato). Il livello non scende mai.
- Percorsi: `packages/ca-core/src/ca_core/scoring/levels.py`.
- Dipende da: K-12, K-04, E-01.
- Accettazione: ogni override di §6.3 applicabile secondo ADR-0021, con `level_source: override` e motivo nell'evidenza; l'override sul segreto valido non scatta mai, verificato da test.
- Spec: §6.3. ADR: 0012, 0013, 0021.

#### K-14 — Passo `score`
- Agente: `backend`. Stato: **chiuso il 2026-11-17** nel nucleo. `scoring/score.py`: A e B sempre, in `variant_scores`; livello e `level_source` cambiano solo con `levels.source: score` (D2-10), con `override` se un override ha alzato il livello; idempotente e deterministico, ordine per livello, punteggio decrescente, categoria e fingerprint. **Non fatto:** il collegamento alla CLI e al report (K-15, E-06, L-02, in corso).
- Percorsi: `packages/ca-core/src/ca_core/pipeline/`.
- Dipende da: K-11, K-12, K-13, K-15.
- Accettazione: passo idempotente; livello attivo secondo D2-10 (raccomandazione: provvisorio fino al Gate 2), punteggi in ombra sempre presenti; ordinamento dell'elenco per livello e punteggio, deterministico.
- Spec: §5 passo 8, §6. ADR: 0002, 0009, 0021.

#### K-15 — Passo `enrich`
- Agente: `backend`. Stato: **chiuso il 2026-11-17** come composizione in `ca_cli/scoring.py`: il contesto di scoring si costruisce nella radice di composizione (feed EPSS e KEV dalla cache o dalla rete, raggiungibilità e churn dal grafo del plugin, contesto del servizio), il nucleo non fa I/O. L'evidenza di ogni fattore porta già i dati usati (CVE, stato del feed, entrypoint, fonte di C ed E), quindi non c'è un passo separato che riscriva l'evidenza dei finding. **Non fatto:** dipendenze di sviluppo o di test dichiarate da lockfile o SBOM (E = 0,2).
- Percorsi: `packages/ca-core/src/ca_core/pipeline/`.
- Dipende da: E-02, E-03, G-12, K-05.
- Accettazione: EPSS, KEV, raggiungibilità e fonte di C ed E aggiunti all'evidenza dei finding, senza rete nel nucleo; dati mancanti dichiarati.
- Spec: §5 passo 6. ADR: 0022, 0024, 0028.

#### K-16 — Passo `resolve_changed_files`
- Agente: `backend`. Stato: **chiuso il 2026-11-17** come lettura della baseline (`pipeline/baseline.py`, `load_baseline`); il nome del passo resta quello del piano ma non calcola file cambiati (ADR-0025 §4). Prende il risultato della porta `BaselineSource`, rifiuta senza leggere una baseline dentro la directory analizzata (confronto sul percorso, il chiamante passa percorsi già risolti), legge con il limite di byte, valida con il modello del report, richiede scansione completa e commit uguale a `--base`. Ogni rifiuto ha un codice (`baseline-inside-workspace`, `-unreadable`, `-invalid`, `-commit-mismatch`, `-not-full`) e lascia la scansione andare avanti con `pr-config-from-head`. Una baseline parziale è valida con `baseline-partial`; la configurazione è quella registrata dalla baseline, con `config-changed-in-pr` che nomina solo le sezioni cambiate, o quella della PR (`baseline-without-config`) per un report della Fase 1. **Non ancora collegato alla CLI** (L-01).
- Percorsi: `packages/ca-core/src/ca_core/pipeline/`.
- Dipende da: A-10, C-06, F-06.
- Accettazione (rivista da ADR-0025 il 2026-11-13): lettura e validazione della baseline (percorso fuori dal workspace, schema, commit uguale a `--base`, scansione completa) e configurazione effettiva ricavata dalla baseline; nessun calcolo dei file cambiati e nessun plugin ristretto in Fase 2. Testo originale: file cambiati rispetto al base dalla porta della storia git; plugin limitati ai file cambiati solo dove ADR-0025 lo ammette; rinomine e cancellazioni gestite.
- Spec: §5 passo 2. ADR: 0025.

#### K-17 — Passo `diff_baseline`
- Agente: `backend`. Stato: **chiuso il 2026-11-17**; `pipeline/diff_baseline.py`, `sarif/aggregate.py`, `fingerprint.py`, `normalize.py`; `scan-report` 1.3 (aggiunto `baseline.updated`). Nuovo, esistente e risolto per fingerprint; `updated` se cambiano posizione o livello. Un finding della baseline il cui strumento è fallito o non è girato non è risolto: `not_evaluated`; per i finding della policy (`ca-core`) contano tutti i plugin. **Secondo passaggio per i file rinominati:** la chiave senza percorso (`pk1`: regola, strumento, contesto o valore del segreto) è calcolata dalla normalizzazione per `code` e `secret`; si accoppia solo un `new` con un `resolved` della stessa chiave, su percorsi diversi, e solo se sono gli unici due. I casi ambigui restano nuovo più risolto: meglio un falso nuovo che un nuovo nascosto. Nel SARIF aggregato `baselineState` (`new`, `unchanged`, `updated`) e i risolti come `absent`. **Non ancora collegato alla CLI** (L-01).
- Percorsi: `packages/ca-core/src/ca_core/pipeline/`, `packages/ca-core/src/ca_core/sarif/aggregate.py`.
- Dipende da: K-16, C-04, F-06.
- Accettazione: finding nuovi, esistenti e risolti per fingerprint, `baselineState` nel SARIF aggregato, conteggi nel report; i casi spostati di riga di F-06 risultano esistenti.
- Spec: §5 passo 9. ADR: 0008, 0011, 0025.

#### K-18 — Gate su finding nuovi e configurazione dal branch base
- Agente: `backend`. Stato: **chiuso il 2026-11-17**; `pipeline/gate.py`. Con `gate.effective_mode` `new-findings-only` bloccano solo i finding `new`; `GateResult.mode` e riga `modo:` nell'uscita di `gate`. Il modello rifiuta un `effective_mode` `new-findings-only` senza baseline valida. L'avviso `new-findings-only-as-all` resta per scansione completa o baseline non valida. La configurazione dal base si applica in `scan` (L-01): provato il caso ostile, una PR che mette `mode: all`, `block_on: []` ed esclude `*.py` non cambia gate né esclusioni, e il finding nuovo blocca.
- Percorsi: `packages/ca-core/src/ca_core/pipeline/gate.py`.
- Dipende da: K-17, C-05.
- Accettazione: `new-findings-only` valutato davvero, l'avviso `new-findings-only-as-all` resta solo senza baseline; in modalità PR gate ed eccezioni si leggono dal branch base, e il caso ostile di F-06 non indebolisce il gate.
- Spec: §8. ADR: 0009, 0014, 0025.

#### K-19 — Avviso di gitleaks sul clone superficiale (riporto dalla Fase 1)
- Agente: `backend`. Stato: **chiuso il 2026-11-10**; CI verde su `main` (`e2e` 42909328345: 371 passati, 5 saltati, nessun `xfail`).
- Percorsi: `packages/ca-core/src/ca_core/sarif/`, `packages/ca-core/src/ca_core/pipeline/`.
- Dipende da: nessuno.
- Accettazione: le notifiche in `invocations` del SARIF di un plugin diventano `warnings[]` nel report con un codice stabile, letto in modo difensivo; il test `xfail` di `tests/e2e/test_detection.py` passa e il marcatore è rimosso. `warnings[].code` è già una stringa libera: lo schema non cambia.
- Spec: §7.3. ADR: 0010, 0011, 0012.

#### K-20 — Riga nei finding di licenza su file (riporto dalla Fase 1)
- Agente: `backend`. Stato: **chiuso il 2026-11-10**; CI verde su `main` (`e2e` 42909328345: 371 passati, 5 saltati, nessun `xfail`).
- Percorsi: `packages/ca-core/src/ca_core/policy/licenses.py`, `packages/ca-plugins/src/ca_plugins/builtin/scancode/`, `doc/adr/0013-*.md`.
- Dipende da: nessuno.
- Accettazione: il finding di licenza su file riporta la riga iniziale che scancode trova; il fingerprint `license-file` (percorso più licenza) non cambia, verificato su un vettore di prova; i due `xfail` `LICENSE_LINES` passano e il marcatore è rimosso; emendamento di ADR-0013.
- Spec: §4.1. ADR: 0008, 0013.

#### K-21 — Correlazione tra tool
- Agente: `backend`. Stato: **chiuso il 2026-11-17**; `ca_core/correlation.py`. Tabella `(strumento, regola)` → problema con i problemi di F-02 (11 gruppi tra trivy, checkov e hadolint), versione `1`; gruppo `cg1:<16 esadecimali>` da categoria, file e problema, assegnato solo se almeno due strumenti concordano. `Finding.correlation` (finding 1.1) e `ScanReport.correlation_version` (scan-report 1.1); fingerprint, livello e ogni altro campo invariati (provato). `representatives` dà un finding per gruppo, il più grave, per i campioni di G2.b e i commenti PR. La tabella copre solo i casi di F-02: cresce con i dati di X-02. Nota: C-01 e C-04 contenevano già altri campi da aggiungere a questi due contratti; qui ne è entrato solo uno ciascuno.
- Percorsi: `packages/ca-core/src/ca_core/`.
- Dipende da: A-11, P-03, P-04.
- Accettazione: i problemi di F-02 rilevati da più tool hanno un identificativo di gruppo comune e fingerprint invariati; l'elenco ordinato può raggrupparli.
- Spec: §1, §4.2. ADR: 0008, 0026.

### L — CLI

#### L-01 — `scan --pr --base`
- Agente: `backend`. Stato: **chiuso il 2026-11-17**; `ca_cli/scan.py`, `main.py`. Flag `--pr`, `--base` (commit completo), `--baseline`, `--baseline-source`, `--pull-request`; errori di sintassi con exit 2 prima di qualunque lavoro (`--pr` senza `--base` e viceversa). La baseline si risolve (realpath) prima del confronto con il workspace; nell'immagine CLI vale solo sotto la radice degli artefatti. Il report registra `scan`, `baseline`, stato dei finding e modo effettivo; la tabella riporta i conteggi. Exit code invariati. **Non coperto:** E2E con container reali (T-03) e la scelta della fonte nelle integrazioni (N-03); `--baseline-source` è solo un'etichetta del report, non verificata.
- Percorsi: `packages/ca-cli/src/ca_cli/`.
- Dipende da: K-16, K-17, K-18.
- Accettazione: modalità PR secondo ADR-0025 con la fonte della baseline scelta; senza baseline disponibile, avviso e valutazione `all`; exit code invariati (ADR-0010).
- Spec: §9.1. ADR: 0010, 0025.

#### L-02 — `--variant` e punteggi in uscita
- Agente: `backend`. Stato: **chiuso il 2026-11-17**. `scan --variant A|B`, `--scoring-config FILE` (o `CA_SCORING_CONFIG`) e `--service-context FILE`, i due file solo da fuori dal repository (un percorso dentro la directory analizzata, anche tramite link, è rifiutato). Precedenza della variante: flag, poi `scoring.variant` della configurazione effettiva (in una PR quella del base), poi il file di scoring. `scoring`, `service_context` ed `enrichment` nel report; `variant_scores` nel JSON; `score` e `variant_scores` (G, P, E, C) nelle proprietà del SARIF; massimo del punteggio nella tabella. Le sezioni `scoring` e `service` di `.code-analyzer.yml` non sono più inerti (resta `agents`); il repository non ha chiavi per pesi o soglie. Il livello e il gate restano quelli provvisori finché la configurazione di scoring non dice `levels.source: score` (D2-10). **Non fatto:** il file di scoring in YAML (solo JSON); `--service-context` da `service-context` del server (B-10); le tabelle di `table` non elencano i punteggi per finding.
- Percorsi: `packages/ca-cli/src/ca_cli/`.
- Dipende da: K-14.
- Accettazione: `--variant` con la precedenza di ADR-0021; punteggi e fattori in `json` e `sarif`, livello e punteggio in `table`.
- Spec: §9.1. ADR: 0010, 0021.

#### L-03 — Invio del report al server
- Agente: `backend`. Stato: `LIBERO`.
- Percorsi: `packages/ca-cli/src/ca_cli/`.
- Dipende da: A-01, C-08, B-04.
- Accettazione: comando o opzione secondo ADR-0016, con token OIDC del provider CI e nessun segreto a lunga durata; senza server la CLI funziona come prima; `ca_cli` continua a non importare server né database (`lint-imports`).
- Spec: §9.2, §12.1. ADR: 0001, 0016, 0019.

#### L-04 — Commenti PR e check run dalla CI
- Agente: `backend`. Stato: **chiuso il 2026-11-17** dal lavoro di N-02, N-03 e del comando `notify` (`ca_cli/notify.py`): commento aggiornato e check run con l'esito calcolato come `gate`, provati con un server finto, senza rete nei test. Legge solo il report, non il SARIF (il SARIF non serve alla composizione).
- Percorsi: secondo ADR-0027 (`packages/ca-cli/` o `packages/ca-integrations/`).
- Dipende da: N-02, N-03, A-12.
- Accettazione: dal report e dal SARIF, un commento PR aggiornato e una check run con esito del gate; nessuna chiamata di rete nei test (server finto).
- Spec: §12.1. ADR: 0027.

#### L-05 — Documentazione utente della Fase 2
- Agente: `backend`. Stato: **parziale, 2026-11-17**: scritto ciò che esiste. `doc/utente/README.md` aggiornato (comandi `notify` ed `export`, opzioni di PR, tabella dei plugin, `gate.mode`), più `pull-request.md`, `ci-github.md`, `ci-gitlab.md` e `livelli-e-punteggi.md`. `livelli-e-punteggi.md` riscritto il 2026-11-17 dopo K-03, K-04, K-05, K-13, K-14 e L-02 (punteggi in ombra, flag, feed, contesto del servizio, limiti). **Non scritto, perché non esiste:** l'invio al server (L-03) e la Variante B (ADR-0023). Non verificato: le istruzioni di `ci-github.md` e `ci-gitlab.md` non sono state seguite da una persona su un'installazione pulita.
- Percorsi: `doc/utente/`.
- Dipende da: L-01, L-02, L-03, L-04, N-04.
- Accettazione: modalità PR, varianti e punteggi, cambio dei livelli rispetto alla Fase 1 e quando avviene (D2-10), nuovi plugin, Action e componente GitLab, invio al server; limiti dichiarati: override del segreto valido non applicato, C ed E dichiarati dal repository se non c'è il server.
- Spec: §17. ADR: 0009, 0021, 0025, 0027.

### B — Server e API

Tutti `IPOTESI` (D2-01): con l'alternativa si aggiungono i task della sezione 3, questi restano.

#### B-01 — Pacchetto `ca-api`
- Agente: `backend`. Stato: **chiuso il 2026-11-17** per lo scheletro: FastAPI con `/v1/health`, configurazione da ambiente con i limiti di ADR-0016, `python -m ca_api.openapi_export [--check]` e `schemas/openapi.json`. Contratti: `ca_api` non importa plugin, CLI, grafo né integrazioni e nessuno importa `ca_api`. Restano per i task che li usano le dipendenze di B-02, B-04 e B-13. Il comando di export è in `AGENTS.md`; è in `verify.yml`. Coperto da `--cov` insieme agli altri pacchetti.
- Percorsi: `packages/ca-api/`, `pyproject.toml`.
- Dipende da: A-01, A-02, A-15.
- Accettazione: applicazione FastAPI nel workspace, contratti `import-linter` (`ca_api` verso `ca_core`), configurazione da ambiente, copertura misurata, export dell'OpenAPI disponibile per C-08.
- Spec: §2, §3, §9.2. ADR: 0001, 0016, 0017.

#### B-02 — Persistenza
- Agente: `backend`. Stato: **chiuso il 2026-11-17** per l'accesso ai dati. `ca_api/db/engine.py` (engine pg8000, `tenant_session` con `schema_translate_map` e nome dello schema validato prima di ogni SQL), `migrate.py`, `stores.py` (creazione idempotente del tenant e del suo schema, repository per identità esterna `(provider, issuer, identificativo)` con il solo nome aggiornato a ogni caricamento, tier ed esposizione con chi e quando, scansioni per digest, elenchi con cursore). 23 test su PostgreSQL vero (`tests/integration/test_api_database.py`, `CA_TEST_DOCKER=1`) e 23 senza database. **Limite dichiarato:** non c'è un ruolo di database per tenant in Fase 2: l'isolamento sta nello schema scelto dalla sessione e nel divieto di SQL grezzo con identificativi; un SQL grezzo senza schema non trova le tabelle, ma uno con lo schema qualificato raggiungerebbe un altro tenant. Va in S-01. Dipendenze nuove: SQLAlchemy 2.0.58, Alembic 1.20.1, pg8000 1.31.6 e `testcontainers` per i test, verificate (vedi ADR-0030).
- Percorsi: `packages/ca-api/src/ca_api/db/`.
- Dipende da: B-01, C-07.
- Accettazione: repository dei dati sul modello di C-07 con selezione dello schema del tenant per richiesta; test su PostgreSQL in container (testcontainers).
- Spec: §4.3. ADR: 0018.

#### B-03 — Ingestione di una scansione
- Agente: `backend`. Stato: **chiuso il 2026-11-17**. `POST /v1/scans` realizzato (`ca_api/ingest.py`, `limits.py`, `manage.py`): parti validate come input non fidati con i lettori del nucleo (report, SARIF, SBOM CycloneDX 1.7, grafo), 422 con il solo luogo dell'errore, nessun commit nel report → 422, repository e commit del report contro il token (403 `repository-mismatch`), tenant inesistente 403; idempotenza per `(repository, SHA-256 del report)` con 201, 200 e 409 se gli artefatti cambiano; artefatti nell'archivio con chiave dai valori del server (mai il nome del file ricevuto) e cancellati se il database fallisce; ripetizione in corsa gestita (quattro invii simultanei: una scansione); limite di dimensione contato mentre si legge (anche con `Content-Length` falso) e per parte; `first_seen`, `last_seen`, stato e `risolto` secondo ADR-0018 (PR e branch non principali, report in ritardo e scansioni parziali non spostano nulla; un finding ricomparso si riapre con un evento; lo stato di triage non si sovrascrive); componenti e grafo della scansione corrente sostituiscono i precedenti; eccezioni del repository registrate come dichiarazioni non verificate; punteggi in ombra per occorrenza. `python -m ca_api.manage migrate|create-tenant`. 42 test su PostgreSQL vero con archivio su file system. **Limiti dichiarati:** il report porta il nome della cartella e non l'identificativo del repository, quindi si confronta con l'ultimo segmento del nome del token (una scansione di una sottocartella si rifiuta); il branch principale si riconosce dal nome (`main`, `master`, configurabile) finché il repository non ne ha uno registrato; il limite per parte si controlla dopo la lettura, ma entro il limite della richiesta; non misurata la velocità su un pilota grande (pg8000).
- Percorsi: `packages/ca-api/src/ca_api/`.
- Dipende da: B-02, B-05, B-07, C-08.
- Accettazione: `POST /v1/scans` valida report, SARIF e SBOM contro `schemas/` come input non fidati, con limiti di dimensione; idempotente per repository, commit ed esecuzione; aggiorna `first_seen`, `last_seen` e `finding_occurrences`; il repository del token deve coincidere con quello del report.
- Spec: §4.3, §9.2. ADR: 0016, 0018, 0019.

#### B-04 — Autenticazione
- Agente: `backend`. Stato: **chiuso il 2026-11-17**. Verifica dei token OIDC di utenti e pipeline con emittenti da configurazione (mai dal token), JWKS in cache con un solo aggiornamento e un limite di frequenza, tempo dal `Clock`, durata massima, `aud` esatta, algoritmi asimmetrici in elenco fisso (`none`, HS* e confusione di algoritmo provati), chiavi simmetriche del JWKS ignorate; claim dei provider confermati sulla documentazione (vedi ADR-0019). Tutti i casi obbligatori dell'ADR con un emittente finto in processo, senza rete. **Nuove dipendenze:** `PyJWT[crypto]` 2.15.1 (MIT) con `cryptography` 50.0.2 (Apache 2.0 o BSD), cffi e pycparser.
- Percorsi: `packages/ca-api/src/ca_api/auth/`.
- Dipende da: B-01, A-04, C-08.
- Accettazione: verifica dei token OIDC di utenti e pipeline (emittente, audience, scadenza, claim del repository), JWKS in cache; test con IdP finto, senza rete esterna.
- Spec: §9.2. ADR: 0019.

#### B-05 — Autorizzazione e tenant
- Agente: `backend`. Stato: **chiuso il 2026-11-17** per la matrice dei ruoli: ogni route e ogni ruolo provati (lettore, triage, approvatore, amministratore, senza ruolo, pipeline), `required_role` nel 403, nessun token ripetuto nelle risposte. **Non fatto:** il 404 tra tenant e il limite della pipeline al proprio repository, che richiedono l'accesso ai dati dalle route (B-06, B-03).
- Percorsi: `packages/ca-api/src/ca_api/auth/`.
- Dipende da: B-04, B-02.
- Accettazione: matrice ruoli ed endpoint di ADR-0019 verificata da test; nessun accesso tra tenant.
- Spec: §9.2. ADR: 0018, 0019.

#### B-06 — Stato e SARIF di una scansione
- Agente: `backend`. Stato: `LIBERO`.
- Percorsi: `packages/ca-api/src/ca_api/`.
- Dipende da: B-03.
- Accettazione: `GET /v1/scans/{id}` e `GET /v1/scans/{id}/sarif` conformi a C-08.
- Spec: §9.2. ADR: 0017.

#### B-07 — Archivio degli artefatti
- Agente: `backend`. Stato: **chiuso il 2026-11-17**. `ca_api/storage/filesystem.py` e `s3.py` della porta `ArtifactStore` con una batteria di contratto comune (anche il fake in memoria): contenimento dei percorsi con `O_NOFOLLOW`, permessi privati, nessuna sovrascrittura nemmeno in corsa (`link` atomico; `If-None-Match` su S3, provato con scrittori concorrenti), tetto di byte con lettura limitata, digest verificato mentre si scrive. Client `boto3` 1.44.4 (Apache 2.0) e server di prova SeaweedFS (Apache 2.0), verificati e riportati in ADR-0030; MinIO resta escluso. **Non fatto:** la costruzione dell'archivio dalla configurazione (B-03); non provato su un servizio S3 reale.
- Percorsi: `packages/ca-api/src/ca_api/storage/`.
- Dipende da: A-15, C-06.
- Accettazione: adattatori su file system e S3 della porta di C-06, con contenimento dei percorsi; test dell'adattatore S3 su un server compatibile in container.
- Spec: §2. ADR: 0030.

#### B-08 — Elenco dei finding
- Agente: `backend`. Stato: `LIBERO`.
- Percorsi: `packages/ca-api/src/ca_api/`.
- Dipende da: B-02, B-05, C-08.
- Accettazione: `GET /v1/repositories/{id}/findings` con filtri per livello, categoria, stato e nuovi, ordinamento per livello attivo e punteggio, punteggi in ombra nella risposta, paginazione a cursore; prestazioni misurate su un volume pari a saleor.
- Spec: §9.2. ADR: 0017, 0021, 0029.

#### B-09 — Dettaglio e aggiornamento di un finding
- Agente: `backend`. Stato: `LIBERO` (D2-02 decisa il 2026-11-16).
- Percorsi: `packages/ca-api/src/ca_api/`.
- Dipende da: B-08, A-03.
- Accettazione: `GET /v1/findings/{id}` e `PATCH /v1/findings/{id}` per stato, owner ed eccezione con motivazione e scadenza, con `approved_by` dall'identità autenticata, registro delle modifiche e precedenza di ADR-0018 sulle eccezioni del repository.
- Spec: §9.2. ADR: 0018, 0019.

#### B-10 — Repository e scansioni
- Agente: `backend`. Stato: `LIBERO` (D2-04 decisa il 2026-11-16).
- Percorsi: `packages/ca-api/src/ca_api/`.
- Dipende da: B-02, B-05, A-13.
- Accettazione: elenco dei repository e delle loro scansioni (lacuna 2); registrazione di tier ed esposizione riservata all'`amministratore` secondo D2-04.
- Spec: §4.3, §9.2. ADR: 0028, 0029.

#### B-11 — SBOM e grafo
- Agente: `backend`. Stato: `LIBERO`.
- Percorsi: `packages/ca-api/src/ca_api/`.
- Dipende da: B-03, C-02.
- Accettazione: `GET /v1/repositories/{id}/sbom` (CycloneDX) e `GET /v1/repositories/{id}/graph` conformi a C-08. Nessuna vista del grafo in UI.
- Spec: §9.2. ADR: 0017, 0020.

#### B-12 — Baseline dal server
- Agente: `backend`. Stato: `LIBERO`.
- Percorsi: `packages/ca-api/src/ca_api/`.
- Dipende da: B-03, A-10.
- Accettazione: se ADR-0025 usa il server come fonte, endpoint per la baseline del branch base, consumato dalla porta di C-06; altrimenti il task si chiude come non necessario.
- Spec: §5 passo 9. ADR: 0025.

#### B-13 — Telemetria minima del server
- Agente: `backend`. Stato: `LIBERO`.
- Percorsi: `packages/ca-api/`.
- Dipende da: B-01.
- Accettazione: durata delle richieste e delle ingestioni, errori, esportazione OTLP opzionale e disattivata per default; nessun segreto né contenuto dei finding nei log.
- Spec: §15, §17. ADR: 0016.

### W — Frontend

#### W-01 — Nascita di `web/`
- Agente: `frontend`. Stato: **chiuso il 2026-11-16**; `web/` con React 19.3.1, TypeScript 6.0.3 in modalità strict, Vite 8.3.8 e vitest 5.1.0. Il lockfile pnpm è stato migrato a Bun 1.4.4; lint e test verificati con Bun. Le proprietà CSS si generano da `doc/ux/tokens.json` e il lint ne controlla la deriva. La verifica licenze W-01 precede la migrazione: rieseguire l'auto-analisi su `web/bun.lock` prima di X-07.
- Percorsi: `web/`.
- Dipende da: U-02, V-01, V-02.
- Accettazione: SPA React, TypeScript in modalità strict e Vite gestita con Bun e lockfile; `bun run --cwd web lint` e `bun run --cwd web test` verdi; dipendenze con licenza verificata.
- Spec: §2, §3, §16. ADR: 0017.

#### W-02 — Client generato dall'OpenAPI
- Agente: `frontend`. Stato: `LIBERO`.
- Percorsi: `web/`.
- Dipende da: W-01, C-08.
- Accettazione: tipi generati da `schemas/openapi.json`, mai scritti a mano; controllo che fallisce se i tipi non corrispondono al file; risposte simulate nei test ricavate dagli esempi dell'OpenAPI.
- Spec: §9.2. ADR: 0017.

#### W-03 — Accesso nella SPA
- Agente: `frontend`. Stato: `LIBERO` (D2-02 decisa il 2026-11-16).
- Percorsi: `web/`.
- Dipende da: W-02, B-04.
- Accettazione: flusso OIDC per la SPA secondo ADR-0019, token non in `localStorage` se l'ADR lo vieta, gestione della scadenza e dell'errore.
- Spec: §9.2. ADR: 0019.

#### W-04 — Elenco dei finding
- Agente: `frontend`. Stato: `IPOTESI` (D2-15).
- Percorsi: `web/`.
- Dipende da: W-02, U-01, U-02, U-03.
- Accettazione: lista unica ordinata per impatto come vista centrale; filtri per livello, categoria, stato e nuovi; nuovi ed esistenti distinti; stati di caricamento, vuoto, errore e scansione parziale; navigazione da tastiera; tutto il contenuto dei finding reso come testo.
- Spec: §1, §9.2. ADR: 0029.

#### W-05 — Dettaglio di un finding
- Agente: `frontend`. Stato: `IPOTESI` (D2-15).
- Percorsi: `web/`.
- Dipende da: W-04, U-04.
- Accettazione: fattori G·P·E·C, pesi, soglie ed evidenze accanto al punteggio (§6.2), livello attivo e punteggi in ombra secondo U-04, posizione, passi di correzione come testo.
- Spec: §6.2. ADR: 0021, 0029.

#### W-06 — Triage ed eccezioni
- Agente: `frontend`. Stato: `IPOTESI` (D2-15; D2-02 decisa il 2026-11-16).
- Percorsi: `web/`.
- Dipende da: W-05.
- Accettazione: cambio di stato, owner, eccezione con motivazione e scadenza obbligatorie; azioni nascoste o disattivate secondo il ruolo; errori del server mostrati.
- Spec: §9.2. ADR: 0019, 0029.

#### W-07 — Repository e stato della scansione
- Agente: `frontend`. Stato: `IPOTESI` (D2-15).
- Percorsi: `web/`.
- Dipende da: W-02, U-01.
- Accettazione: selettore del repository, ultima scansione con stato, plugin falliti e avvisi; nessun aggregato né trend.
- Spec: §9.2. ADR: 0029.

#### W-08 — Test dei componenti e di accessibilità
- Agente: `test`. Stato: `IPOTESI` (D2-15).
- Percorsi: `web/`.
- Dipende da: W-04, W-05, W-06, W-07.
- Accettazione: test dei componenti per ogni stato di U-01, controlli automatici di accessibilità sui criteri di U-03, contenuto HTML ostile in un finding reso come testo.
- Spec: §14. ADR: 0029.

### N — Integrazioni

#### N-01 — Pacchetto `ca-integrations`
- Agente: `backend`. Stato: **chiuso il 2026-11-17**; pacchetto nel workspace, contratti `import-linter` come sopra. Il contratto a strati ammette `ca_cli` sopra di lui: l'emendamento di ADR-0001 resta ad A-16.
- Percorsi: `packages/ca-integrations/`, `pyproject.toml`.
- Dipende da: A-12.
- Accettazione: pacchetto nel workspace con i contratti `import-linter` di ADR-0027, copertura misurata.
- Spec: §3. ADR: 0001, 0027.

#### N-02 — Commento PR e check run su GitHub
- Agente: `backend`. Stato: **chiuso il 2026-11-17** per il client (il comando `notify` è fatto il 2026-11-17: vedi N-03); `ca_integrations/github/` (trasporto e client). Un solo commento per PR ritrovato dal marcatore iniziale e dall'autore atteso, check run già conclusa con annotazioni, errori come codici stabili (`forbidden`, `rate-limited`, `redirect`…) che non portano mai corpo né token. Trasporto sulla sola libreria standard: nessun redirect (`urllib` inoltrerebbe il token), solo HTTPS tranne loopback su richiesta, tetto di 5 MiB e timeout. Provato con un trasporto finto e con un server in loopback. **Non fatto:** la lettura dei limiti di GitHub alla fonte (restano a memoria, N-03) e la verifica alla fonte dei permessi.
- Percorsi: `packages/ca-integrations/src/ca_integrations/github/`.
- Dipende da: N-01, C-09.
- Accettazione: creazione o aggiornamento di un unico commento e di una check run con il token e i permessi di ADR-0027; test su server finto, nessuna rete.
- Spec: §12.1. ADR: 0027.

#### N-03 — Formato del commento e delle annotazioni
- Agente: `backend`. Stato: **chiuso il 2026-11-17** per il formato; `ca_integrations/github/format.py`. Commento: solo i finding `new` con i conteggi (senza baseline valida lo dice ed elenca quelli che bloccano), ordine dell'elenco, un gruppo di correlazione una volta con tutti gli strumenti, tetto configurabile e numero dei rimanenti, corpo sotto il limite senza tagliare un finding. Testo del report neutralizzato: caratteri di controllo e bidirezionali tolti, ogni punteggiatura ASCII con backslash, menzioni, `#n`, indirizzi, `www.` e hash esadecimali interrotti da un carattere invisibile, nessun collegamento costruito dai testi; provato con contenuto ostile, marcatore contraffatto e un titolo che finge un'intestazione. Check run: conclusione dalla stessa funzione di `gate`; annotazioni solo per finding con posizione (livello critico e alto errore, medio avviso, basso nota), testo pulito ma non in Markdown perché non è reso come tale. **Non fatto:** la lettura dei limiti e dei permessi di GitHub alla fonte: restano a memoria in `limits.py` e non verificati (nessun accesso alla rete).
- Percorsi: `packages/ca-integrations/`.
- Dipende da: C-09.
- Accettazione: solo finding nuovi, ordinati per impatto, con limite di lunghezza; contenuto dei finding neutralizzato per Markdown e menzioni; test con contenuto ostile.
- Spec: §12.1. ADR: 0027.

#### N-04 — GitHub Action
- Agente: `devops`. Stato: **chiuso il 2026-11-17** per `action.yml` e script (`integrations/github-action/`); l'uso da repository esterni dipende da I-04 e quindi dalla decisione del 2026-11-10 e da D2-16. Ordine: evento, baseline (artefatto del push sul branch principale, poi scansione del base, poi avviso), `scan` senza `--fail-on`, conservazione del report, SARIF con `always()` via `gh api`, `notify`, `gate` per ultimo; immagine e chiave pubblica come input senza valore predefinito; `pull_request_target` rifiutato; permessi minimi nel README. **Non fatto:** ingressi `variant` e `server-url` (la CLI non ha varianti né `upload`); prova con l'immagine reale su un runner (N-05); il test è su `docker` e `gh` finti.
- Percorsi: `integrations/github-action/`.
- Dipende da: I-01, L-01, L-04.
- Accettazione: `action.yml` con `scan`, upload SARIF con `if: always()` e `gate` separati (ADR-0010), commento e check run; input `server-url` e `variant` effettivi; registry delle immagini come input, senza un registry pubblico predefinito nel codice; permessi minimi documentati; nessun `--fail-on` passato a `scan`.
- Spec: §12.1. ADR: 0010, 0027.

#### N-05 — E2E dell'Action
- Agente: `devops`. Stato: **parte locale chiusa il 2026-11-17**; il workflow non è stato eseguito. Fatto: l'immagine CLI è stata ricostruita con `ca-integrations` (corretto `build-cli-image.sh`, che non ne copiava il wheel) e provata; `tests/e2e/test_packaging.py::test_action_scripts_run_against_the_real_image` esegue gli script dell'Action con l'immagine vera, una PR simulata (commit di merge), la scansione del base come baseline, `scan --pr`, `notify` su un GitHub finto su loopback (commento aggiornato e non duplicato, due check run sul commit di testa, token mai in uscita) e `gate` (exit 1). Aggiunti l'ingresso `offline` e `CA_NOTIFY_ALLOW_LOOPBACK_HTTP` (solo prove). Corrette nel modulo le attese vecchie (7 plugin; ora 13 impacchettati, `eslint` non parte sulla fixture Python). `.github/workflows/e2e-action.yml` scritto: registry e firma nel job, l'Action sul progetto stesso, verifica su GitHub di commento e check run. **Non fatto:** esecuzione del workflow su GitHub (mai girato: va visto al primo push), verifica del SARIF (richiede Code Scanning attivo, qui solo avviso), `actionlint` non disponibile. Deviazione dal piano: il repository analizzato è il progetto stesso, non una fixture, perché commento e check run richiedono una PR vera.
- Percorsi: `.github/workflows/`, `tests/fixtures/repos/`.
- Dipende da: N-04, O-02.
- Accettazione: l'Action gira nella CI del progetto su un repository di prova; nel job si avvia `deploy/compose/registry.yaml`, si costruiscono e firmano le immagini con la chiave di prova e l'Action le scarica da lì; SARIF caricato, gate valutato, commento e check run verificati. Nessuna immagine esce dal job.
- Spec: §14. ADR: 0005, 0027.

#### N-06 — Report nativi di GitLab
- Agente: `backend`. Stato: **chiuso il 2026-11-17**. `ca_integrations/gitlab/export.py` e comando `code-analyzer export --format gitlab [--sbom]`: `sast` (finding `sast`), `dependency_scanning` (`dependency`, con percorso e versione dal purl), `codequality` (`quality`, con percorso e riga) e CycloneDX. Ogni file è validato contro lo schema fissato prima di scrivere (nessun file se uno è invalido); i finding senza il dato richiesto o senza formato (segreti, licenze, IaC, architettura, test, salute) si contano e si dichiarano su stderr, mai inventati. **CycloneDX:** GitLab accetta 1.4, 1.5 e 1.6 (documentazione letta il 2026-11-17), il prodotto è 1.7: lo schema 1.6 è fissato in `vendor_schemas` (stesso commit di 1.7, manifest e ancora dell'hash aggiornati), il documento è riportato alla 1.6 e validato; se usa qualcosa di esclusivo della 1.7 non si scrive. La 1.6 vale solo in uscita (`EXPORT_CYCLONEDX_VERSIONS`), non come ingresso né per i plugin. Provato con dati veri nell'E2E dell'immagine: l'SBOM di syft riportato alla 1.6 e validato, `sast` col finding della PR simulata, `dependency_scanning` non vuoto. **Non fatto:** prova dei report su un'istanza GitLab (D2-12); il report `cyclonedx` è del livello Ultimate; versione e identificativi dello scanner sono provvisori (`ca-cli` come versione).
- Percorsi: `packages/ca-integrations/src/ca_integrations/gitlab/`.
- Dipende da: N-01, C-09.
- Accettazione: report `sast`, `dependency_scanning`, `codequality` e `cyclonedx` dal report e dal SARIF, validati sugli schemi fissati di C-09.
- Spec: §12.2. ADR: 0027.

#### N-07 — Componente GitLab
- Agente: `devops`. Stato: **scritto il 2026-11-17, mai eseguito su GitLab** (D2-12 resta aperta). `integrations/gitlab-component/templates/code-analyzer.yml`: controllo del daemon, scansione del base come baseline in una merge request, `scan --pr`, SBOM, `export`, `gate` per ultimo; registry delle immagini come input senza valore predefinito; artefatti nativi anche dopo un gate fallito. Provato come struttura e con lo script eseguito con `docker` finto (14 test). **Non fatto:** esecuzione su un'istanza, linter CI di GitLab, baseline da artefatto del branch principale, merge request da fork. **Vincolo scoperto:** la CLI non accetta un `DOCKER_HOST` remoto e vuole la stessa directory per job e daemon, quindi il solo Docker-in-Docker di ADR-0027 non basta: serve un runner con socket e `/builds` alla pari (scritto nel README del componente).
- Percorsi: `integrations/gitlab-component/templates/code-analyzer.yml`.
- Dipende da: N-06, I-01, L-01.
- Accettazione: componente con il daemon di ADR-0027, registry delle immagini come input, artefatti nativi di N-06, job che fallisce secondo `gate.block_on`.
- Spec: §12.2. ADR: 0004, 0027.

#### N-08 — E2E del componente GitLab
- Agente: `devops`. Stato: `BLOCCATO` (D2-12).
- Percorsi: progetto GitLab di D2-12.
- Dipende da: N-07.
- Accettazione: pipeline su un repository di prova con un registry locale come servizio del job, immagini costruite e firmate nella stessa pipeline con la chiave di prova; report visibili nella merge request e gate valutato. Nessuna immagine esce dalla pipeline.
- Spec: §14. ADR: 0027.

#### N-09 — Pubblicazione di Action e componente
- Agente: `devops`. Stato: `BLOCCATO` (decisione del 2026-11-10 sulla pubblicazione, D2-16, D2-13, I-04; I-07 per i plugin nuovi).
- Percorsi: `integrations/`, `.github/`.
- Dipende da: N-05, N-08, I-04.
- Accettazione: Action e componente con versione e immagini sulla destinazione di D2-16, utilizzabili da un repository esterno autorizzato. Solo dopo approvazione esplicita.
- Spec: §12. ADR: 0005, 0027.

### I — Immagini e rilascio

Decisione dell'utente del 2026-11-10: nessuna pubblicazione, né su GHCR né altrove, salvo destinazione privata e gratuita (D2-16), e comunque solo con approvazione esplicita. Tutti i task di questa sezione tranne I-04, I-07 e la parte di registry di I-06 lavorano sul registry locale.

#### I-01 — Immagine CLI (riporto di F1:I-03)
- Agente: `devops`. Stato: **chiuso il 2026-11-13**; CI verde su `main` (`e2e` 43433206651). Scostamenti dal progetto in ADR-0004, "Realizzazione (I-01)". `CA_HOST_OUTPUT` non esiste: `/ca/output` la scrive solo la CLI (N-38). Il client Docker nell'immagine va aggiunto a D2-14.
- Percorsi: `deploy/docker/cli/`.
- Dipende da: nessuno.
- Accettazione: come F1:I-03: orchestra i plugin come container fratelli con `CA_HOST_WORKSPACE` e `CA_HOST_OUTPUT`, contiene `cosign` a versione fissata, nessun plugin al suo interno, il socket non raggiunge i plugin, privilegio del socket documentato; licenze e SBOM come F1:I-05; E2E con il registry locale.
- Spec: §2, §3. ADR: 0004, 0005.

#### I-02 — Nuove immagini nel pacchetto
- Agente: `devops`. Stato: `LIBERO`.
- Percorsi: `deploy/docker/`, `packages/ca-plugins/`.
- Dipende da: P-01, P-02, P-03, P-04, P-05, G-09.
- Accettazione: `package-cli.sh` e `image-gate.sh` includono le nuove immagini, digest nei manifest impacchettati, licenze e SBOM obbligatori; `max_bytes` e risorse misurati sui pilota come F1:X-02.
- Spec: §7.2. ADR: 0004, 0005.

#### I-03 — Immagine del server
- Agente: `devops`. Stato: `LIBERO` (D2-07 decisa il 2026-11-16).
- Percorsi: `deploy/docker/server/`.
- Dipende da: B-01, W-01.
- Accettazione: immagine dell'API con la SPA compilata, utente non root, nessun segreto, licenze e SBOM.
- Spec: §2, §15. ADR: 0016, 0030.

#### I-04 — Primo rilascio ufficiale (riporto di F1:I-06)
- Agente: `devops`. Stato: `BLOCCATO` dalla decisione dell'utente del 2026-11-10 (nessuna pubblicazione salvo destinazione privata e gratuita) e da D2-16. D-0015 è approvata (2026-11-10) e non blocca più.
- Percorsi: `deploy/docker/`, `.github/`.
- Dipende da: I-01 (gli E2E della Fase 1, F1:O-02, sono già verdi).
- Accettazione: le 7 immagini dei plugin della Fase 1 e l'immagine CLI rese disponibili sulla destinazione privata e gratuita di D2-16 con la chiave definitiva (D-0005, D2-13), dopo approvazione esplicita dell'utente. Con l'opzione raccomandata di D2-16 il task resta bloccato per tutta la Fase 2. Per il rilascio si conservano insieme, in una cartella persistente, immagini, digest e SBOM (`package-cli.sh` scrive gli SBOM in `<cartella-di-uscita>/sbom/`), come chiede l'approvazione di D-0015. L'immagine CLI rientra in D2-14 come componente nuovo: se Riccardo Roveda non la valuta prima, il rilascio contiene solo le immagini dei plugin. Sblocca N-09. Non serve per il Gate 2.
- Spec: §7.2, §15. ADR: 0005, 0015.

#### I-07 — Rilascio dei plugin nuovi
- Agente: `devops`. Stato: `BLOCCATO` (decisione del 2026-11-10 sulla pubblicazione, D2-16, D2-14).
- Percorsi: `deploy/docker/`, `.github/`.
- Dipende da: I-02, O-02, I-04.
- Accettazione: immagini di ruff, eslint, checkov, hadolint, coverage e `ca-graph` rese disponibili con la stessa procedura e la stessa destinazione di I-04, con immagini, digest e SBOM conservati insieme e la valutazione D2-14 registrata. Per hadolint, in più, testo della licenza e offerta della sorgente del binario esatto nell'immagine (decisione D2-14 del 2026-11-17: finora solo uso interno).
- Spec: §7.3, §15. ADR: 0005, 0015.

#### I-05 — Ambiente di sviluppo del server
- Agente: `devops`. Stato: `LIBERO` (D2-02 e D2-07 decise il 2026-11-16); **parziale il 2026-11-17**: `deploy/compose/server-dev.yaml` con PostgreSQL 16 per digest, volume degli artefatti e API (immagine di sviluppo da `deploy/docker/server/build-dev-image.sh`), tutto su loopback, password dall'ambiente, API con file system in sola lettura e senza capability; provato avviando lo stack. **Mancano l'IdP finto (arriva con B-04) e la SPA (la serve l'immagine di rilascio, I-03)**; l'API non usa ancora il database (B-02).
- Percorsi: `deploy/compose/`.
- Dipende da: A-15, A-04.
- Accettazione: compose con PostgreSQL 16, archivio di ADR-0030, IdP finto, API e SPA; nessun segreto nel repository.
- Spec: §3. ADR: 0019, 0030.

#### I-06 — Ambiente del pilota per il Gate 2
- Agente: `devops`. Stato: `BLOCCATO` (D2-06; D2-16 solo per un eventuale registry sull'host).
- Percorsi: `deploy/`.
- Dipende da: I-03, I-05, B-08, W-05.
- Accettazione: server raggiungibile dai team di D2-03, accesso con l'IdP di D2-02, backup del DB. Le scansioni dei repository dei team girano sulla macchina di riferimento con il registry locale e inviano i report al server; un registry privato sull'host serve solo con l'opzione (2) di D2-16, che ne è il blocco ulteriore.
- Spec: §13. ADR: 0016.

### O — CI del progetto

#### O-01 — Verifica: `web/` e OpenAPI
- Agente: `devops`. Stato: `LIBERO`.
- Percorsi: `.github/workflows/verify.yml`, `AGENTS.md`.
- Dipende da: C-08, W-01.
- Accettazione: `bun run --cwd web lint` e `bun run --cwd web test` in `AGENTS.md` e in `verify.yml`; export dell'OpenAPI con `--check` e controllo dei tipi generati; nuovi pacchetti in `lint-imports` e `ty`.
- Spec: §16. ADR: 0003, 0017.

#### O-02 — E2E estesi
- Agente: `devops`. Stato: `LIBERO`.
- Percorsi: `.github/workflows/e2e.yml`.
- Dipende da: I-02, T-03, T-04.
- Accettazione: nuovi plugin, `ca-graph`, modalità PR e immagine CLI negli E2E con registry locale e chiave di prova; nessun segreto nei log.
- Spec: §14. ADR: 0005.

#### O-03 — Snapshot dei feed esteso
- Agente: `devops`. Stato: `LIBERO`.
- Percorsi: `.github/workflows/feeds-snapshot.yml`.
- Dipende da: E-02, E-03, F-04.
- Accettazione: EPSS e KEV nello snapshot di CI con la stessa procedura di F1:O-03; i job di test non hanno rete verso i feed.
- Spec: §16 regola 7. ADR: 0006, 0024.

#### O-04 — Integrazione del server
- Agente: `devops`. Stato: `LIBERO`.
- Percorsi: `.github/workflows/`.
- Dipende da: T-05.
- Accettazione: job con PostgreSQL e archivio in container per i test di integrazione di `ca-api`; nessun servizio esterno.
- Spec: §14. ADR: 0016.

### S — Sicurezza

`security` lavora in sola lettura: restituisce i finding e `architect` li registra in `doc/verifiche/sicurezza-fase-2.md`.

#### S-01 — Modello delle minacce del server
- Agente: `security`. Stato: **chiuso il 2026-11-17** come revisione di progetto fatta dallo stesso agente che ha scritto gli ADR (non indipendente: la ripete S-06 sul codice). 2 alti, 6 medi, 3 bassi in `doc/verifiche/sicurezza-fase-2.md`. Alti: lo stato «scansione corrente» deve venire dal token e non dal report (B-03, ADR-0019); limiti per tenant a ingestione e archivio (B-03). Parere su D2-02: regge a quattro condizioni.
- Percorsi: lettura di `doc/adr/`; esito in `doc/verifiche/sicurezza-fase-2.md`.
- Dipende da: A-01, A-03, A-04.
- Accettazione: finding per gravità su autenticazione delle pipeline, isolamento dei tenant, ingestione di report ostili, limiti di dimensione, CORS e CSRF per la SPA, C ed E dichiarati dal repository; parere su D2-02.
- Spec: §9.2, §15. ADR: 0016, 0018, 0019.

#### S-02 — `ca-graph` su input ostile
- Agente: `security`. Stato: **chiuso il 2026-11-17** (stessa avvertenza di S-01). Nessun alto, 4 medi, 3 bassi. La divisione di ADR-0020 regge. Corretto subito: i percorsi del grafo non ammettono caratteri di controllo (C-02).
- Percorsi: lettura; esito in `doc/verifiche/sicurezza-fase-2.md`.
- Dipende da: A-05.
- Accettazione: parere su dove gira tree-sitter, sulla lettura della storia git per il churn e sui limiti del grafo emesso.
- Spec: §7.2. ADR: 0004, 0012, 0020.

#### S-03 — Linter, IaC e coverage su input ostile
- Agente: `security`. Stato: **chiuso il 2026-11-17** (stessa avvertenza di S-01). 1 alto, 4 medi, 3 bassi. Alto: il rifiuto delle entità XML non va fatto cercando testo ma con il parser sui byte (P-05, F-03 da estendere con codifiche diverse). La configurazione del repository non si legge mai: confermato.
- Percorsi: lettura; esito in `doc/verifiche/sicurezza-fase-2.md`.
- Dipende da: A-11.
- Accettazione: parere sulla configurazione dei linter (codice eseguibile del repository), sui parser XML dei report di copertura, sui percorsi indicati dal repository.
- Spec: §7.2, §8. ADR: 0014, 0026.

#### S-04 — Integrazioni CI
- Agente: `security`. Stato: **chiuso il 2026-11-17** (stessa avvertenza di S-01). 1 alto (token OIDC mintabile da una PR dello stesso repository, si chiude sul server), 5 medi, 3 bassi. Da fare in N-02..N-04: neutralizzare `::` a inizio riga in ciò che la CLI stampa.
- Percorsi: lettura; esito in `doc/verifiche/sicurezza-fase-2.md`.
- Dipende da: A-12.
- Accettazione: PR da fork, permessi dei token, injection nei commenti, claim OIDC verso il server, uso del socket nell'immagine CLI in CI.
- Spec: §12. ADR: 0004, 0027.

#### S-05 — Feed e mirror
- Agente: `security`. Stato: **chiuso il 2026-11-16**; esito in `doc/verifiche/sicurezza-fase-2.md`: nessun critico, 1 alto, 7 medi, 5 bassi. L'alto (S5-A1: dopo il Gate 2 un feed alterato può abbassare i livelli di tutte le dipendenze) si risolve in ADR-0021 (A-06) con il limite dal CVSS scelto dall'utente il 2026-11-16; non ferma E-01..E-04. Richieste per E-02, E-03, E-05, E-06 e due emendamenti di ADR-0024 (A-16). Il rischio residuo lo decide l'utente.
- Percorsi: lettura; esito in `doc/verifiche/sicurezza-fase-2.md`.
- Dipende da: A-09.
- Accettazione: snapshot avvelenato (rischio lasciato aperto da ADR-0006), firma, origine, effetto di un EPSS manipolato sul punteggio.
- Spec: §15. ADR: 0006, 0024.

#### S-06 — Revisione dell'implementazione
- Agente: `security`. Stato: `LIBERO`.
- Percorsi: lettura di `packages/`, `web/`; esito in `doc/verifiche/sicurezza-fase-2.md`.
- Dipende da: B-09, W-06, N-02, G-09, P-01, P-02, P-03, P-04, P-05, E-04.
- Accettazione: i finding di S-01..S-05 verificati nel codice; rischio residuo da sottoporre all'utente.
- Spec: §15. ADR: 0016..0030.

### T — Test

#### T-01 — Regressione e proprietà dello scoring
- Agente: `test`. Stato: `LIBERO`.
- Percorsi: `tests/unit/core/`.
- Dipende da: F-05, C-03.
- Accettazione: test parametrizzati sulla tabella di F-05 e test di proprietà: punteggio in [0,100], monotonia rispetto a ciascun fattore, intervalli semiaperti, determinismo. Scritti prima di K-02..K-13 e falliti finché non sono implementati.
- Spec: §14. ADR: 0021, 0023.

#### T-02 — Harness di contratto per i nuovi plugin
- Agente: `test`. Stato: **chiuso il 2026-11-16 salvo il grafo**; `tests/contract/plugins/test_recorded_samples_fase2.py` sui campioni di V-03: ruff, eslint, checkov, hadolint e i report di copertura. Il grafo non ha ancora uno schema (C-02): la sua prova passa a C-10. Emerso dai campioni e riportato in ADR-0026: il JSON di eslint contiene il testo intero dei file analizzati, il SARIF di ruff porta `fixes`, il testo di aiuto di checkov contiene il nome della risorsa.
- Percorsi: `tests/contract/`, `tests/fixtures/plugin-output/`.
- Dipende da: V-03.
- Accettazione: l'harness di F1:T-04 copre ruff, eslint, checkov, hadolint, coverage e il grafo di `ca-graph` sui campioni reali di V-03.
- Spec: §14, §16 regola 4. ADR: 0007.

#### T-03 — E2E di rilevamento della Fase 2
- Agente: `test`. Stato: `LIBERO`.
- Percorsi: `tests/e2e/`.
- Dipende da: F-01, F-02, F-03, P-01, P-02, P-03, P-04, P-05, G-10.
- Accettazione: tutti i problemi noti di F-01, F-02 e F-03 rilevati, confronto automatico con gli attesi, nessun `xfail` nuovo senza decisione.
- Spec: §13, §14. ADR: 0020, 0026.

#### T-04 — E2E della modalità PR
- Agente: `test`. Stato: `LIBERO`.
- Percorsi: `tests/e2e/`.
- Dipende da: F-06, L-01.
- Accettazione: sui repository di F-06, conteggi nuovi, esistenti e risolti corretti, gate `new-findings-only` corretto, configurazione ostile del branch senza effetto, durata registrata.
- Spec: §5, §14. ADR: 0025.

#### T-05 — Integrazione del server
- Agente: `test`. Stato: `LIBERO` (D2-02 decisa il 2026-11-16).
- Percorsi: `tests/integration/`.
- Dipende da: B-03, B-05, B-08, B-09, I-05.
- Accettazione: ingestione e lettura su PostgreSQL e archivio in container, matrice di autorizzazione, isolamento dei tenant, report ostili rifiutati.
- Spec: §14. ADR: 0016, 0018, 0019.

#### T-06 — Contratto tra OpenAPI e client
- Agente: `test`. Stato: `LIBERO`.
- Percorsi: `tests/contract/`, `web/`.
- Dipende da: C-08, W-02.
- Accettazione: gli esempi dell'OpenAPI superano gli schemi; le risposte reali di `ca-api` nei test superano l'OpenAPI; i tipi del client compilano sul file corrente.
- Spec: §14. ADR: 0017.

### X — Misura e chiusura

#### X-01 — Registrare team, repository e protocollo del Gate 2
- Agente: `architect`, su scelta dell'utente. Stato: **chiuso il 2026-11-13** con 2 repository; un terzo, facoltativo, si aggiunge prima di X-02.
- Percorsi: `doc/verifiche/gate-2.md`.
- Dipende da: nessuno.
- Accettazione: validatore unico (l'utente), 2 o 3 repository con commit fissato, campione, metrica, soglia e regola di misura di D2-03; scostamento rispetto a §13 e riservatezza dei dati dichiarati.
- Spec: §13. ADR: 0021, 0023.

#### X-02 — Scansione in ombra dei repository del gate
- Agente: `test`. Stato: `LIBERO`.
- Percorsi: `doc/verifiche/gate-2.md`.
- Dipende da: X-01, K-14, L-02, I-02.
- Accettazione: su pilota e repository dei team, G2.a misurata; distribuzione dei livelli provvisori, di A e di B; numero di finding che cambiano livello. Solo conteggi se i repository sono riservati.
- Spec: §13. ADR: 0009, 0021.

#### X-03 — Materiale di valutazione
- Agente: `test`. Stato: `LIBERO`.
- Percorsi: `doc/verifiche/gate-2.md`, materiale riservato fuori dal repository.
- Dipende da: X-02.
- Accettazione: campioni stratificati secondo il protocollo, presentati senza punteggi né variante; seme di estrazione registrato.
- Spec: §13. ADR: nessuno.

#### X-04 — Validazione con i team
- Agente: `test` per la raccolta; la valutazione la fanno i team. Stato: `LIBERO`.
- Percorsi: `doc/verifiche/gate-2.md`.
- Dipende da: X-03.
- Accettazione: ordinamenti dei team raccolti per tutti i campioni; metriche di G2.b calcolate per ciascuna variante e ciascun team.
- Spec: §13. ADR: nessuno.

#### X-05 — Misura della scansione PR
- Agente: `test`. Stato: `LIBERO`.
- Percorsi: `doc/verifiche/gate-2.md`.
- Dipende da: L-01, I-02, T-04.
- Accettazione: PR di riferimento registrata per ciascun pilota; durata totale in modalità `--pr` dal report, con la regola di misura della Fase 1; G2.d misurata.
- Spec: §5, §13. ADR: 0009, 0025.

#### X-06 — Proposta della variante predefinita
- Agente: `architect`. Stato: `LIBERO`.
- Percorsi: `doc/verifiche/gate-2.md`.
- Dipende da: X-04.
- Accettazione: confronto tra A e B sui valori di G2.b e di X-02, con raccomandazione; la scelta resta all'utente (§18).
- Spec: §13, §18. ADR: 0021, 0023.

#### X-07 — Auto-analisi con i livelli della Fase 2
- Agente: `test`. Stato: `LIBERO`.
- Percorsi: `doc/verifiche/gate-2.md`.
- Dipende da: K-14, I-02, X-10.
- Accettazione: Code Analyzer sul proprio monorepo con `--fail-on critico,alto` esce con 0: nessun finding Critico o Alto, con i 6 finding di licenza effettiva coperti dalle eccezioni di X-10.
- Spec: §17. ADR: 0009, 0021.

#### X-10 — Eccezioni per i 6 finding di licenza effettiva
- Agente: `test`. Stato: **chiuso il 2026-11-13**, confermato da Riccardo Roveda. Auto-analisi su clone pulito: `complete`, 41,1 s, 342 finding, `gate --fail-on critico,alto` esce con 0 con 36 eccezioni, tutte in uso. Oltre ai 6 finding previsti: 2 dei 6 fingerprint erano cambiati rispetto a `gate-1.md`, e servivano altre 8 eccezioni approvate lo stesso giorno (2 citazioni già eccepite con fingerprint cambiato, 1 citazione nuova in `doc/plan/fase-2.md`, 5 dichiarazioni della licenza del progetto in `README.md` e nei `pyproject.toml`). Dopo I-01 resta 1 finding nuovo da eccepire: le note di terze parti dell'immagine CLI, che nominano la licenza del progetto.
- Percorsi: `.code-analyzer.yml`.
- Dipende da: nessuno.
- Accettazione: un'eccezione per ciascuno dei 6 fingerprint elencati in `doc/verifiche/gate-1.md` ("Non eccepibili come falsi positivi"), con `approved_by: Riccardo Roveda`, motivazione che rimanda all'approvazione di D-0015 del 2026-11-10 come rischio residuo, non come falso positivo, e scadenza proposta 2027-05-09; `config validate` verde; `gate --fail-on critico,alto` sull'auto-analisi esce con 0 con le sole eccezioni attive. Se un fingerprint cambia (per esempio con K-20, che non deve cambiarli), l'eccezione va rifatta.
- Spec: §8, §17. ADR: 0013, 0014, 0015.

#### X-08 — Esito del Gate 2
- Agente: `architect`. Stato: `LIBERO`.
- Percorsi: `doc/verifiche/gate-2.md`.
- Dipende da: X-05, X-06.
- Accettazione: G2.a..G2.d con evidenza, valore misurato ed esito; scelta della variante registrata in §18 e in un ADR; scostamenti all'utente (§13: valori da confermare dopo il pilota).
- Spec: §13. ADR: 0021, 0023.

#### X-09 — Chiusura della Fase 2
- Agente: `architect`. Stato: `LIBERO`.
- Percorsi: `doc/plan/fase-2.md`, `doc/verifiche/gate-2.md`, `doc/PROJECT.md`.
- Dipende da: X-07, X-08 e tutti i task non bloccati da decisioni respinte.
- Accettazione: voci di §13 e di §17 spuntate con evidenza, copertura ≥ 80% sul codice nuovo, CI verde su `main`; nessun `xfail` dei tre riportati dalla Fase 1; ADR 0016..0030 portati ad `Accettato` o riaperti con motivo; D2-14, D2-16, I-04, I-07, E-05, N-09 riportati come chiusi o rinviati con il loro proprietario.
- Spec: §13, §17. ADR: tutti.

## 9. Percorso critico

Calcolato sul grafo delle dipendenze, in numero di task: non ci sono stime di durata. La catena più lunga verso l'esito del Gate 2 conta 17 task:

`V-01` → `V-07` → `A-05` → `A-07` → `A-06` → `A-08` → `C-03` → `K-01` → un task tra `K-02..K-10` → `K-11` → `K-14` → `L-02` → `X-02` → `X-03` → `X-04` → `X-06` → `X-08`, poi `X-09` per chiudere la fase.

Il percorso attraversa D2-03 (`X-01`, da cui dipende `X-02`), D2-10 (`K-14`, `L-02`) e D2-11 (`A-08`, e `K-06`, `K-07` sul ramo B di `K-11`). D2-03 è la decisione che ferma il Gate 2 più a lungo: `X-01` è nella prima ondata ma resta `BLOCCATO` finché i team non sono scelti.

Catene quasi critiche:

- Modalità PR, 12 task: `V-01` → `V-07` → `A-05` → `A-07` → `A-06` → `C-01` → `C-04` → `K-17` → `K-18` → `L-01` → `T-04` → `X-05`. Attraversa D2-01 tramite A-10 per la fonte della baseline.
- UI, 13 task: `… A-06` → `C-01` → `C-04` → `C-08` → `W-02` → `W-04` → `W-05` → `W-06`, poi `I-06`. Conta solo se il protocollo di D2-03 usa la UI.
- Integrazioni, 14 task fino a `N-09`, che resta `BLOCCATO` da I-04, cioè dalla decisione del 2026-11-10 sulla pubblicazione e da D2-16. Sviluppo e test delle integrazioni (fino a N-05 e N-08) non ne dipendono.

## 10. Primi task avviabili

Senza alcuna decisione dell'utente e senza dipendenze aperte: V-01, V-05, V-06, A-01, A-02, I-01 (immagine CLI), K-19 (avviso di gitleaks), K-20 (riga nelle licenze). Subito dopo, in parallelo: V-02, V-03, V-04, V-07, A-03, A-09, A-10, U-02 e U-03 appena U-01 è scritto.

K-19 e K-20 chiudono tre `xfail` della Fase 1 senza toccare contratti: sono indipendenti da tutto il resto e possono partire subito. I-01 non dipende da alcuna decisione e si prova sul registry locale; renderla disponibile fuori dal repository dipende da I-04. X-10 è `IPOTESI` solo per scadenza e testo delle eccezioni, e chiude il residuo dell'auto-analisi della Fase 1.

I task `IPOTESI` della prima ondata, U-01 (D2-15) e P-07 (D2-08), hanno un costo minimo se la raccomandazione cade: una pagina di documento e una riga di filtro nell'adattatore.

Da chiedere subito all'utente, perché fermano il percorso critico o il gate: D2-03 (team e protocollo), D2-01 (server e Temporal), D2-10 (livello attivo durante l'ombra), D2-11 (benchmark della Variante B). D2-16 non ferma né il gate né lo sviluppo: serve solo per rendere l'Action e il componente utilizzabili da repository esterni.
