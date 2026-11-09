# Fase 1 — MVP: inventario (Python, JS/TS)

Piano di lavoro derivato da `doc/PROJECT.md` §13 e da `doc/adr/`. Stato del repository alla stesura: nessun codice applicativo.

Obiettivo: CLI `code-analyzer` con `scan`, `sbom`, `gate`, `config validate`, sette plugin in container firmati, SARIF aggregato, policy licenze, fixture con problemi noti. Nessuna UI, nessuna API server, nessun database, nessun Temporal.

## 1. Come leggere il piano

Stato di ogni task:

| Stato | Significato |
| --- | --- |
| `LIBERO` | Presuppone al più ADR tecnici. Non attende alcuna decisione dell'utente |
| `IPOTESI` | Presuppone la raccomandazione di un ADR che richiede l'utente. Può partire: la sezione 3 indica cosa si rifà se la raccomandazione viene respinta |
| `BLOCCATO` | Non può partire o chiudersi finché la decisione indicata non è presa |

Lo stato riguarda il task in sé. Un blocco si propaga lungo le dipendenze: la sezione 3 elenca anche i task bloccati indirettamente.

Gli ADR `Proposto` valgono come ipotesi di lavoro, come richiesto. Sono `Accettato` ADR-0001, ADR-0004 e ADR-0006; di ADR-0009 è accettata solo la parte sul Gate 1.

## 2. Collegamento al Gate 1 (§13)

| Condizione misurabile | Come si misura | Task che la producono | Decisioni necessarie |
| --- | --- | --- | --- |
| **G1.a** 3 repository pilota scansionati | 3 report con `status: complete` e schema valido, gate valutato | X-01, X-04 | D-0009-B; D-0004, D-0006 |
| **G1.b** Scansione < 10 minuti | Durata totale dal report su ciascun pilota, ipotesi ADR-0009: scansione completa. Rilevazione precoce in V-08 | V-08, C-04, X-04 | D-0009-B |
| **G1.c** Tutti i problemi noti delle fixture rilevati | Confronto automatico tra report e `expected-findings.yaml`: nessun atteso mancante | F-01, F-02, F-03, F-04, T-05, T-08 | D-0006 solo per i CVE (T-08) |

X-06 registra l'esito delle tre condizioni. X-07 chiude la fase sulle voci di §13 e sulla Definition of Done di §17, inclusa la CI, che non è una condizione del Gate 1 ma è una voce di §13.

Definition of Done in Fase 1 (§17), con gli adattamenti richiesti:

- Copertura ≥ 80% su `ca-core`: M-03, verificata in X-07.
- Telemetria: ridotta alle durate nel report (ADR-0010). Nessuno stack OpenTelemetry.
- Auto-analisi: valida solo da quando la CLI funziona, quindi da X-05 in poi. Prima di allora la voce non è applicabile, e va dichiarato.
- Comandi di §16 regola 5: `pnpm --dir web` omesso finché `web/` non esiste (M-04, A-03).

## 3. Decisioni dell'utente

Prese dall'utente il 2026-11-08: D-CI (GitHub Actions), D-0004 (`hardened-container` fuori dal server), D-0006 (sincronizzazione separata), D-0009-B (scansione completa < 10 minuti, PR incrementale al Gate 2). Pilota scelti: `fastapi/full-stack-fastapi-template`, `excalidraw/excalidraw`, `saleor/saleor`. Resta da confermare la regola di misura proposta più sotto per D-0009-B (macchina di riferimento e snapshot dei feed). Il parere di `security` su D-0004 resta previsto in S-01.

D-0012: l'utente ha confermato il livello `alto` il 2026-11-08. Ha confermato anche la disattivazione di B105, B106 e B107.

D-0013: decisa il 2026-11-08. Vietate `AGPL-3.0-only`, `AGPL-3.0-or-later` e `SSPL-1.0`; soggette ad approvazione `GPL-2.0-only`, `GPL-2.0-or-later`, `GPL-3.0-only`, `GPL-3.0-or-later`, `LGPL-2.1-only`, `LGPL-2.1-or-later`, `LGPL-3.0-only` e `LGPL-3.0-or-later`. `distributed_product: true`; l'approvazione è di livello `alto`. Verifica legale prima della distribuzione resta in D-0015.

Ordine consigliato per chi decide: D-CI e D-0006 per prime, perché sono quelle che fermano lavoro sul percorso critico o sulle verifiche continue.

| Decisione | Oggetto e raccomandazione | Proprietario | Task bloccati direttamente | Bloccati indirettamente | Gate 1 |
| --- | --- | --- | --- | --- | --- |
| **D-CI** (decisa) | CI del progetto. Raccomandata GitHub Actions (origin è su GitHub; nessuna CI esiste) | Utente | O-01, O-02, O-03 | I-06, X-07 | Non blocca G1.a/b/c, blocca la chiusura fase |
| **D-0004** (decisa) | Accettare `hardened-container` fuori dal server | Utente, con parere `security` | R-09, A-02, A-03 | X-04, X-06, X-07, I-06 | Blocca G1.a e G1.b |
| **D-0005** | Host del registry, namespace, custodia chiave. Nel frattempo registry del repository e chiave di test | Utente | I-06, A-02 | X-07 tramite A-02; nessuno sul gate | Non blocca |
| **D-0006** (decisa) | Sincronizzazione separata del database vulnerabilità | Utente | R-06, P-03, P-05, F-05, L-07, T-08, O-03, A-02 | X-02, I-04, O-02, X-04, X-05, X-06, X-07, I-06 | Blocca G1.a, G1.b e la parte CVE di G1.c |
| **D-0009-A** | Livelli provvisori invece di anticipare la Variante A | Utente | A-02, A-03 | X-07 | Non blocca le tre condizioni; ne cambia il contenuto se respinta |
| **D-0009-B** (decisa) | Gate 1 su scansione completa < 10 minuti, PR incrementale al Gate 2; scelta dei 3 pilota; macchina di riferimento e trattamento della sincronizzazione feed nella misura | Utente | X-01, X-04, X-06, A-03 | X-07 | Blocca G1.a e G1.b |
| **D-0012** (livello deciso: `alto`) | Livello dei segreti non verificati: `alto` raccomandato, `critico` alternativa | Utente | A-03 | X-07 | Non blocca |
| **D-0013** (decisa) | Elenchi `forbidden` e `require_approval` (§18); `distributed_product: true`; `alto` per l'approvazione | Utente | Nessuno; X-03 applica i valori decisi | Nessuno | Non blocca |
| **D-0015** | Verifica legale di motori e regole; licenza del prodotto | Persona designata dall'utente, non un agente | A-04, I-06 | Nessuno sul gate, se i pilota restano uso interno | Non blocca finché non si distribuisce |

Rischio residuo di S-01, decisione dell'utente del 2026-11-09: R-1..R-5 accettati per CI effimere e uso locale, con A-01 e A-02 corretti e riverificati da `security`; runner persistenti condivisi non accettati senza gVisor; M-01 e M-03 inclusi in R-09; `/out` su tmpfs con dimensione massima, valore fissato misurando in X-04 (`doc/verifiche/sicurezza-fase-1.md`).

Decisioni dell'utente del 2026-11-09 sulla riverifica di S-01: soppressioni in linea ignorate per ora (N-04, ADR-0012); residuo di N-03 accettato per la Fase 1; N-09 accettato e da dichiarare in L-06.

Blocchi non legati a un ADR da confermare con l'utente, senza effetto sul percorso critico:

- `sbom --format spdx` è in §9.1 ma non in §13. ADR-0010 lo omette e il piano lo lascia fuori. Se deve rientrare, serve un task in più in `ca_core/sbom/` e in L-03.
- `trufflehog` resta fuori (ADR-0012, ADR-0015): nessuna cartella `builtin/trufflehog/` in Fase 1, benché §3 la elenchi.

### Effetti se una raccomandazione non viene accolta o una decisione viene riaperta

| Decisione | Alternativa | Effetto sul piano |
| --- | --- | --- |
| D-CI | Altra piattaforma | Si riscrivono O-01..O-03. I comandi di verifica sono locali (M-04) e non cambiano. Cambia il registry provvisorio di I-02 |
| D-0004 | Solo gVisor (opzione 2) | R-02 e R-05 restano, `hardened-container` diventa un errore. Servono `runsc` sulla macchina di sviluppo (oggi assente) e runner CI propri: O-02 cambia |
| D-0004 | Immagine unica con sottoprocessi (opzione 1) | Si riscrivono R-02, R-03, R-05, I-01, I-02 e la parte immagine di tutti i P-*. Cade la firma per plugin: ADR-0005 e S-01 si riaprono |
| D-0004 | Ripiego su sottoprocesso (opzione 4) | Si aggiunge un `SubprocessExecutor` e S-01 si estende. Nessun lavoro perso |
| D-0005 | Keyless (opzione 2) | R-04 e V-06 si rifanno. La chiave pubblica esce dal pacchetto. La verifica dipende da radice e log pubblici: da rivalutare per l'uso air-gapped |
| D-0005 | Solo digest (opzione 1) | R-04 si riduce a controllo del digest. Va modificato §7.2 |
| D-0006 | Rete durante la scansione (opzione 1) | Cade l'invariante "codice o rete". R-06 si sostituisce con un proxy di uscita (componente nuovo, serve ADR). `feeds` esce da C-02. S-01 si estende |
| D-0006 | Database nell'immagine (opzione 2) | R-06 sparisce, `feeds` esce da C-02. P-03 e P-05 diventano build giornaliere, in conflitto con il digest fissato (ADR-0005 da riaprire) |
| D-0006 | Mirror anticipati (opzione 4) | Si importa infrastruttura di Fase 2: nuovo ambito e nuovi task, fuori da questo piano |
| D-0009-A | Variante A anticipata | ADR-0009 decade e le lacune 5 e 6 tornano bloccanti. Servono EPSS, KEV e raggiungibilità, quindi feed e `ca-graph`. K-11 si butta. Il piano va rifatto per la parte `gate` |
| D-0009-A | Gate solo su licenze e segreti (opzione 3) | K-11 si riduce e K-13 filtra per categoria. Nessun altro task cambia |
| D-0009-A | `gate` in Fase 2 (opzione 4) | Escono K-13, L-05 e T-07. Contraddice §13 |
| D-0009-B | Gate 1 sulla PR incrementale | Vanno anticipati baseline e `--pr` di Fase 2, e `resolve_changed_files`. X-04 non è eseguibile con questo piano |
| D-0012 | `critico` | Cambia una riga in K-11. Gli attesi delle fixture non contengono il livello |
| D-0012 | Verifica online o trufflehog | Viola ADR-0006 e §7.2: serve un nuovo ADR, un plugin in più e la verifica di licenza AGPL |
| D-0013 | `medio` per l'approvazione | Cambia una riga in K-12. La policy non blocca più il gate predefinito |
| D-0013 | Corrispondenza esatta di stringa | K-12 si semplifica e L-02 perde il controllo delle espressioni. Licenze composte eludono la policy |
| D-0015 | Semgrep escluso | Per JS/TS non resta SAST: G1.c non è raggiungibile con le fixture di F-03, serve un altro motore e un nuovo ADR |
| D-0015 | Regole terze ammesse (opzione 3) | P-09 si amplia. La copertura sui pilota migliora, le fixture non cambiano |

Per D-0009-B il piano propone, senza deciderlo: misura sulla macchina di sviluppo attuale con snapshot dei feed già presente, tempo di sincronizzazione riportato a parte. §13 precisa che i valori sono da confermare dopo il pilota.

## 4. Fuori ambito (Fase 2 e successive)

Temporal, testcontainers e i test di integrazione di §14 basati su di essi (ADR-0002). PostgreSQL, object storage, API REST, UI, OpenAPI. `ca-graph`, scoring A/B, EPSS/KEV, baseline, `--pr`, `--base`, `--variant`. Plugin ruff, eslint, checkov, hadolint, coverage. GitHub Action, componente GitLab e correzione di §12.1. `explain`, `plugin list|verify|run`, VEX. Adattatore Kubernetes con gVisor. Stack OpenTelemetry.

Java/Kotlin resta in Fase 4 (§13). Decisione dell'utente del 2026-11-08: dopo il Gate 1 si fa una scansione di prova su un repository Java, fuori dalla misura del gate, solo per vedere cosa funziona già.

Livelli di §14 attivi in Fase 1: Unit (senza scoring), Contratto, integrazione con daemon Docker reale e plugin finto, E2E della sola CLI.

## 5. Ordine e parallelismo

Prima i fatti (V), poi le fondamenta (M), poi i contratti (C) e gli attesi (F, T-01), infine le implementazioni che li consumano. Ogni task che consuma un contratto dipende esplicitamente da esso, come chiede ADR-0003.

Le ondate elencano i task che possono procedere insieme a dipendenze soddisfatte, supponendo prese le decisioni. Ogni ondata è parallelizzabile al suo interno.

| Ondata | Task (`*` = `BLOCCATO`) |
| --- | --- |
| 1 | M-01, V-01, X-01* |
| 2 | M-02, M-03, M-05, V-02, V-03, V-04, V-05, V-06, V-07, V-08 |
| 3 | A-04*, C-01, C-03, M-04, V-09 |
| 4 | A-01, C-02, C-05, F-01, I-01, K-07, K-08, K-09, K-11, M-06, T-01 |
| 5 | A-02*, A-03*, C-04, C-06, F-02, F-03, F-04, I-02, K-01, K-02, R-01, T-02 |
| 6 | C-07, I-05, K-03, K-04, K-06, K-10, K-13, K-14, K-15, K-16, L-01, P-09, R-02, R-04, R-08 |
| 7 | K-05, K-12, K-18, L-05, O-01*, R-03, R-05, R-06*, T-04 |
| 8 | K-17, L-02, P-01, R-07 |
| 9 | F-06, L-03, L-04, P-02, P-04, P-06, P-07, P-08, P-10, T-03 |
| 10 | I-03, L-06, P-03*, P-05*, S-01, T-05, T-06, T-07, X-03* |
| 11 | F-05*, L-07*, R-09*, S-02 |
| 12 | O-03*, T-08* |
| 13 | X-02, X-05 |
| 14 | I-04 |
| 15 | O-02*, X-04* |
| 16 | I-06*, X-06* |
| 17 | X-07 |

Vincoli di parallelismo da rispettare oltre le dipendenze:

- `pyproject.toml` radice: M-01, M-02 e M-03 lo toccano tutti e vanno in serie o coordinati, come risulta dalle dipendenze.
- `schemas/`: i task C-* generano file distinti; rigenerare con l'export prima del merge.
- P-02..P-10 toccano ciascuno solo la propria cartella `builtin/<nome>/`: sono il blocco parallelo più ampio del piano.
- K-17 compone i moduli K-05..K-12 e non va iniziato prima che siano chiusi.

## 6. Task

Formato: `Stato` come da sezione 1. `Spec` e `ADR` indicano la sezione della specifica e gli ADR presupposti. I test indicati nell'accettazione sono scritti nello stesso task, salvo quelli assegnati a `test`.

### V — Verifica iniziale dei fatti sugli scanner

Task iniziale di verifica, diviso per argomento. Le informazioni negli ADR su licenze, versioni CycloneDX, opzioni offline e flag cosign non sono state controllate sulle versioni reali. Esito in `doc/verifiche/scanner-fase-1.md`. Questi task possono usare la rete (§16 regola 7 riguarda i test) e girano solo su repository pubblici o di prova. `cosign` e `runsc` oggi non sono installati sulla macchina di sviluppo.

#### V-01 — Fissare le versioni candidate
- Agente: `devops`. Stato: `LIBERO`.
- Percorsi: `doc/verifiche/scanner-fase-1.md`.
- Dipende da: nessuno.
- Accettazione: tabella con versione esatta, digest o checksum di rilascio, data e stato di manutenzione per syft, osv-scanner, trivy, scancode, gitleaks, semgrep, bandit, cosign.
- Spec: §7.3, §16 regola 2. ADR: 0005, 0007.

#### V-02 — Licenze sul testo della versione fissata
- Agente: `devops`. Stato: `LIBERO`.
- Percorsi: `doc/verifiche/scanner-fase-1.md`.
- Dipende da: V-01.
- Accettazione: per ogni motore e per le regole del registry Semgrep, licenza letta dal file al tag fissato, con collegamento, confrontata con la tabella di ADR-0015. Non è il parere legale (A-04).
- Spec: §7.3. ADR: 0015, 0012.

#### V-03 — Versioni CycloneDX emesse
- Agente: `devops`. Stato: `LIBERO`.
- Percorsi: `doc/verifiche/scanner-fase-1.md`.
- Dipende da: V-01.
- Accettazione: versione `specVersion` realmente emessa da syft e trivy sulle versioni fissate, ed elenco proposto delle versioni ammesse in ingresso. Indica se K-03 è una vera conversione o un passaggio diretto.
- Spec: §1, §7.2. ADR: 0007, 0003.

#### V-04 — Contenuto reale degli output
- Agente: `devops`. Stato: `LIBERO`.
- Percorsi: `doc/verifiche/scanner-fase-1.md`, `tests/fixtures/plugin-output/`.
- Dipende da: V-01.
- Accettazione: campioni reali registrati e, per scanner, esito su: CVSS e alias in SARIF di osv-scanner e trivy; severità in SARIF di semgrep, bandit e trivy; formato SARIF disponibile per bandit; oscuramento gitleaks; forma JSON di scancode; lettura di `bun.lock` da parte di syft e osv-scanner (usato dal pilota `fastapi/full-stack-fastapi-template`). Segnala i casi in cui serve il formato nativo.
- Spec: §7.1. ADR: 0007, 0008, 0009, 0012.

#### V-05 — Opzioni offline dei database
- Agente: `devops`. Stato: `LIBERO`.
- Percorsi: `doc/verifiche/scanner-fase-1.md`.
- Dipende da: V-01.
- Accettazione: comandi esatti di scaricamento senza workspace e di scansione senza rete per osv-scanner e trivy, dimensione dello snapshot, firma disponibile o meno. Include il bundle delle regole di configurazione di trivy, che non deve richiedere rete durante la scansione.
- Spec: §7.2. ADR: 0006, 0007.

#### V-06 — Verifica cosign senza log di trasparenza
- Agente: `devops`. Stato: `LIBERO`.
- Percorsi: `doc/verifiche/scanner-fase-1.md`.
- Dipende da: V-01.
- Accettazione: comandi esatti di firma con chiave e di verifica senza log sulla versione fissata, provati su un registry locale. Chiarisce se la verifica richiede accesso al registry, e quindi come firmare e verificare nei test le immagini costruite localmente.
- Spec: §7.2. ADR: 0005.

#### V-07 — Comportamento con le restrizioni del container
- Agente: `devops`. Stato: `LIBERO`.
- Percorsi: `doc/verifiche/scanner-fase-1.md`.
- Dipende da: V-01.
- Accettazione: ogni scanner eseguito con `--network none`, root in sola lettura, workspace in sola lettura, `--cap-drop ALL`, utente non root. Registra: necessità di tmpfs o `HOME` scrivibili (ADR-0004 non li elenca), scrittura in `/out` con UID diverso dal proprietario, lettura della storia git da repository di altro proprietario per gitleaks, limite PID sufficiente per scancode.
- Spec: §7.2. ADR: 0004, 0012.

#### V-08 — Misura preliminare di scancode
- Agente: `devops`. Stato: `LIBERO`.
- Percorsi: `doc/verifiche/scanner-fase-1.md`.
- Dipende da: V-01.
- Accettazione: durata di scancode sul pilota più grande, `saleor/saleor`, con numero di file e LOC. Se supera da solo la metà del budget di 10 minuti, propone contromisure da portare in X-04.
- Spec: §13. ADR: 0009.

#### V-09 — Consolidamento e riapertura ADR
- Agente: `architect`. Stato: `LIBERO`.
- Percorsi: `doc/verifiche/scanner-fase-1.md`, `doc/adr/` solo se un fatto smentisce un ADR.
- Dipende da: V-02, V-03, V-04, V-05, V-06, V-07, V-08.
- Accettazione: per ogni affermazione da verificare negli ADR, esito `confermato`, `smentito` o `non verificabile`. Elenco degli ADR riaperti, con i task del piano interessati. Una smentita ferma i task dipendenti finché l'ADR non è aggiornato.
- Spec: §7. ADR: 0004, 0005, 0006, 0007, 0009, 0012, 0015.

### A — Decisioni e allineamento della specifica

#### A-01 — Revisione tecnica degli ADR senza decisione umana
- Agente: `architect`. Stato: `LIBERO`.
- Percorsi: `doc/adr/`.
- Dipende da: V-09.
- Accettazione: 0002, 0003, 0007, 0008, 0010, 0011, 0014 passano ad `Accettato` o tornano in discussione con motivo. La revisione chiude le lacune di dettaglio emerse in pianificazione: manifest sorgente e impacchettato (C-02), percorso di `inputs.sbom` e `inputs.config` (C-02), schema delle proprietà SARIF non previsto da ADR-0003 (C-05), cartella `tests/contract/` non prevista da §3.
- Esito (2026-11-08): ADR-0003 `Accettato`. Restano `Proposto` 0002, 0007, 0008, 0010, 0011, 0014: la decisione non è contestata e i task che la realizzano procedono; manca la prova nell'implementazione, e ogni ADR elenca in "Revisione A-01" i task che la portano. `tests/contract/` confermata (ADR-0003); §3 si aggiorna con A-03. Correzioni ai contratti: emendamenti di C-01..C-05 e C-07.
- Spec: §16 regola 1. ADR: tutti i citati.

#### A-02 — Applicare a `doc/PROJECT.md` le modifiche di §4.1, §7.1, §7.2, §8
- Agente: `architect`. Stato: `BLOCCATO` da D-0005, D-0009-A.
- Percorsi: `doc/PROJECT.md`.
- Dipende da: A-01.
- Accettazione: §4.1 con `tools`, `level_source`, `Location.commit` opzionale, `id` e date senza database; §7.1 con `feeds` e versione CycloneDX; §7.2 con versioni ammesse in ingresso, livelli di isolamento e firma; §8 con `paths.exclude` e `gate.mode: all`. Nessuno scarto tra testo e schemi esportati.
- Spec: §4.1, §7.1, §7.2, §8. ADR: 0004, 0005, 0006, 0007, 0008, 0009, 0014.

#### A-03 — Allineare le altre sezioni della specifica
- Agente: `architect`. Stato: `BLOCCATO` da D-0009-A.
- Percorsi: `doc/PROJECT.md`.
- Dipende da: A-01.
- Accettazione: §2 e §7 (gVisor obbligatorio solo su server), §3 (`pipeline/`, `ports.py`, feed fuori dal nucleo, `scan-report`, cartella di contratto, trufflehog), §5 (motore senza Temporal in Fase 1, requisito PR al Gate 2), §13 (significato del Gate 1), §14, §16 regola 5 (`pnpm` condizionato), §17 (telemetria e auto-analisi in Fase 1). §12.1 resta per la Fase 2.
- Spec: §2, §3, §5, §13, §14, §16, §17. ADR: 0001, 0002, 0004, 0009, 0010, 0012.

#### A-04 — Registrare l'esito legale e la licenza del prodotto
- Agente: `architect`, su esito fornito dal proprietario umano. Stato: `BLOCCATO` da D-0015.
- Percorsi: `doc/verifiche/licenze-fase-1.md`, `LICENSE`.
- Dipende da: V-02.
- Accettazione: esito firmato dal proprietario per ogni motore e per le regole; file `LICENSE` presente; condizioni di attribuzione riportate in I-05.
- Spec: §7.3. ADR: 0015.

### M — Monorepo e strumenti

#### M-01 — Workspace `uv` e pacchetti di Fase 1
- Agente: `backend`. Stato: `LIBERO`.
- Percorsi: `pyproject.toml`, `uv.lock`, `packages/ca-core/`, `packages/ca-plugins/`, `packages/ca-cli/`.
- Dipende da: nessuno.
- Accettazione: `uv sync` e `uv run pytest -q` passano con un test minimo per pacchetto. Python 3.12+. Non esistono altri pacchetti di §3.
- Spec: §2, §3, §13. ADR: 0001.

#### M-02 — Contratto `import-linter`
- Agente: `backend`. Stato: `LIBERO`.
- Percorsi: `pyproject.toml`.
- Dipende da: M-01.
- Accettazione: il controllo locale impone la tabella di ADR-0001 per i tre pacchetti; `ca-core` non importa `subprocess`, client HTTP né S3; `ca-cli` non importa Temporal, FastAPI né driver di database. Un import vietato introdotto per prova fa fallire il controllo.
- Spec: §3. ADR: 0001.

#### M-03 — Ruff, mypy, pytest, copertura
- Agente: `backend`. Stato: `LIBERO`.
- Percorsi: `pyproject.toml`.
- Dipende da: M-01.
- Accettazione: i comandi di §16 regola 5 lato Python passano sul progetto vuoto. La copertura di `ca-core` fallisce sotto l'80%.
- Spec: §16, §17. ADR: nessuno.

#### M-04 — `AGENTS.md`
- Agente: `architect`. Stato: `LIBERO`.
- Percorsi: `AGENTS.md`.
- Dipende da: M-02, M-03, M-05.
- Accettazione: contiene le regole di §16 e i comandi locali di verifica, inclusi `import-linter` e l'export `--check`. I comandi `pnpm --dir web` sono omessi con la nota "finché `web/` non esiste". Tutti i comandi elencati, eseguiti, passano.
- Spec: §3, §16. ADR: 0001, 0003.

#### M-05 — Export degli schemi con `--check`
- Agente: `backend`. Stato: `LIBERO`.
- Percorsi: `packages/ca-core/src/ca_core/`, `schemas/`.
- Dipende da: M-01.
- Accettazione: l'export scrive `schemas/*.schema.json` con `$id` e versione. `--check` esce con errore se un modello e il file divergono, provato con una divergenza voluta.
- Spec: §3, §16 regola 1. ADR: 0003.

#### M-06 — Schemi esterni fissati e risoluzione locale
- Agente: `backend`. Stato: `LIBERO`.
- Percorsi: `schemas/vendor/`, `packages/ca-core/src/ca_core/`.
- Dipende da: M-01, V-09.
- Accettazione: SARIF 2.1.0 e le versioni CycloneDX ammesse copiati con i relativi `$ref`. La validazione funziona senza rete e un `$ref` esterno o fuori dai percorsi ammessi viene rifiutato. Da R-09 i file stanno in `ca_core/vendor_schemas/` e `schemas/vendor` è un symlink (ADR-0003, emendamento per R-09).
- Spec: §1, §7.2. ADR: 0003, 0007.

### C — Contratti

Precedono ogni implementazione che li consuma. Modello e schema esportato stanno nella stessa modifica; la revisione di `architect` parte dal diff dello schema.

#### C-01 — Contratto `finding`
- Agente: `backend`. Stato: `IPOTESI` (D-0009-A, solo `level_source`).
- Percorsi: `packages/ca-core/src/ca_core/models/`, `schemas/finding.schema.json`.
- Dipende da: M-05.
- Accettazione: modello §4.1 rivisto secondo ADR-0008: `tools` accanto a `tool` (primo in ordine lessicografico), `evidence` per tool con `occurrences`, `Location.commit` opzionale, `id` uguale al fingerprint e date uguali all'ora della scansione in assenza di database. `level_source` da ADR-0009. `impact` e `score` ammessi a `null`. `extra="forbid"`. `--check` verde. Emendamenti dopo A-01: `tools` con `uniqueItems: true`; `description` su `tool` (primo di `tools`) e su `Location` (`end_line` non precede `start_line`), vincoli che lo schema non può esprimere (ADR-0003).
- Spec: §4.1, §4.2. ADR: 0003, 0008, 0009.

#### C-02 — Contratto `plugin-manifest`
- Agente: `backend`. Stato: `IPOTESI` (D-0005).
- Percorsi: `packages/ca-core/src/ca_core/models/`, `schemas/plugin-manifest.schema.json`.
- Dipende da: M-05, V-09.
- Accettazione: §7.1 più blocco opzionale `feeds`, versione CycloneDX emessa tra quelle ammesse, limite di byte obbligatorio. Definisce il percorso di montaggio di `inputs.sbom` e `inputs.config`, oggi non specificato. Stabilisce la distinzione tra manifest sorgente e impacchettato: `@sha256:` obbligatorio solo su quest'ultimo. Schema con esempi validi e non validi per ogni regola. Emendamenti dopo A-01: `sarif` e `cyclonedx` con percorsi diversi, tetto di `max_bytes`, `latest` vietato, `outputs.cyclonedx` incompatibile con `inputs.sbom: optional` (ADR-0004, 0005, 0007). Elementi di `feeds.sync_command` con `minLength: 1` nello schema, come `Annotated[str, Field(min_length=1)]` al posto del `field_validator` (ADR-0003).
- Spec: §7.1, §7.2. ADR: 0003, 0004, 0005, 0006, 0007.

#### C-03 — Contratto `code-analyzer-config`
- Agente: `backend`. Stato: `IPOTESI` (D-0009-A per `gate.mode: all`).
- Percorsi: `packages/ca-core/src/ca_core/models/`, `schemas/code-analyzer-config.schema.json`.
- Dipende da: M-05.
- Accettazione: tutto §8 più `paths.exclude`. `service`, `scoring`, `agents` validati e inerti. `additionalProperties: false`, `version: 1`. Nessuna chiave per immagine, digest, firma, isolamento, rete, montaggi, comando o origine dei feed: un file con una di queste chiavi è rifiutato. Emendamenti dopo A-01 (ADR-0003, 0014): gli elementi di `paths.exclude` e `plugins.semgrep.rules` hanno nello schema `minLength: 1` e un `not` con `pattern` uguale a `^[/\\]|^[A-Za-z]:|(^|[/\\])\.\.([/\\]|$)`, equivalenti a `_relative_posix`, con `json_schema_extra` su `RelativePath`; `Gate` ha un `allOf` generato dall'enum `Level` che per ogni livello vieta la presenza in entrambe le liste (`not` su `block_on` e `warn_on` con `type: array` e `contains: {const: <livello>}`, `required` su tutte e due).
- Spec: §8. ADR: 0003, 0009, 0014.

#### C-04 — Contratto `scan-report`
- Agente: `backend`. Stato: `IPOTESI` (D-0005).
- Percorsi: `packages/ca-core/src/ca_core/models/`, `schemas/scan-report.schema.json`.
- Dipende da: C-01, C-02.
- Accettazione: campi di ADR-0010, inclusi stato `complete | partial`, `effective_mode`, durata totale e per plugin, e per plugin versione, digest, firma, isolamento, esito, snapshot del feed. Copertura ridotta della storia git, plugin disattivati, esclusioni ed eccezioni applicate. Emendamenti dopo A-01 (ADR-0003, 0010). `PluginRun`: `if` `outcome` è `failed` (`required: [outcome]`), `then` `failure` `type: string` e `required`, `else` `failure` `type: null`. `ScanReport`: `if` `plugins` `contains` un elemento con `outcome` `failed` (`required: [outcome]`, `required: [plugins]`), `then` `status` `const: partial`, in un solo verso. Entrambi con `json_schema_extra` nel `model_config`, come `Outputs`; i validatori del modello restano. `description` su `plugins` (nomi unici) e su `disabled_plugins` (disgiunti dai nomi di `plugins`), non esprimibili. La versione resta 1.0 (ADR-0003).
- Spec: §9.1, §17. ADR: 0003, 0004, 0005, 0006, 0009, 0010, 0012, 0014.

#### C-05 — Contratto delle proprietà SARIF dei plugin
- Agente: `backend`. Stato: `LIBERO`.
- Percorsi: `schemas/plugin-sarif-properties.schema.json`.
- Dipende da: M-05, V-09.
- Accettazione: schema autonomo e chiuso (`extra="forbid"`) per `aliases`, `cvss`, `tool_severity`, `license_spdx`, `purl`, `category`, `secret_sha256`. Serve perché gli adattatori nelle immagini non importano `ca-core`. Confermato da `architect` in A-01 (emendamenti di ADR-0003 e ADR-0007). Emendamento dopo A-01: `allOf` con due regole, valide solo se `category` è presente: `secret` richiede `secret_sha256` di tipo stringa, `dependency` richiede `purl` di tipo stringa; stesso controllo nel modello. Il caso valido `category` di `test_sarif_properties_contract.py` deve aggiungere `purl`. Senza `category` il controllo spetta a K-05.
- Spec: §7.1. ADR: 0003, 0007.

#### C-06 — Porte del nucleo
- Agente: `backend`. Stato: `LIBERO`.
- Percorsi: `packages/ca-core/src/ca_core/ports.py`.
- Dipende da: C-01, C-02.
- Accettazione: `Protocol` tipizzati per `PluginExecutor`, `SourceReader`, `ArtifactSink`, `Clock`, con ingressi e uscite serializzabili. Fake in memoria usati dai test di `ca-core`. `mypy` verde. Emendamenti dopo A-01: `SourceTooLarge`, livello di isolamento noto prima dell'esecuzione, ingressi non dichiarati rifiutati (ADR-0004, 0014). Emendamenti di ADR-0002, 0004, 0005: `PluginExecutor.run_many`, `RunOutcome.INVALID_OUTPUT`, `PluginRunResult.signature` obbligatorio.
- Spec: §5. ADR: 0001, 0002.

#### C-07 — Test di contratto sugli schemi
- Agente: `test`. Stato: `LIBERO`.
- Percorsi: `tests/contract/`.
- Dipende da: C-01, C-02, C-03, C-04, C-05.
- Accettazione: istanze valide e non valide per i cinque schemi, validate contro i file in `schemas/` senza importare i modelli. Emendamenti dopo A-01 (ADR-0003): `test_status_is_not_tied_to_plugin_outcome` si sostituisce con casi non validi per `complete` con plugin `failed`, e per `failed` senza `failure` o con `failure` nullo o `ok` con `failure`, tenendo valido `partial` senza plugin falliti. Casi non validi per ogni emendamento di C-01..C-05. Un test di equivalenza `test_*_model_equivalence.py` per ogni contratto (oggi solo le proprietà SARIF), con i casi che soltanto il modello rifiuta elencati per nome: un nuovo disallineamento fa fallire il test. Eccezione ammessa alla regola sui modelli.
- Spec: §14, §16 regola 1. ADR: 0003.

### F — Fixture e attesi

Gli attesi precedono scanner e pipeline: G1.c si misura contro di essi. Ogni atteso viene osservato almeno una volta eseguendo lo scanner direttamente.

#### F-01 — Formato degli attesi
- Agente: `test`. Stato: `LIBERO`.
- Percorsi: `tests/fixtures/expected-findings.schema.json`.
- Dipende da: C-01.
- Accettazione: schema con categoria, regola o CVE, percorso, intervallo di righe e tool ammessi. Non usa il fingerprint come chiave, per non legare le fixture all'algoritmo sotto verifica.
- Spec: §13. ADR: 0008.

#### F-02 — Fixture Python
- Agente: `test`. Stato: `LIBERO`.
- Percorsi: `tests/fixtures/repos/python-app/`.
- Dipende da: F-01, V-01.
- Accettazione: lockfile con CVE note, problemi SAST per bandit e per le regole Semgrep, `Dockerfile` o Terraform per trivy, file con licenza riconoscibile, dipendenza con licenza soggetta a policy. `expected-findings.yaml` valido, senza attesi su B105, B106 e B107 (ADR-0012). Nessun progetto vulnerabile viene installato.
- Spec: §13, §16 regola 4. ADR: 0007, 0013, 0015.

#### F-03 — Fixture JS/TS
- Agente: `test`. Stato: `LIBERO`.
- Percorsi: `tests/fixtures/repos/js-ts-app/`.
- Dipende da: F-01, V-01.
- Accettazione: come F-02 per npm e TypeScript, con problemi SAST coperti solo dalle regole Semgrep del progetto.
- Spec: §13. ADR: 0007, 0015.

#### F-04 — Costruttore della storia git con segreti finti
- Agente: `test`. Stato: `LIBERO`.
- Percorsi: `tests/fixtures/repos/secrets-history/`, `tests/fixtures/builders/`.
- Dipende da: F-01, V-04.
- Accettazione: la storia viene generata durante il test, perché un `.git` annidato non è versionabile. Segreto presente solo in un commit passato e segreto in HEAD. Valori finti, riconoscibili, accettati da gitleaks (i valori di esempio noti possono essere ignorati dalle sue regole) e tali da non attivare la protezione dei push. Copre anche il clone superficiale.
- Spec: §7.3, §13. ADR: 0012.

#### F-05 — Snapshot congelato dei feed
- Agente: `test`. Stato: `LIBERO`.
- Percorsi: `tests/fixtures/feeds/README.md`, cache locale fuori dal repository.
- Dipende da: P-03, P-05.
- Accettazione: procedura ripetibile che produce uno snapshot contenente i CVE attesi, datato e con checksum, usato dai test senza rete. Preparato localmente finché O-03 non lo sostituisce.
- Spec: §16 regola 7. ADR: 0006.

#### F-06 — Configurazione del monorepo
- Agente: `test`. Stato: `LIBERO`.
- Percorsi: `.code-analyzer.yml`.
- Dipende da: L-02.
- Accettazione: `config validate` passa. `paths.exclude` copre `tests/fixtures/` e `golden-set/`. Nessun blocco `licenses` fino a X-03.
- Spec: §8, §17. ADR: 0014.

### T — Test

#### T-01 — Tabella dei casi del fingerprint
- Agente: `test`. Stato: `LIBERO`.
- Percorsi: `tests/unit/core/test_fingerprint.py`.
- Dipende da: C-01.
- Accettazione: casi attesi per i sei `kind` di ADR-0008 e proprietà hypothesis: spostamento di righe, CRLF, duplicati e occorrenze, alias CVE/GHSA, stesso segreto in più commit. Scritti prima di K-04 e inizialmente in errore. Adattamenti e vettori in ADR-0008, "Precisazioni per K-04".
- Spec: §4.2, §14. ADR: 0008.

#### T-02 — Plugin finto
- Agente: `test`. Stato: `LIBERO`.
- Percorsi: `tests/fixtures/plugins/fake/`.
- Dipende da: I-01, C-02.
- Accettazione: immagine locale con comportamenti selezionabili: successo, exit non zero, SARIF non valido, output oltre il limite, scrittura in `/tmp` e in `/out` con il profilo completo, symlink in `/out`, tentativo di rete, tentativo di scrittura nel workspace, timeout.
- Spec: §7.2, §16 regola 4. ADR: 0004.

#### T-03 — Test del confine host–plugin
- Agente: `test`. Stato: `IPOTESI` (D-0005).
- Percorsi: `tests/integration/runner/`.
- Dipende da: T-02, R-02, R-03, R-04, R-05, R-07, R-08.
- Accettazione: ogni comportamento di T-02 produce l'esito di ADR-0004 e ADR-0005. Symlink, `..`, URI assoluti e file oltre il limite sono rifiutati. Firma assente o errata non fa partire alcun container ed esce con 2. Nessuna variabile d'ambiente dell'host arriva al plugin. Con registry non raggiungibile esce con 2. Workspace di altro proprietario leggibile e `/out` scrivibile con UID `65534`.
- Spec: §7.2, §15. ADR: 0004, 0005, 0008.

#### T-04 — Harness di contratto dei plugin
- Agente: `test`. Stato: `LIBERO`.
- Percorsi: `tests/contract/plugins/`.
- Dipende da: C-05, C-07, M-06.
- Accettazione: test parametrico che valida output reali registrati di un plugin contro SARIF o CycloneDX e contro le proprietà di C-05, senza importare `ca-core`. Prova con i campioni di V-04.
- Spec: §7.2, §14, §16 regola 4. ADR: 0003, 0007.

#### T-05 — E2E di rilevamento senza CVE
- Agente: `test`. Stato: `IPOTESI` (D-0005, D-0015).
- Percorsi: `tests/e2e/test_detection.py`.
- Dipende da: L-04, F-02, F-03, F-04, P-01, P-04, P-06, P-07, P-08, P-10.
- Accettazione: per segreti, SAST Python e JS/TS, IaC, licenze: nessun atteso mancante sulle tre fixture. Parte di G1.c. Nessuna chiamata di rete.
- Spec: §13, §14. ADR: 0007, 0012, 0015.

#### T-06 — Sentinella del segreto
- Agente: `test`. Stato: `LIBERO`.
- Percorsi: `tests/e2e/test_secret_sentinel.py`.
- Dipende da: L-04, P-07, P-08, P-10, F-04.
- Accettazione: il valore sentinella è assente da report, SARIF, stdout e log, anche quando compare in un'assegnazione Python che attiverebbe B105 e sulla riga trovata da una regola Semgrep con metavariabile nel messaggio.
- Spec: §15. ADR: 0011, 0012.

#### T-07 — Matrice E2E di `scan` e `gate`
- Agente: `test`. Stato: `IPOTESI` (D-0005, D-0009-A).
- Percorsi: `tests/e2e/test_gate.py`.
- Dipende da: L-04, L-05, T-02.
- Accettazione: exit 0, 1, 2 per scan completa e parziale, con e senza `--allow-partial`, immagine non firmata, `--fail-on`, `new-findings-only` trattato come `all` con avviso, eccezioni attive e scadute.
- Spec: §9.1. ADR: 0005, 0009, 0010, 0014.

#### T-08 — E2E di rilevamento dei CVE
- Agente: `test`. Stato: `LIBERO`.
- Percorsi: `tests/e2e/test_detection_cve.py`.
- Dipende da: T-05, F-05, L-07.
- Accettazione: tutti i CVE attesi rilevati con lo snapshot congelato e `--offline`. Fusione tra osv-scanner e trivy sullo stesso problema verificata. Completa G1.c.
- Spec: §13. ADR: 0006, 0007, 0008.

### K — Nucleo `ca-core`

#### K-01 — Lettura SARIF non fidata
- Agente: `backend`. Stato: `LIBERO`.
- Percorsi: `packages/ca-core/src/ca_core/sarif/`.
- Dipende da: C-01, C-05, M-06.
- Accettazione: legge SARIF 2.1.0 validato contro lo schema fissato e le proprietà di C-05. Input non valido genera un errore di plugin. Casi hypothesis senza eccezioni non gestite.
- Spec: §7.2, §14. ADR: 0003, 0007.

#### K-02 — Lettura CycloneDX per versione
- Agente: `backend`. Stato: `LIBERO`.
- Percorsi: `packages/ca-core/src/ca_core/sbom/`.
- Dipende da: M-06, C-02.
- Accettazione: valida secondo la versione dichiarata dal manifest. Versione non ammessa o documento non conforme fanno fallire il plugin.
- Spec: §7.2. ADR: 0007.

#### K-03 — Scrittura CycloneDX 1.7
- Agente: `backend`. Stato: `LIBERO`.
- Percorsi: `packages/ca-core/src/ca_core/sbom/`.
- Dipende da: K-02.
- Accettazione: l'output è sempre 1.7 e valido contro lo schema fissato, senza perdita dei campi usati (componenti, purl, licenze). V-03 ha confermato che syft e trivy emettono già 1.7, quindi il task si riduce alla validazione.
- Spec: §1. ADR: 0007.

#### K-04 — Fingerprint `fp1`
- Agente: `backend`. Stato: `LIBERO`.
- Percorsi: `packages/ca-core/src/ca_core/fingerprint.py`.
- Dipende da: T-01, C-06.
- Accettazione: T-01 interamente verde. Formato, firma e vettori di ADR-0008, "Precisazioni per K-04", comprese `context_hash`, `normalize_purl` e `assign_occurrences`. Per i segreti usa l'hash già calcolato nel container.
- Spec: §4.2. ADR: 0008.

#### K-05 — Normalizzazione SARIF in `Finding`
- Agente: `backend`. Stato: `LIBERO`.
- Percorsi: `packages/ca-core/src/ca_core/normalize.py`.
- Dipende da: K-01, K-04, C-06.
- Accettazione: mappa i sei `kind`, usa `Clock` per le date e gestisce la cartella non git. URI assoluti, `..` e symlink fanno fallire il plugin. Assegna `occurrence` per ogni SARIF con `assign_occurrences`; `vuln_ids` è l'unione di `ruleId` e `aliases`; file oltre il limite o `result` senza `region` producono un finding senza contesto (ADR-0008, "Precisazioni per K-04").
- Spec: §4.1, §5. ADR: 0002, 0007, 0008.

#### K-06 — Licenze dichiarate da SBOM
- Agente: `backend`. Stato: `LIBERO`.
- Percorsi: `packages/ca-core/src/ca_core/normalize.py`.
- Dipende da: K-02, C-06.
- Accettazione: estrae per ogni componente purl e licenza dichiarata, comprese licenza mancante, `NOASSERTION` e `LicenseRef-*`.
- Spec: §7.3. ADR: 0007, 0013.

#### K-07 — Deduplicazione
- Agente: `backend`. Stato: `LIBERO`.
- Percorsi: `packages/ca-core/src/ca_core/dedup.py`.
- Dipende da: C-01.
- Accettazione: `deduplicate` fonde per fingerprint nella scansione, conservando tutti i `tools`, l'evidenza per tool e `occurrences`, con le regole di ADR-0008, "Precisazioni per K-04" §7. Proprietà hypothesis: idempotenza e indipendenza dall'ordine. SAST di scanner diversi non si fondono.
- Spec: §4.2, §14. ADR: 0008.

#### K-08 — Filtro `paths.exclude`
- Agente: `backend`. Stato: `LIBERO`.
- Percorsi: `packages/ca-core/src/ca_core/pipeline/`.
- Dipende da: C-01, C-03.
- Accettazione: filtro autorevole in normalizzazione con i predefiniti di ADR-0014 e artefatti di output. L'esclusione di `.git` non si applica a gitleaks. Le esclusioni compaiono nel report.
- Spec: §8, §17. ADR: 0014.

#### K-09 — Eccezioni
- Agente: `backend`. Stato: `LIBERO`.
- Percorsi: `packages/ca-core/src/ca_core/pipeline/`.
- Dipende da: C-01, C-03.
- Accettazione: eccezione con fingerprint e `expires` non superata imposta `accettato`. Eccezione scaduta ignorata con avviso. Confronto di data con `Clock`, casi di confine inclusi.
- Spec: §8. ADR: 0014.

#### K-10 — Controllo strutturale dei SARIF dei plugin
- Agente: `backend`. Stato: `LIBERO`.
- Percorsi: `packages/ca-core/src/ca_core/sarif/`.
- Dipende da: K-01, C-05.
- Accettazione: la CLI non conosce il valore del segreto, quindi il controllo è strutturale. Per ogni plugin, la chiave `snippet` a qualunque profondità fa fallire il plugin. Per gitleaks, anche `message` conforme al modello oscurato e `partialFingerprints` privo di `email`, `author` e `commitMessage`. Test con i campioni di V-04 di bandit, semgrep e gitleaks, che contengono `snippet` e devono essere rifiutati.
- Spec: §15. ADR: 0012.

#### K-11 — Livelli provvisori e ordinamento
- Agente: `backend`. Stato: `IPOTESI` (D-0009-A).
- Percorsi: `packages/ca-core/src/ca_core/scoring/levels.py`.
- Dipende da: C-01.
- Accettazione: tabella di ADR-0009 in dati e non nella logica, intervalli CVSS semiaperti verificati ai confini, `level_source` valorizzato, `impact` e `score` nulli. Ordinamento deterministico per livello, categoria, fingerprint.
- Spec: §13, §16 regola 3. ADR: 0009, 0012.

#### K-12 — Motore della policy licenze
- Agente: `backend`. Stato: `LIBERO`.
- Percorsi: `packages/ca-core/src/ca_core/policy/licenses.py`.
- Dipende da: C-01, C-03, K-06.
- Accettazione: semantica `AND`/`OR`, entrambe le fonti, licenze ignote `medio`, tabella dei casi di ADR-0013. Nessun elenco predefinito nel codice; `licenses` assente è segnalato nel report. Eventuale libreria di espressioni SPDX verificata per licenza e manutenzione.
- Spec: §8, §13, §16 regola 2. ADR: 0013.

#### K-13 — Valutazione del gate
- Agente: `backend`. Stato: `IPOTESI` (D-0009-A).
- Percorsi: `packages/ca-core/src/ca_core/pipeline/`.
- Dipende da: C-04, K-11.
- Accettazione: funzione pura sul report con precedenza `--fail-on`, `gate.block_on`, `critico,alto`; eccezioni escluse; scansione parziale, o con un plugin `signature: skipped` (ADR-0005), esce con 2 salvo `--allow-partial`.
- Spec: §8, §9.1. ADR: 0009, 0010.

#### K-14 — SARIF aggregato
- Agente: `backend`. Stato: `LIBERO`.
- Percorsi: `packages/ca-core/src/ca_core/sarif/`, `tests/contract/`.
- Dipende da: C-01, C-04, K-01.
- Accettazione: layout di ADR-0011 coperto da test di contratto, validazione prima della scrittura, due esecuzioni producono byte identici. `security-severity` solo con CVSS. Finding senza posizione nelle notifiche.
- Spec: §1, §13. ADR: 0011.

#### K-15 — Passo `prepare_workspace`
- Agente: `backend`. Stato: `LIBERO`.
- Percorsi: `packages/ca-core/src/ca_core/pipeline/`.
- Dipende da: C-06.
- Accettazione: rilevamento di Python e JS/TS su percorso locale tramite `SourceReader`, nessun clone. Ingressi e uscite serializzabili.
- Spec: §5. ADR: 0002.

#### K-16 — Passo `run_plugins` a due stadi
- Agente: `backend`. Stato: `LIBERO`.
- Percorsi: `packages/ca-core/src/ca_core/pipeline/`.
- Dipende da: C-06, C-02.
- Accettazione: con `PluginExecutor` finto, prima i plugin con `outputs.cyclonedx`, poi gli altri con l'SBOM se disponibile. Plugin fallito genera finding `health` `ca.scanner-not-run` e scansione parziale, senza fermare gli altri. Ogni stadio è una sola chiamata a `run_many`, e il secondo parte a primo finito. `ScanAborted` si propaga senza produrre un risultato. L'SBOM montato è il primo valido per nome, indipendentemente dall'ordine di fine. `invalid_output` diventa `outcome: failed` con il `detail` come `failure`, senza prefisso di exit.
- Spec: §5, §7.2. ADR: 0002, 0004, 0007.

#### K-17 — Passo `normalize`
- Agente: `backend`. Stato: `IPOTESI` (D-0009-A).
- Percorsi: `packages/ca-core/src/ca_core/pipeline/`.
- Dipende da: K-05, K-06, K-07, K-08, K-09, K-10, K-11, K-12.
- Accettazione: composizione idempotente: dagli output dei plugin all'elenco ordinato, con esecuzione ripetuta identica.
- Spec: §5. ADR: 0002, 0008, 0009.

#### K-18 — Passo `publish` su file
- Agente: `backend`. Stato: `LIBERO`.
- Percorsi: `packages/ca-core/src/ca_core/pipeline/`.
- Dipende da: K-14, C-04, C-06.
- Accettazione: scrive report e SARIF tramite `ArtifactSink`, con i nomi di ADR-0010 (`code-analyzer.report.json`, `code-analyzer.sarif`, emendamento per R-09), report valido contro `schemas/scan-report.schema.json`.
- Spec: §5. ADR: 0002, 0010, 0011.

### R — Runner `ca-plugins`

#### R-01 — Caricamento dei manifest
- Agente: `backend`. Stato: `IPOTESI` (D-0005).
- Percorsi: `packages/ca-plugins/src/ca_plugins/sdk.py`.
- Dipende da: C-02.
- Accettazione: manifest solo dai dati del pacchetto, mai dal repository analizzato. Rifiuta un manifest senza limite di byte e, se impacchettato, senza digest.
- Spec: §7.1. ADR: 0004, 0005, 0014.

#### R-02 — `OciExecutor`
- Agente: `backend`. Stato: `LIBERO`.
- Percorsi: `packages/ca-plugins/src/ca_plugins/runner.py`.
- Dipende da: C-06, R-01, T-02, V-09.
- Accettazione: Docker e Podman, argomenti come lista senza shell, profilo `hardened-container` completo di `--tmpfs /tmp:rw,noexec,nosuid` e `HOME=/tmp` (emendamento di ADR-0004), `/out` su volume tmpfs per esecuzione, proprietario `65534:65534`, con custodia e copia del solo file dichiarato (ADR-0004, emendamento per R-09), nessuna variabile dell'host al plugin. Senza runtime OCI: exit 2, nessun ripiego. Verificato su T-02.
- Spec: §7.2. ADR: 0002, 0004.

#### R-03 — Lettura sicura di `/out`
- Agente: `backend`. Stato: `LIBERO`.
- Percorsi: `packages/ca-plugins/src/ca_plugins/runner.py`.
- Dipende da: R-02.
- Accettazione: cartella nuova per plugin e per esecuzione, sola lettura di file regolari al primo livello con `O_NOFOLLOW`, limite di byte dal manifest, directory rimossa a fine esecuzione. L'emendamento per R-09 di ADR-0004 sostituisce la lettura diretta con la copia del solo file dichiarato da `docker cp`; i controlli di tipo e dimensione restano. Valori provvisori da V-04; valori finali in X-02.
- Spec: §7.2. ADR: 0004.

#### R-04 — Verifica della firma
- Agente: `backend`. Stato: `IPOTESI` (D-0005).
- Percorsi: `packages/ca-plugins/src/ca_plugins/runner.py`, `packages/ca-plugins/src/ca_plugins/keys/`.
- Dipende da: R-01, V-09.
- Accettazione: verifica con il comando fissato in V-06, poi esecuzione dello stesso digest, mai di un tag. Firma assente o errata, o registry non raggiungibile: exit 2, nessun report e nessun container del lotto, perché `run_many` verifica tutte le immagini prima di avviarne una; uno stadio precedente può aver eseguito immagini verificate (emendamento di ADR-0005). La verifica precede la preparazione in `run` e `sync_feeds`, quindi ogni risultato riporta l'esito reale. `CA_INSECURE_ALLOW_UNSIGNED=1` letta solo dall'ambiente e registrata come `signature: skipped`; il pull per digest avviene anche in quel caso.
- Spec: §7.2. ADR: 0005.

#### R-05 — Livelli di isolamento
- Agente: `backend`. Stato: `LIBERO`.
- Percorsi: `packages/ca-plugins/src/ca_plugins/runner.py`.
- Dipende da: R-02.
- Accettazione: `gvisor` se `runsc` è registrato, altrimenti `hardened-container`, registrato per plugin. `--min-isolation` non soddisfatto esce con 2. Il valore non è mai letto da `.code-analyzer.yml`.
- Spec: §2, §7.2. ADR: 0004, 0014.

#### R-06 — Sincronizzazione dei feed
- Agente: `backend`. Stato: `LIBERO`.
- Percorsi: `packages/ca-plugins/src/ca_plugins/feeds.py`.
- Dipende da: R-02, R-04.
- Accettazione: container con rete e senza workspace né dati derivati dal repository, scaricamento di osv-scanner dagli `all.zip` degli ecosistemi fissati nel manifest, mai con `--download-offline-databases` (emendamento di ADR-0006), snapshot in cache per utente, soglia di età, snapshot precedente con avviso, plugin fallito se nessuno snapshot. Un test verifica l'invariante "codice o rete, mai entrambi". Controllo di spazio durante la sincronizzazione e pulizia con `purge_feeds`: ADR-0006, emendamento per R-09, realizzati in R-09.
- Spec: §7.2, §15. ADR: 0006.

#### R-07 — Parallelismo, timeout, esiti
- Agente: `backend`. Stato: `LIBERO`.
- Percorsi: `packages/ca-plugins/src/ca_plugins/runner.py`, `packages/ca-core/src/ca_core/ports.py`, `packages/ca-core/src/ca_core/fakes.py`, `packages/ca-cli/src/ca_cli/composition.py`.
- Dipende da: R-02, R-03.
- Accettazione: esecuzione parallela nell'adattatore tramite `PluginExecutor.run_many`, risultati nell'ordine delle richieste, al più `max_parallel` container, fissato dalla radice di composizione (emendamento di ADR-0002). Timeout dal manifest, predefinito 10 minuti. Exit non zero (`failed`), timeout (`timeout`) e output non valido (`invalid_output`) danno esito distinto senza fermare gli altri; anche timeout ed errori del client su `create`, `start`, `inspect` sono risultati `failed`. Un'eccezione che annulla la scansione non attende le esecuzioni precedenti nell'ordine e annulla subito quelle non avviate; i container in corso vengono rimossi. Durata registrata.
- Spec: §5, §7.2. ADR: 0002, 0004.

#### R-08 — `SourceReader` locale
- Agente: `backend`. Stato: `LIBERO`.
- Percorsi: `packages/ca-plugins/src/ca_plugins/source.py`.
- Dipende da: C-06.
- Accettazione: legge solo file regolari sotto la radice, workspace o `/out`. Ogni symlink, `..` e percorsi assoluti rifiutati, con test. `SourceTooLarge` per il file oltre il limite (emendamento di ADR-0004).
- Spec: §7.2. ADR: 0001, 0008.

#### R-09 — Chiusura del runner
- Agente: `backend`. Stato: `LIBERO`.
- Percorsi: `packages/ca-plugins/src/ca_plugins/`, `packages/ca-core/src/ca_core/` (`ports.py`, `fakes.py`, `schema_validation.py`, `vendor_schemas/`, `pipeline/publish.py`, `pipeline/exclusions.py`), `packages/ca-cli/src/ca_cli/`, `schemas/vendor`, `tests/`.
- Dipende da: S-01.
- Accettazione: finding critici e alti di S-01 risolti e riverificati da `security`; il rischio residuo è accettato dall'utente (fatto il 2026-11-09, con le condizioni riportate nella sezione delle decisioni). Solo da qui il runner è considerato chiuso. Deve valere, con prova:
  - A-01 `/out`: volume tmpfs per esecuzione con custodia, dimensione `out_tmpfs_bytes`, `--memory` uguale a `resources.memory` più il tmpfs, copia del solo file dichiarato con i controlli su tipo e dimensione, file non dichiarati mai copiati, rimozione di container e volume anche con errori (ADR-0004).
  - A-01 `/feeds`: guardia durante la sincronizzazione su spazio libero, byte e voci, `--ulimit fsize` (ADR-0006).
  - A-02: `count_unreadable` prima del lotto, esito `partial` e avviso `workspace-unreadable` con il solo conteggio; nessun nome di file in report, stdout, stderr (ADR-0004).
  - M-01: `rmtree` riesce su `/out`; `purge_feeds` rimuove gli snapshot scartati. Gli `xfail` strict di `test_t03_out_hostile.py` sono rimossi.
  - M-03: SIGINT, SIGTERM e SIGHUP durante un lotto fermano i container e lasciano exit 2, `cancel_futures=True`, rimozione all'avvio dei soli orfani scaduti, `close()` sempre chiamato dalla CLI (ADR-0004).
  - Schemi: `SchemaStore.packaged()` con SHA ancorato, wheel provato fuori dal repository (ADR-0003).
  - Nome del report: un solo `REPORT_NAME`, nessuna ridenominazione (ADR-0010).
  - Non si dichiara provato ciò che non lo è: Podman e gVisor restano `UNPROVEN` e il comportamento è il fallimento del plugin, mai un ripiego su bind mount.
- Spec: §7.2, §15. ADR: 0003, 0004, 0005, 0006, 0010.

### I — Immagini e rilascio

Nessuna pubblicazione senza approvazione esplicita dell'utente.

#### I-01 — Immagine base dei plugin
- Agente: `devops`. Stato: `LIBERO`.
- Percorsi: `deploy/docker/plugin-base/`.
- Dipende da: V-09.
- Accettazione: base fissata per digest, utente non root, Python standard per gli adattatori, nessun segreto. Funziona con il profilo di V-07.
- Spec: §3, §13. ADR: 0004, 0007.

#### I-02 — Build e firma locali con chiave di test
- Agente: `devops`. Stato: `IPOTESI` (D-0005).
- Percorsi: `deploy/docker/`, `deploy/compose/`.
- Dipende da: I-01.
- Accettazione: Compose con registry locale, immagine costruita e firmata con il digest letto dal registry dopo il push, verificabile con il comando di V-06. Accerta se `--use-signing-config=false` è indispensabile. La chiave privata di test non è nel repository.
- Spec: §7.2, §13. ADR: 0005.

#### I-03 — Immagine CLI
- Agente: `devops`. Stato: `IPOTESI` (D-0005).
- Percorsi: `deploy/docker/cli/`.
- Dipende da: L-04.
- Accettazione: orchestra i plugin come container fratelli con `CA_HOST_WORKSPACE` e `CA_HOST_OUTPUT`, contiene `cosign` a versione fissata, senza plugin al suo interno. Il socket non raggiunge i plugin. Privilegio del socket documentato.
- Spec: §2, §3. ADR: 0004, 0005.

#### I-04 — Prova di impacchettamento
- Agente: `devops`. Stato: `IPOTESI` (D-0005).
- Percorsi: `deploy/docker/`, `packages/ca-plugins/`.
- Dipende da: I-02, I-05, R-01, X-02.
- Accettazione: procedura completa con chiave di test: build e firma delle immagini, digest nei manifest, pacchetto CLI. Il pacchetto risultante supera lo schema con `@sha256:` e T-07.
- Spec: §7.2, §13. ADR: 0005.

#### I-05 — Licenze e SBOM per immagine
- Agente: `devops`. Stato: `LIBERO`.
- Percorsi: `deploy/docker/`.
- Dipende da: I-02, V-02.
- Accettazione: ogni immagine include i file di licenza e ha un SBOM associato, attribuzione di scancode inclusa. Mancanza di uno dei due fa fallire la build.
- Spec: §7.3, §15. ADR: 0015.

#### I-06 — Primo rilascio ufficiale
- Agente: `devops`. Stato: `BLOCCATO` da D-0005, D-0015.
- Percorsi: `deploy/docker/`, `.github/`.
- Dipende da: I-04, O-02, R-09, A-04.
- Accettazione: immagini pubblicate sul registry definitivo con la chiave definitiva, dopo approvazione esplicita dell'utente. Non serve per il Gate 1.
- Spec: §7.2, §15. ADR: 0005, 0015.

### O — CI del progetto

Tutti i controlli esistono già come comandi locali (M-04): la CI li incapsula.

#### O-01 — Workflow di verifica
- Agente: `devops`. Stato: `LIBERO`.
- Percorsi: `.github/workflows/`.
- Dipende da: M-04, C-07.
- Accettazione: esegue i comandi di `AGENTS.md` su ogni PR, permessi minimi, action fissate per SHA, nessuna chiamata di rete nei test.
- Spec: §13, §16. ADR: 0001, 0003.

#### O-02 — Build, firma ed E2E in CI
- Agente: `devops`. Stato: `IPOTESI` (D-0005 per il registry provvisorio).
- Percorsi: `.github/workflows/`.
- Dipende da: O-01, I-04, T-05.
- Accettazione: stessa procedura di I-04 con chiave di test, nessun segreto nei log, E2E verdi.
- Spec: §13. ADR: 0005.

#### O-03 — Job dello snapshot dei feed
- Agente: `devops`. Stato: `LIBERO`.
- Percorsi: `.github/workflows/`.
- Dipende da: O-01, F-05.
- Accettazione: job separato produce lo snapshot e lo pubblica come cache della CI. I job di test non hanno rete verso i feed.
- Spec: §16 regola 7. ADR: 0006.

### P — Plugin

Ogni plugin include manifest, adattatore in Python standard senza importare `ca-core`, `Dockerfile` e test di contratto su output reali (§16 regola 4), con esito della verifica di licenza registrato. syft per primo: stabilisce il modello da ricalcare e produce l'SBOM per lo stadio successivo. D-0015 ferma la pubblicazione delle immagini (I-06), non lo sviluppo né l'uso interno.

#### P-01 — syft
- Agente: `backend`. Stato: `IPOTESI` (D-0015).
- Percorsi: `packages/ca-plugins/src/ca_plugins/builtin/syft/`.
- Dipende da: R-01, I-02, I-05, T-04.
- Accettazione: CycloneDX valido nella versione dichiarata dal manifest, gira con il profilo completo, test di contratto verde.
- Spec: §7.3. ADR: 0004, 0007, 0015.

#### P-02 — osv-scanner: adattatore
- Agente: `backend`. Stato: `IPOTESI` (D-0015).
- Percorsi: `packages/ca-plugins/src/ca_plugins/builtin/osv_scanner/`.
- Dipende da: P-01.
- Accettazione: conversione verificata sui campioni di V-04: SARIF con alias, CVSS e purl, con vettore CVSS e alias dal JSON nativo. Exit 1 con vulnerabilità trovate ed exit 128 senza pacchetti non sono fallimenti dell'adattatore. Lettura preferita dei lockfile. Non gestisce ancora il database. `uri` riscritti come relativi al workspace (emendamento di ADR-0007).
- Spec: §7.3. ADR: 0007, 0008.

#### P-03 — osv-scanner: database
- Agente: `backend`. Stato: `LIBERO`.
- Percorsi: `packages/ca-plugins/src/ca_plugins/builtin/osv_scanner/`.
- Dipende da: P-02, R-06.
- Accettazione: blocco `feeds` nel manifest, scansione con `network: none`, `--offline-vulnerabilities` e `--no-resolve` sul database montato in `/feeds` in sola lettura, CVE di fixture rilevati. Se il log contiene `could not load db` il plugin è fallito, con test su un ecosistema mancante.
- Spec: §7.2. ADR: 0006.

#### P-04 — trivy: adattatore e IaC
- Agente: `backend`. Stato: `IPOTESI` (D-0015).
- Percorsi: `packages/ca-plugins/src/ca_plugins/builtin/trivy/`.
- Dipende da: P-01.
- Accettazione: solo workspace (dipendenze e configurazioni), nessuna scansione di immagini. Configurazione IaC rilevata senza rete. Conversione verificata sui campioni di V-04. Accerta se il JSON nativo fornisce gli alias. `purl` e `category` per ogni risultato, `--scanners vuln,misconfig`, `uri` senza `uriBaseId` (emendamento di ADR-0007).
- Spec: §7.3. ADR: 0007.

#### P-05 — trivy: database
- Agente: `backend`. Stato: `LIBERO`.
- Percorsi: `packages/ca-plugins/src/ca_plugins/builtin/trivy/`.
- Dipende da: P-04, R-06.
- Accettazione: come P-03 per trivy, con i comandi di V-05.
- Spec: §7.2. ADR: 0006.

#### P-06 — scancode
- Agente: `backend`. Stato: `IPOTESI` (D-0015).
- Percorsi: `packages/ca-plugins/src/ca_plugins/builtin/scancode/`.
- Dipende da: P-01.
- Accettazione: output nativo convertito in SARIF con `license_spdx`, un risultato per file con licenza rilevata. L'immagine fissa con un lock `pluggy` < 1.7. Durata registrata sulle fixture e confrontata con V-08.
- Spec: §7.3, §13. ADR: 0007, 0013, 0015.

#### P-07 — gitleaks
- Agente: `backend`. Stato: `IPOTESI` (D-0015).
- Percorsi: `packages/ca-plugins/src/ca_plugins/builtin/gitleaks/`.
- Dipende da: P-01, F-04.
- Accettazione: output grezzo su percorso interno, in `/out` solo SARIF oscurato con l'hash in `properties.secret_sha256`. Storia completa, copertura ridotta segnalata per clone superficiale. `evidence.validity = "unverified"`. Esecuzione senza `--redact` su percorso nel tmpfs interno; niente `snippet`, `email`, `author`, `commitMessage` in `/out`. Git ombra nel tmpfs dell'adattatore, senza `safe.directory` né `--log-opts` (ADR-0012, emendamento per P-07); ogni errore di git nel log, `dubious ownership` compreso, fa fallire il plugin. Test su workspace di altro proprietario: segreto trovato. `tests/integration/test_gitleaks_hostile_repo.py` con `.git/config` ostile: nessun comando eseguito, controllo positivo sullo stesso repository, `.gitleaks.toml` e `.gitleaksignore` ostili senza effetto. Test di contratto su output oscurato.
- Spec: §7.3, §15. ADR: 0007, 0008, 0012.

#### P-08 — bandit
- Agente: `backend`. Stato: `IPOTESI` (D-0015).
- Percorsi: `packages/ca-plugins/src/ca_plugins/builtin/bandit/`.
- Dipende da: P-01.
- Accettazione: immagine con `bandit[sarif]`, esecuzione con `--skip B105,B106,B107`, nessun `snippet` in `/out`. SARIF con `tool_severity`, `uri` relativi al workspace, problemi Python di F-02 rilevati.
- Spec: §7.3. ADR: 0007, 0009.

#### P-09 — Primo set di regole Semgrep
- Agente: `backend`. Stato: `IPOTESI` (D-0015).
- Percorsi: `packages/ca-plugins/src/ca_plugins/builtin/semgrep/rules/`.
- Dipende da: F-02, F-03, V-02.
- Accettazione: regole proprie per le classi di problemi di F-02 e F-03, necessarie perché con `network: none` non si accede al registry e per JS/TS non esiste altro SAST. Nessuna regola copiata dal registry. Nessuna metavariabile interpolata in `message`. Ogni regola ha un caso positivo e uno negativo.
- Spec: §7.3, §13. ADR: 0015.

#### P-10 — semgrep
- Agente: `backend`. Stato: `IPOTESI` (D-0015).
- Percorsi: `packages/ca-plugins/src/ca_plugins/builtin/semgrep/`.
- Dipende da: P-01, P-09.
- Accettazione: mai `--config auto` né registry. Regole incluse più `plugins.semgrep.rules` controllate per contenimento nel workspace. SARIF con `tool_severity` ricavata da `defaultConfiguration.level`, nessun `snippet` in `/out`, `uri` relativi al workspace, `ruleId` uguale all'`id` del file YAML senza prefisso di percorso, tutti i SAST Semgrep di F-02 e F-03 rilevati.
- Spec: §7.3, §8. ADR: 0007, 0014, 0015.

### L — CLI

#### L-01 — Scheletro e radice di composizione
- Agente: `backend`. Stato: `LIBERO`.
- Percorsi: `packages/ca-cli/src/ca_cli/`.
- Dipende da: M-02, C-06.
- Accettazione: comando `code-analyzer` con i soli `scan`, `sbom`, `gate`, `config validate`. Exit code 0, 1, 2. Eventuale libreria CLI verificata per licenza e manutenzione.
- Spec: §9.1, §13. ADR: 0001, 0010.

#### L-02 — `config validate`
- Agente: `backend`. Stato: `LIBERO`.
- Percorsi: `packages/ca-cli/src/ca_cli/`.
- Dipende da: L-01, C-03, K-12.
- Accettazione: controllo offline di schema, espressioni SPDX, date e percorsi, con avviso per la sola variante `-only`. Chiavi inerti segnalate. Exit 0 o 2.
- Spec: §8, §9.1. ADR: 0010, 0013, 0014.

#### L-03 — `sbom`
- Agente: `backend`. Stato: `IPOTESI` (D-0005).
- Percorsi: `packages/ca-cli/src/ca_cli/`.
- Dipende da: L-01, K-03, P-01, R-03, R-04, R-05, R-07.
- Accettazione: `--format cyclonedx`, solo syft, output 1.7 valido. `--format spdx` non esiste.
- Spec: §9.1. ADR: 0007, 0010.

#### L-04 — `scan`
- Agente: `backend`. Stato: `IPOTESI` (D-0005, D-0009-A).
- Percorsi: `packages/ca-cli/src/ca_cli/`.
- Dipende da: L-01, C-04, K-15, K-16, K-17, K-18, R-03, R-04, R-05, R-07, R-08.
- Accettazione: scrive sempre `code-analyzer.report.json` e `code-analyzer.sarif`. `--format` governa solo lo stdout. Exit 0 anche se parziale, 2 senza report valido, mai 1. `--min-isolation` attivo.
- Spec: §5, §9.1, §13. ADR: 0002, 0004, 0010.

#### L-05 — `gate`
- Agente: `backend`. Stato: `IPOTESI` (D-0009-A).
- Percorsi: `packages/ca-cli/src/ca_cli/`.
- Dipende da: L-01, K-13, C-04.
- Accettazione: legge il report, `--fail-on`, `--allow-partial`. Exit 0, 1, 2 secondo ADR-0010. Nessun `--pr` né `--base`.
- Spec: §9.1, §13. ADR: 0009, 0010.

#### L-06 — Documentazione utente
- Agente: `backend`. Stato: `IPOTESI` (D-0009-A).
- Percorsi: `doc/utente/`.
- Dipende da: L-02, L-03, L-04, L-05.
- Accettazione: comandi, exit code, `.code-analyzer.yml`, requisiti (runtime OCI, `cosign`). Limiti dichiarati: livelli provvisori che cambieranno in Fase 2, isolamento inferiore fuori dal server, report da trattare come riservati, `approved_by` non autenticato, copertura SAST limitata.
- Spec: §17. ADR: 0004, 0008, 0009, 0014, 0015.

#### L-07 — Feed in `scan` e `--offline`
- Agente: `backend`. Stato: `LIBERO`.
- Percorsi: `packages/ca-cli/src/ca_cli/`.
- Dipende da: L-04, R-06, P-03, P-05.
- Accettazione: sincronizza se lo snapshot manca o è vecchio, `--offline` lo impedisce, origine e data dello snapshot nel report.
- Spec: §7.2, §9.1. ADR: 0006, 0010.

### S — Sicurezza

`security` lavora in sola lettura: restituisce i finding e `architect` li registra in `doc/verifiche/sicurezza-fase-1.md`.

#### S-01 — Rischio residuo di sandbox e firma
- Agente: `security`. Stato: `IPOTESI` (D-0005).
- Percorsi: lettura di `packages/ca-plugins/`, `deploy/docker/`; esito in `doc/verifiche/sicurezza-fase-1.md`.
- Dipende da: R-01, R-02, R-03, R-04, R-05, R-07, R-08, T-03, I-02, V-09.
- Accettazione: finding per gravità su: exploit del parser di uno scanner con contenuto ostile senza kernel intermedio, confine `/out`, limiti di risorse, verifica prima dell'esecuzione, ordine digest e firma, `CA_INSECURE_ALLOW_UNSIGNED`, socket del daemon nella modalità immagine CLI. Dichiarazione del rischio residuo da sottoporre all'utente per D-0004.
- Spec: §7.2, §15. ADR: 0004, 0005.

#### S-02 — Altri rischi residui
- Agente: `security`. Stato: `LIBERO`.
- Percorsi: lettura di `packages/`; esito in `doc/verifiche/sicurezza-fase-1.md`.
- Dipende da: L-04, K-10, T-06.
- Accettazione: finding su hash di segreti a bassa entropia e riservatezza dei report, snapshot avvelenato, indebolimento di gate ed eccezioni modificando `.code-analyzer.yml` nel branch, input ostile a SARIF e CycloneDX.
- Spec: §15. ADR: 0006, 0008, 0012, 0014.

### X — Misura e chiusura

#### X-01 — Registrare i 3 repository pilota
- Agente: `architect`, su scelta dell'utente. Stato: `IPOTESI` (regola di misura proposta per D-0009-B).
- Percorsi: `doc/verifiche/gate-1.md`.
- Dipende da: nessuno.
- Accettazione: i 3 pilota `fastapi/full-stack-fastapi-template`, `excalidraw/excalidraw`, `saleor/saleor`, ciascuno con SHA di commit fissato, clone completo, dimensione e linguaggi; macchina di riferimento, regola di misura.
- Spec: §13. ADR: 0009.

#### X-02 — Valori dei limiti di byte
- Agente: `backend`. Stato: `LIBERO`.
- Percorsi: `packages/ca-plugins/src/ca_plugins/builtin/*/plugin.yaml`.
- Dipende da: T-05, T-08.
- Accettazione: ADR-0004 chiede di fissare i limiti nel piano, ma senza output reali non ci sono valori. Il piano fissa il metodo: dimensione massima misurata sulle fixture per plugin, con un margine dichiarato e motivato. I valori stanno nei manifest e i pilota li confermano in X-04.
- Spec: §7.2. ADR: 0004.

#### X-03 — Applicare l'elenco licenze approvato
- Agente: `test`. Stato: `LIBERO`.
- Percorsi: `.code-analyzer.yml`.
- Dipende da: F-06.
- Accettazione: blocco `licenses` con i valori decisi in D-0013 e `config validate` verde. Stessa configurazione indicata per i pilota. §18 aggiornata da `architect`.
- Spec: §8, §18. ADR: 0013.

#### X-04 — Scansione dei repository pilota
- Agente: `test`. Stato: `LIBERO`.
- Percorsi: `doc/verifiche/gate-1.md`.
- Dipende da: X-01, I-04, L-05, L-07, R-09.
- Accettazione: CLI impacchettata, 3 report `complete` e durata totale < 10 minuti per ciascuno, secondo la regola di X-01. Si registrano solo durate e conteggi: i report dei pilota sono riservati e non si committano. Limiti di byte confermati, inclusi i valori provvisori di ADR-0004 e ADR-0006 (emendamenti per R-09): dimensione del tmpfs di `/out` e margine, `FEEDS_MIN_FREE_BYTES`, `DEFAULT_MAX_BYTES`, costo dei container in più.
- Spec: §13. ADR: 0004, 0009, 0010.

#### X-05 — Auto-analisi
- Agente: `test`. Stato: `IPOTESI` (D-0009-A).
- Percorsi: `doc/verifiche/gate-1.md`.
- Dipende da: F-06, L-05, L-07, T-08.
- Accettazione: Code Analyzer sul proprio monorepo non produce finding Critici o Alti con `--fail-on critico,alto`. Fixture e `golden-set/` esclusi con `paths.exclude`.
- Spec: §17. ADR: 0009, 0014.

#### X-06 — Esito del Gate 1
- Agente: `architect`. Stato: `LIBERO`.
- Percorsi: `doc/verifiche/gate-1.md`.
- Dipende da: X-04, T-05, T-08.
- Accettazione: G1.a, G1.b, G1.c riportati con evidenza, valore misurato ed esito. Eventuali scostamenti vanno all'utente: i valori sono da confermare dopo il pilota (§13).
- Spec: §13. ADR: 0009.

#### X-07 — Chiusura della Fase 1
- Agente: `architect`. Stato: `IPOTESI` (tutte le decisioni con effetto sulla fase).
- Percorsi: `doc/plan/fase-1.md`, `doc/verifiche/gate-1.md`.
- Dipende da: X-05, X-06, T-06, T-07, S-02, L-06, I-03, O-01, O-02, A-02, A-03.
- Accettazione: voci di §13 e di §17 spuntate con evidenza, copertura ≥ 80% su `ca-core`, D-0013 e D-0015 riportate come chiuse o rinviate con il loro proprietario. ADR-0002, 0007, 0008, 0010, 0011, 0014 portati ad `Accettato` con le prove elencate in "Revisione A-01", o riaperti con motivo.
- Spec: §13, §17. ADR: tutti.

## 7. Percorso critico

Calcolato sul grafo delle dipendenze, in numero di task: non ci sono stime di durata. La catena più lunga verso l'esito del Gate 1 conta 16 task:

`V-01` → un task tra `V-02..V-08` → `V-09` → `C-02` → `C-04` → `C-07` → `T-04` → `P-01` → `P-02` o `P-04` → `P-03` o `P-05` → `F-05` → `T-08` → `X-02` → `I-04` → `X-04` → `X-06`, poi `X-07` per chiudere la fase.

Il percorso attraversa D-0006 (`P-03`, `P-05`, `F-05`, `T-08`) e D-0009-B (`X-04`, `X-06`): sono le due decisioni che fermano il Gate 1 più a lungo.

Catene quasi critiche, da tenere sotto osservazione:

- Runner e CLI: `V-09` → `C-02` → `R-01` → `R-02` → `R-03` → `R-07` → `L-04` → `T-05` → `T-08`.
- Sicurezza: `R-07` → `T-03` → `S-01` → `R-09` → `X-04`, che attraversa D-0004.

## 8. Primi task avviabili

Senza alcuna decisione dell'utente e senza dipendenze aperte: V-01 e M-01. Subito dopo, in parallelo: V-02..V-08, M-02, M-03, M-05.

In tutto sono 18 i task che non toccano e non ereditano alcuna decisione dell'utente: V-01..V-09, M-01..M-06, C-05, I-01, A-01.

I task `IPOTESI` possono partire senza attendere l'utente, secondo le raccomandazioni degli ADR. I primi, C-01 e C-03, hanno un costo minimo se la raccomandazione cade: un campo da togliere da uno schema senza consumatori. D-0004 e D-0006 sono decise (sezione 3), quindi R-02, P-01, P-02 e P-04 non dipendono più da una risposta dell'utente.
