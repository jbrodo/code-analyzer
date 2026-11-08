# ADR-0007: Adattatori nell'immagine, ordine dei plugin e versioni dei formati

- Stato: Proposto; confermati il 2026-11-08 in revisione tecnica (A-01) manifest e proprietà SARIF. Adattatori e due stadi non esistono ancora (P-01..P-10, K-16)
- Data: 2026-11-08
- Decisione umana richiesta: no (scelta tecnica; da confermare in revisione)
- Riferimenti: §1, §3, §5, §7.1, §7.2, §7.3

## Contesto

Lacune non elencate, su tre punti.

1. §7.1 impone output SARIF o CycloneDX, ma non tutti gli scanner li emettono con le informazioni necessarie: scancode non produce SARIF e le rilevazioni di licenza per file non hanno un posto naturale in CycloneDX; osv-scanner può perdere in SARIF CVSS e alias; gitleaks include il segreto se non si oscura.
2. §5 esegue i plugin in parallelo, ma `inputs.sbom` implica che alcuni seguano syft.
3. §1 e §7.2 fissano CycloneDX 1.7. Gli scanner potrebbero emettere una versione precedente (a quanto noto all'autore, 1.6): lo stato va verificato sulle versioni fissate. Con la regola attuale l'output verrebbe scartato come non valido.

## Opzioni

Per il punto 1:

1. Conversione in `ca-core`: un parser per scanner nel nucleo, che elabora output non standard fuori dalla sandbox.
2. Adattatore dentro l'immagine del plugin: lo scanner viene chiamato e l'output convertito nel contratto di §7.

## Raccomandazione

Opzione 2 per il punto 1.

- Ogni immagine contiene un adattatore in Python standard, senza importare `ca-core`, che invoca lo scanner e scrive SARIF o CycloneDX in `/out`. I parser degli output grezzi restano nel confine isolato.
- Dati aggiuntivi nei `properties` SARIF: `aliases`, `cvss` (versione, vettore, punteggio), `tool_severity`, `license_spdx`, `purl`.
- `ca-core` conosce solo SARIF 2.1.0, CycloneDX e queste proprietà. Tutto l'output del plugin resta non fidato: viene validato al confine, con limiti di dimensione e percorsi confinati al workspace (ADR-0004, ADR-0008).
- Trivy in Fase 1 analizza solo il workspace (dipendenze e configurazioni); la scansione di immagini container resta fuori perché non ha un input definito.

Punto 2: due stadi. Prima i plugin con `outputs.cyclonedx` non nullo, poi gli altri in parallelo; `inputs.sbom: optional` riceve l'SBOM se disponibile. osv-scanner legge di preferenza i lockfile.

Punto 3: distinguere ingresso e uscita.

- Ogni manifest dichiara la versione CycloneDX che emette, e `ca-core` valida contro lo schema di quella versione, fra quelle ammesse.
- L'SBOM prodotto da Code Analyzer è sempre 1.7. Il principio di §1 vale per l'output del prodotto.
- Una versione non ammessa o un output non conforme fanno fallire il plugin (§7.2).

Plugin fallito: finding `health` con `rule_id` `ca.scanner-not-run`, senza percorso, e scansione parziale (§5, §7.2).

## Conseguenze

- Ogni adattatore richiede test di contratto su output reali (§16 regola 4), inclusi output oscurati per gitleaks.
- §7.2 va precisato sulle versioni CycloneDX ammesse in ingresso.
- Se uno scanner non fornisce CVSS o alias nell'output standard, l'adattatore legge il suo formato nativo.

## Emendamento dopo V-09

Data: 2026-11-08. Riporta gli esiti di V-03, V-04 e V-07. Le opzioni raccomandate non cambiano; l'ipotesi del punto 3 del Contesto (emissione in 1.6) è smentita.

- CycloneDX: syft 1.57.0 e trivy 0.76.2 emettono già 1.7. Versione in ingresso per la Fase 1: 1.7. La 1.6 si aggiunge solo se un manifest la dichiara. K-03 si riduce alla validazione. Resta valida la distinzione tra ingresso e uscita.
- osv-scanner: il SARIF ha il punteggio in `security-severity`, ma né vettore né versione CVSS, e gli alias in `deprecatedIds`. Per la proprietà `cvss` serve il JSON nativo (`severity`), che porta anche `groups[].aliases`. L'adattatore usa quel formato come fonte di `cvss` e `aliases`.
- trivy: il SARIF ha `cvssv3_baseScore` e `cvssv3_vector` sulla regola, nessun alias. Il JSON nativo non è stato campionato: P-04 accerta se offre alias, e T-08 verifica la fusione con osv-scanner.
- semgrep: la severità è in `defaultConfiguration.level` sulla regola, non sul risultato. L'adattatore la porta in `tool_severity`.
- bandit: il formato SARIF richiede l'extra `bandit[sarif]` nell'immagine.
- scancode 32.5.0 non si avvia con `pluggy` 1.7.0, che è la versione risolta senza vincoli: l'immagine fissa `pluggy` con un lock a una versione inferiore a 1.7 (provate 1.5.0 e 1.6.0).
- Exit degli adattatori: osv-scanner esce con 1 quando trova vulnerabilità, ma R-07 tratta un exit non zero del container come fallimento. Ogni adattatore esce con 0 se ha scritto l'output del contratto e con un valore non zero se lo scanner è fallito.
- Nessun adattatore scrive `snippet` in `/out` (ADR-0012).

## Emendamento dopo A-01

Data: 2026-11-08. Esito della revisione delle proprietà SARIF e di `outputs`. Le opzioni raccomandate non cambiano.

Il contratto vale per `results[].properties`. Le proprietà su `run` e sulle regole non sono lette dal nucleo.

- `extra="forbid"` al posto di `extra="allow"`. Gli adattatori riscrivono comunque il SARIF: togliere le chiavi fuori contratto (`tags`, `issue_severity`, ...) è parte di quel passaggio. Un insieme chiuso rende impossibile portare dati verso il report con una chiave sconosciuta, compresi dati personali e valori di segreti (ADR-0012), e rende visibile un errore di battitura come `alias`, che altrimenti impedirebbe in silenzio la fusione.
- Nuove proprietà: `category` (valori di `Category`, obbligatoria se il manifest dichiara più di una categoria; oggi trivy, `dependency` e `iac`) e `secret_sha256` (`^[0-9a-f]{64}$`, obbligatoria per la categoria `secret`, valore di ADR-0008). `secret_sha256` si usa solo per il fingerprint e non si copia in `evidence` né nel report.
- `purl` è obbligatorio per la categoria `dependency`: il SARIF di osv-scanner e di trivy non lo porta, lo ricava l'adattatore. `aliases` può contenere anche `ruleId`.
- Gli `uri` in `/out` sono relativi alla radice del workspace, senza `uriBaseId`. Oggi bandit e osv-scanner emettono `file:///workspace/…`, semgrep `/workspace/…`, trivy un `uriBaseId`: li riscrive l'adattatore. Un URI assoluto che arriva al nucleo fa fallire il plugin (ADR-0008).
- `ruleId` non dipende da dove stanno le regole. semgrep prefissa l'id con il percorso della directory di configurazione: l'adattatore lo riporta all'`id` del file YAML, altrimenti spostare `rules/` cambia il fingerprint e invalida le eccezioni.
- trivy si esegue con `--scanners vuln,misconfig`: i risultati di licenza (`lodash:MIT` nel campione) non sono previsti in questa fase e diventerebbero finding `dependency` falsi.
- Due stadi: un plugin con `outputs.cyclonedx` è del primo stadio e non può dichiarare `inputs.sbom: optional`, perché non riceverebbe mai l'SBOM. Lo schema lo vieta.
- `cyclonedx_version` in `outputs`: confermato, è la dichiarazione richiesta dal punto 3.
- `languages` vuoto significa "indipendente dal linguaggio", non "nessun linguaggio": confermato. L'errore costa un'esecuzione in più, mentre un plugin saltato è un falso negativo.

## Revisione A-01

Data: 2026-11-08. Resta `Proposto`: i contratti ci sono, gli adattatori no.

Confermato:

- `plugin-manifest`: `cyclonedx_version`, percorsi di output, `outputs.cyclonedx` incompatibile con `inputs.sbom: optional`, forma impacchettata con digest.
- `plugin-sarif-properties`: oggetto chiuso con le proprietà degli emendamenti. `ca_core/formats.py` ammette in ingresso solo CycloneDX 1.7.
- Gli esiti di V-09 riportati sopra.

Da provare:

- `ca_plugins/builtin/` non esiste: adattatore nell'immagine, riscrittura degli URI, `ruleId` stabile, exit (P-01..P-10, con T-04).
- Due stadi e `inputs.sbom`: K-16.
- Finding `health` `ca.scanner-not-run` e scansione parziale: K-16, K-17.

`secret_sha256` per la categoria `secret` e `purl` per `dependency` sono obbligatori, ma oggi non li controlla né lo schema né il modello. Lo schema può esprimerli quando `category` è presente (emendamento di C-05). Se `category` manca perché il manifest ne dichiara una sola, il controllo spetta alla normalizzazione (K-05).
