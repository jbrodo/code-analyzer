# ADR-0007: Adattatori nell'immagine, ordine dei plugin e versioni dei formati

- Stato: Proposto
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
