# Code Analyzer: guida della CLI (Fase 1)

La CLI `code-analyzer` analizza una directory con scanner open source eseguiti in container, e decide da un report se la scansione supera il gate.

**Stato.** Non esiste ancora un rilascio: il pacchetto si costruisce con `deploy/docker/package-cli.sh`, che firma le immagini con una chiave di prova su un registry locale (D-0005).

## Requisiti

- Runtime OCI: daemon Docker raggiungibile.
- `cosign` v3.1.4, nel `PATH` o indicato da `COSIGN=/percorso/cosign`.
- Chiave pubblica di verifica delle immagini in `CA_COSIGN_PUBLIC_KEY`. Senza chiave `scan` esce con 2.
- Rete solo per sincronizzare i feed di vulnerabilità, salvo `--offline`.

`CA_INSECURE_ALLOW_UNSIGNED=1` salta la verifica della firma, solo per sviluppo locale: il report registra `signature: skipped` e `gate` esce con 2.

`--help` e `config validate` funzionano anche senza runtime.

## Comandi

| Comando | Cosa fa | Exit |
| --- | --- | --- |
| `scan [PATH] [--output-dir DIR] [--format table\|json\|sarif] [--min-isolation LIVELLO] [--offline]` | Analizza `PATH` (predefinito `.`) e scrive gli artefatti | 0 report prodotto, anche parziale; 2 nessun report |
| `gate [--report FILE] [--fail-on LIVELLI] [--allow-partial]` | Decide dal report | 0 superato; 1 fallito; 2 errore o scansione non valutabile |
| `config validate [PATH]` | Controlla `.code-analyzer.yml` offline: schema, espressioni SPDX, date, percorsi | 0 valido; 2 non valido |
| `sbom [PATH] [--format cyclonedx] [--output FILE]` | Genera con syft l'SBOM CycloneDX 1.7 di `PATH`, su stdout o in `FILE` | 0 SBOM prodotto; 2 errore |

`scan` non esce mai con 1: a decidere è solo `gate`. Un'interruzione o un errore inatteso danno sempre 2.

### `scan`

Scrive sempre `code-analyzer.report.json` e `code-analyzer.sarif` in `--output-dir`, sovrascrivendo quelli di un lancio precedente. `--format` riguarda solo lo stdout.

`--min-isolation` accetta `hardened-container` o `gvisor`: se il livello non è disponibile, `scan` esce con 2 prima di avviare i container. Il livello effettivo è registrato nel report per ogni plugin.

Senza `--offline` i feed si sincronizzano in `~/.cache/code-analyzer/feeds` (o sotto `XDG_CACHE_HOME`). Con `--offline` si usa lo snapshot esistente, anche vecchio, con l'avviso `feeds-stale`; se manca, il plugin risulta fallito e la scansione parziale.

Il report è `partial`, e quindi non supera il gate, quando:

- un plugin fallisce o nessun plugin viene eseguito (`no-plugin-run`);
- alcuni percorsi non sono leggibili dai plugin (`workspace-unreadable`);
- ci sono collegamenti simbolici il cui contenuto non viene analizzato (`workspace-symlinks`): quelli a file e quelli a directory che escono dalla directory scansionata o finiscono in un percorso escluso. Vale qualunque sia il nome, anche se il link è innocuo: se è atteso, escludilo con `paths.exclude`. Analizzando una sottodirectory di un monorepo, un link come `shared -> ../../shared` rende quindi parziale la scansione.

Scanner eseguiti: syft, osv-scanner, trivy, scancode, gitleaks, bandit (Python) e semgrep (Python, JavaScript, TypeScript). Un plugin il cui linguaggio non è presente viene saltato con l'avviso `plugin-skipped`.

### `sbom`

Scrive solo l'SBOM, validato contro lo schema CycloneDX 1.7: nessun report. Tiene conto di `.code-analyzer.yml`, ma non di `plugins.disable`. Percorsi non leggibili e collegamenti simbolici non analizzati producono un avviso su stderr, e l'exit resta 0: l'SBOM è incompleto.

### `gate`

Legge il report (predefinito `code-analyzer.report.json` nella directory corrente). La soglia di blocco viene, in quest'ordine, da `--fail-on`, da `gate.block_on` registrato nel report, oppure è `critico,alto`.

I livelli sono `critico`, `alto`, `medio`, `basso`. `--fail-on ""` è una scelta esplicita: nulla blocca. I finding con un'eccezione attiva non contano.

`gate` esce con 2 con una scansione parziale o con un plugin non firmato. `--allow-partial` valuta comunque i finding presenti e riporta i motivi su stderr.

In CI si fissa la soglia con `--fail-on`, perché `.code-analyzer.yml` è modificabile da chi modifica il branch (vedi i limiti). Il SARIF va caricato prima di `gate`, che può far terminare il job.

```bash
code-analyzer scan . --output-dir out
code-analyzer gate --report out/code-analyzer.report.json --fail-on critico,alto
```

## `.code-analyzer.yml`

Il file è facoltativo e sta alla radice del repository. Le chiavi sconosciute sono un errore.

```yaml
version: 1                    # obbligatoria, sempre 1
languages: [python]           # linguaggi dichiarati
paths:
  exclude: ["tests/fixtures/**"]   # glob relativi al repository
gate:
  mode: all                   # all | new-findings-only (in Fase 1 equivale ad all)
  block_on: [critico, alto]
  warn_on: [medio]            # un livello non può stare in entrambe le liste
licenses:                     # se la sezione manca, le licenze non sono valutate
  forbidden: [AGPL-3.0-only]
  require_approval: [GPL-3.0-only]
  distributed_product: true
plugins:
  disable: [scancode]
  semgrep:
    rules: [regole/semgrep.yaml]   # regole aggiuntive, percorsi relativi al repository
exceptions:
  - fingerprint: "<fingerprint riportato nel report>"
    reason: "Motivo dell'accettazione"
    expires: 2027-06-30       # scaduta, l'eccezione è ignorata con un avviso
    approved_by: "nome"
```

Sono esclusi per impostazione predefinita `node_modules`, `.venv`, `dist`, `.git` (non per gitleaks) e gli artefatti di output.

`service`, `scoring` e `agents` vengono validati ma non hanno effetto in Fase 1; il report li elenca come sezioni inerti.

Il file non può decidere immagini, firma, isolamento, rete, montaggi, comandi dei plugin o origine dei feed.

## Limiti da conoscere

**Livelli provvisori.** In Fase 1 i livelli derivano dalla severità degli scanner e dalle policy, senza punteggio né raggiungibilità: una vulnerabilità non raggiungibile con CVSS alto blocca comunque. In Fase 2 molti finding cambieranno livello.

**Isolamento.** Fuori da un server i plugin girano in container rafforzati, con isolamento inferiore a gVisor. Il rischio residuo è accettato per CI effimere e uso locale, non per runner persistenti condivisi senza gVisor.

**Report riservati.** Report e SARIF descrivono debolezze e percorsi del repository: trattali come dati riservati. Da un fingerprint di segreto, che `gate` stampa anche nei log CI, si può risalire per forza bruta a un segreto debole: limita l'accesso a report e log.

**Feed.** Uno snapshot dei feed alterato o molto vecchio riduce i risultati senza effetto sul gate: non condividere la cache con job meno fidati.

**Tempi.** Un repository ostile può far lavorare l'host per decine di minuti: imposta un timeout sul job CI.

**`approved_by` non è autenticato.** È una dichiarazione testuale. Chi modifica il branch può anche indebolire gate, esclusioni ed eccezioni modificando `.code-analyzer.yml`, e `--fail-on` protegge solo la soglia. Il report elenca sempre plugin disattivati, esclusioni ed eccezioni applicate: controllalo.

**Soppressioni in linea.** I commenti `gitleaks:allow`, `nosec` e `nosem` vengono ignorati: per accettare un finding si usa `exceptions`.

**Copertura SAST limitata.** Il set di regole Semgrep è iniziale e copre i problemi noti, non un'analisi ampia. Per JavaScript e TypeScript semgrep è l'unico scanner SAST.

**Storia git.** Con un clone superficiale la storia analizzata da gitleaks è ridotta. Il report lo indica solo con `repository.history: shallow`, senza un avviso e senza effetto sul gate: in CI usa un clone completo.

**Licenze.** Il finding di licenza su un file indica il percorso ma non la riga.

### Casi in cui i risultati si riducono senza avviso

Un repository può ridurre i risultati di uno scanner nei modi seguenti, e il report non li segnala.

| Scanner | Condizione |
| --- | --- |
| gitleaks | File coperti dall'allowlist predefinita, come `*.png`, `*.bin`, `package-lock.json`, `node_modules/` |
| gitleaks | File con byte NUL nell'analisi della storia git |
| trivy | `# trivy:ignore:*` nei Dockerfile, che non si può disattivare nella versione usata |
| Tutti | Codice sotto un percorso escluso per impostazione predefinita, come `dist/`: il report elenca i pattern, non quanti file toglie |
| trivy, syft | Lockfile corrotto o vuoto: nessun risultato |
| osv-scanner | Alcuni lockfile vuoti o illeggibili, come `{}` o un `poetry.lock` da 0 byte; gli altri lockfile corrotti fanno fallire il plugin, e la scansione diventa parziale |
| semgrep | File JavaScript in UTF-16 |
| trivy, syft | `"dev": true` nel lockfile (osv-scanner mantiene i risultati) |
| bandit | File con errore di sintassi, byte NUL o `coding` inesistente: saltati (semgrep li analizza ancora) |
| bandit | Directory `.tox`, `.eggs`, `__pycache__`, `CVS`, `.hg`, `.svn` (semgrep le analizza ancora) |
| Vari | Lockfile dentro `node_modules/` o con un nome non standard |
| Vari | Script senza estensione |
| scancode | Directory VCS, `.gitignore`, `.gitattributes` e testo UTF-16 |

Non sono stati verificati il timeout per regola di semgrep e, salvo i casi indicati, gli ecosistemi diversi da npm e PyPI.
