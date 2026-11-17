# Code Analyzer: guida della CLI

La CLI `code-analyzer` analizza una directory con scanner open source eseguiti in container, e decide da un report se la scansione supera il gate. In Fase 2 sa anche confrontare una PR con una baseline, commentare la PR su GitHub e produrre i report nativi di GitLab.

Altre pagine: [modalità PR e baseline](pull-request.md), [GitHub: Action, commento e check run](ci-github.md), [GitLab: componente e report nativi](ci-gitlab.md), [livelli, punteggi e varianti](livelli-e-punteggi.md).

**Stato.** Non esiste ancora un rilascio: il pacchetto si costruisce con `deploy/docker/package-cli.sh`, che firma le immagini con una chiave di prova su un registry locale (D-0005).

## Requisiti

- Python 3.14 o successivo per la CLI.
- Runtime OCI: daemon Docker raggiungibile.
- `cosign` v3.1.4, nel `PATH` o indicato da `COSIGN=/percorso/cosign`.
- Chiave pubblica di verifica delle immagini in `CA_COSIGN_PUBLIC_KEY`. Senza chiave `scan` esce con 2.
- Rete solo per sincronizzare i feed di vulnerabilità, salvo `--offline`.

`CA_INSECURE_ALLOW_UNSIGNED=1` salta la verifica della firma, solo per sviluppo locale: il report registra `signature: skipped` e `gate` esce con 2.

`--help` e `config validate` funzionano anche senza runtime.

## Immagine CLI

In alternativa all'installazione, la CLI gira in un container che avvia i plugin come container fratelli attraverso il socket del daemon. Montaggi, variabili `CA_HOST_WORKSPACE`, `CA_HOST_WORK` e `CA_HOST_CACHE`, e il privilegio che il socket comporta sono in `deploy/docker/cli/README.md`. Non esiste ancora un'immagine pubblicata: si costruisce con `deploy/docker/cli/build-cli-image.sh`.

## Comandi

| Comando | Cosa fa | Exit |
| --- | --- | --- |
| `scan [PATH] [--output-dir DIR] [--format table\|json\|sarif] [--min-isolation LIVELLO] [--offline] [--pr --base COMMIT --baseline FILE …] [--variant A\|B] [--scoring-config FILE] [--service-context FILE]` | Analizza `PATH` (predefinito `.`) e scrive gli artefatti | 0 report prodotto, anche parziale; 2 nessun report |
| `gate [--report FILE] [--fail-on LIVELLI] [--allow-partial]` | Decide dal report | 0 superato; 1 fallito; 2 errore o scansione non valutabile |
| `config validate [PATH]` | Controlla `.code-analyzer.yml` offline: schema, espressioni SPDX, date, percorsi | 0 valido; 2 non valido |
| `sbom [PATH] [--format cyclonedx] [--output FILE]` | Genera con syft l'SBOM CycloneDX 1.7 di `PATH`, su stdout o in `FILE` | 0 SBOM prodotto; 2 errore |
| `notify --provider github [--report FILE] [--no-comment] [--no-check-run] [--max-findings N] [--max-annotations N]` | Scrive il commento sulla PR e la check run dal report (token in `GITHUB_TOKEN`) | 0 fatto o saltato con avviso; 2 errore; mai 1 |
| `export --format gitlab [--report FILE] [--sbom FILE] [--output-dir DIR]` | Scrive i report nativi di GitLab dal report | 0 fatto; 2 errore |

Le opzioni di PR sono in [pull-request.md](pull-request.md). `scan`, `notify` ed `export` non escono mai con 1: a decidere è solo `gate`. Un'interruzione o un errore inatteso danno sempre 2.

### `scan`

Scrive sempre `code-analyzer.report.json` e `code-analyzer.sarif` in `--output-dir`, sovrascrivendo quelli di un lancio precedente. `--format` riguarda solo lo stdout.

`--min-isolation` accetta `hardened-container` o `gvisor`: se il livello non è disponibile, `scan` esce con 2 prima di avviare i container. Il livello effettivo è registrato nel report per ogni plugin.

Senza `--offline` i feed si sincronizzano in `~/.cache/code-analyzer/feeds` (o sotto `XDG_CACHE_HOME`). Con `--offline` si usa lo snapshot esistente, anche vecchio, con l'avviso `feeds-stale`; se manca, il plugin risulta fallito e la scansione parziale.

Il report è `partial`, e quindi non supera il gate, quando:

- un plugin fallisce o nessun plugin viene eseguito (`no-plugin-run`);
- alcuni percorsi non sono leggibili dai plugin (`workspace-unreadable`);
- ci sono collegamenti simbolici il cui contenuto non viene analizzato (`workspace-symlinks`): quelli a file e quelli a directory che escono dalla directory scansionata o finiscono in un percorso escluso. Vale qualunque sia il nome, anche se il link è innocuo: se è atteso, escludilo con `paths.exclude`. Analizzando una sottodirectory di un monorepo, un link come `shared -> ../../shared` rende quindi parziale la scansione.

Scanner eseguiti, ciascuno nel proprio container firmato; un plugin il cui linguaggio non è presente viene saltato con l'avviso `plugin-skipped`:

| Plugin | Cosa analizza | Categoria |
| --- | --- | --- |
| syft | SBOM dei componenti | (SBOM) |
| osv-scanner, trivy | Vulnerabilità delle dipendenze | `dependency` |
| scancode | Licenze | `license` |
| gitleaks | Segreti, anche nella storia git | `secret` |
| bandit (Python), semgrep (Python, JavaScript, TypeScript) | Problemi di sicurezza nel codice | `sast` |
| ruff (Python), eslint (JavaScript, TypeScript) | Qualità del codice | `quality` |
| checkov, hadolint | Configurazioni IaC (Dockerfile, Kubernetes, Terraform) | `iac` |
| coverage | File con copertura di riga bassa, dai report LCOV o Cobertura prodotti dalla CI | `test` |
| ca-graph | Grafo dei moduli (Python, JS, TS) e smell architetturali: dipendenza ciclica, hub, instabile | `architecture` |

I repository possono solo **spegnere** regole di checkov, hadolint, ruff ed eslint (`plugins.<nome>.disable_rules`); il report le elenca. `coverage` legge i report indicati in `plugins.coverage.reports` (`path`, `format`, `base_dir`): senza, non trova nulla. Segnala i file con almeno 20 righe e copertura inferiore al 50%; le soglie non sono ancora configurabili. Finding di strumenti diversi sullo stesso problema nello stesso file ricevono un gruppo di correlazione (`correlation`), senza cambiare livello né esito del gate. La distribuzione dell'immagine di hadolint è ancora un tema aperto.

### `sbom`

Scrive solo l'SBOM, validato contro lo schema CycloneDX 1.7: nessun report. Tiene conto di `.code-analyzer.yml`, ma non di `plugins.disable`. Percorsi non leggibili e collegamenti simbolici non analizzati producono un avviso su stderr, e l'exit resta 0: l'SBOM è incompleto.

### `gate`

Legge il report (predefinito `code-analyzer.report.json` nella directory corrente). La soglia di blocco viene, in quest'ordine, da `--fail-on`, da `gate.block_on` registrato nel report, oppure è `critico,alto`.

I livelli sono `critico`, `alto`, `medio`, `basso`. `--fail-on ""` è una scelta esplicita: nulla blocca. I finding con un'eccezione attiva non contano.

`gate` stampa su stderr gli avvisi del report, una riga per codice (`avviso del report: <codice>`), senza cambiare l'exit code: controllali nel log, perché segnalano anche una copertura ridotta.

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
  mode: all                   # all | new-findings-only (solo in una scansione di PR con baseline valida)
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

`service` e `scoring` (solo `variant`) sono attive: vedi [livelli-e-punteggi.md](livelli-e-punteggi.md). `agents` viene validata ma non ha effetto; il report la elenca come sezione inerte.

Il file non può decidere immagini, firma, isolamento, rete, montaggi, comandi dei plugin o origine dei feed.

## Limiti da conoscere

**Livelli provvisori.** I livelli che decidono il gate derivano ancora dalla severità degli scanner e dalle policy: una vulnerabilità non raggiungibile con CVSS alto blocca comunque. I punteggi A e B si calcolano in ombra e stanno nel report; quando il livello da punteggio diventerà attivo molti finding cambieranno livello, una volta sola (vedi [livelli-e-punteggi.md](livelli-e-punteggi.md)).

**Isolamento.** Fuori da un server i plugin girano in container rafforzati, con isolamento inferiore a gVisor. Il rischio residuo è accettato per CI effimere e uso locale, non per runner persistenti condivisi senza gVisor.

**Report riservati.** Report e SARIF descrivono debolezze e percorsi del repository: trattali come dati riservati. I file sono scritti con permessi 0600. Da un fingerprint di segreto presente nel report si può risalire per forza bruta a un segreto debole: limita l'accesso; `gate` non stampa il fingerprint dei segreti.

**Feed.** Uno snapshot dei feed alterato o molto vecchio riduce i risultati senza effetto sul gate: non condividere la cache con job meno fidati.

**Tempi.** Un repository ostile può far lavorare l'host per decine di minuti: imposta un timeout sul job CI.

**`approved_by` non è autenticato.** È una dichiarazione testuale. Chi modifica il branch può anche indebolire gate, esclusioni ed eccezioni modificando `.code-analyzer.yml`, e `--fail-on` protegge solo la soglia. Il report elenca sempre plugin disattivati, esclusioni ed eccezioni applicate: controllalo.

**Soppressioni in linea.** I commenti `gitleaks:allow`, `nosec` e `nosem` vengono ignorati: per accettare un finding si usa `exceptions`.

**Copertura SAST limitata.** Il set di regole Semgrep è iniziale e copre i problemi noti, non un'analisi ampia. Per JavaScript e TypeScript semgrep è l'unico scanner SAST.

**Storia git.** Con un clone superficiale la storia analizzata da gitleaks è ridotta. Il report lo indica con `repository.history: shallow` e con l'avviso `plugin-history-coverage-reduced`, senza effetto sul gate: in CI usa un clone completo. Senza una cartella `.git` l'avviso è `plugin-no-git-history`.

**Ecosistemi non coperti.** osv-scanner controlla solo le dipendenze npm e PyPI. Se il repository contiene dipendenze di un altro ecosistema, per esempio un `pom.xml` di Maven, la scansione non fallisce: il report riporta l'avviso `plugin-feeds-ecosystem-missing` con l'ecosistema e il numero di pacchetti non controllati, e il gate può risultare superato.

**Avvisi dei plugin.** Gli avvisi con codice `plugin-<id>` vengono dalle notifiche di uno scanner, indicato in `subject`: il testo è dello scanner, ripulito e troncato.

**Licenze.** Il finding di licenza su un file indica l'intervallo di righe che copre tutte le corrispondenze trovate da scancode nel file, non la singola corrispondenza.

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
| bandit | `B101` (`assert`) nei file di test: cartelle `test`, `tests`, `testing`, file `test_*.py`, `*_test.py`, `conftest.py`. Altrove resta un finding |
| bandit | Directory `.tox`, `.eggs`, `__pycache__`, `CVS`, `.hg`, `.svn` (semgrep le analizza ancora) |
| Vari | Lockfile dentro `node_modules/` o con un nome non standard |
| Vari | Script senza estensione |
| scancode | Directory VCS, `.gitignore`, `.gitattributes` e testo UTF-16 |

Non sono stati verificati il timeout per regola di semgrep e, salvo i casi indicati, gli ecosistemi diversi da npm e PyPI.
