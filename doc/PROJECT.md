# Code Analyzer — Guida di implementazione

> Documento operativo per costruire Code Analyzer. Deriva dalla proposta di architettura (artifact "Code Analyzer — Proposta di architettura", rev. 26) e la traduce in struttura del repository, contratti, schemi dati, algoritmi e piano di lavoro con criteri di accettazione.
> Destinatari: team di sviluppo e agenti di coding (questo file può essere usato come base per `AGENTS.md` / `CLAUDE.md`).

---

## 1. Obiettivo del prodotto

Code Analyzer scansiona un repository e restituisce **una lista unica di problemi ordinata per impatto**, ciascuno con i passi per risolverlo.

Copre: qualità del codice, architectural smell, copertura test, sicurezza (SAST, segreti, IaC), dipendenze (SBOM, CVE), licenze, salute del progetto. Nelle fasi successive: ricostruzione dell'architettura, data lineage, osservabilità.

Principi non negoziabili:

1. **Non reinventare gli scanner.** Si orchestrano motori open source; il valore sta in normalizzazione, correlazione e prioritizzazione.
2. **Rilevamento deterministico.** Gli LLM spiegano, filtrano e propongono correzioni; non sono mai l'unica fonte di un finding.
3. **Formati standard.** SARIF 2.1.0 per i finding, CycloneDX 1.7 per SBOM/VEX, SPDX per licenze, purl per i pacchetti.
4. **Stesso codice per SaaS e self-hosted.**
5. **Merge sempre umano.** Nessuna patch generata viene unita senza revisione.

Ambito MVP: **Python e JavaScript/TypeScript**. Fasi successive: Java/Kotlin, Go, C#, Rust.

---

## 2. Stack tecnologico

| Livello | Scelta | Note |
| --- | --- | --- |
| Linguaggio core | Python 3.14 (`requires-python >= 3.14`) | Gestione dipendenze con `uv`; la CI usa la stessa versione |
| Orchestrazione | La CLI esegue i passi del nucleo in sequenza (ADR-0002); il server non esegue scansioni (ADR-0016) | Temporal non è in Fase 2: tornerebbe solo se una fase futura lo richiedesse |
| API | FastAPI + Pydantic v2 | OpenAPI generata e verificata in CI (ADR-0017); nessuna sessione: token OIDC (ADR-0019) |
| UI | React + TypeScript + Vite, gestita con Bun | Pacchetto separato `web/`; in Fase 2 la serve lo stesso processo dell'API (I-03, ADR-0030) |
| Database | PostgreSQL 16, uno schema per tenant (ADR-0018); pgvector dalla Fase 3 | SQLAlchemy 2 e pg8000; migrazioni con Alembic |
| Archivio degli artefatti | Porta `ArtifactStore`: file system (sviluppo e pilota) o S3 generico con il client `boto3` (ADR-0030) | Report, SARIF, SBOM e grafo; nessun server di object storage incluso nel prodotto (MinIO escluso per la sua licenza) |
| Parsing codice | tree-sitter (py-tree-sitter) | Grammatiche Python, JS, TS, TSX |
| Isolamento plugin | `hardened-container` in CI e in locale, gVisor (runsc) dove disponibile; Firecracker non è in Fase 2 (ADR-0004) | Rete disattivata per default |
| Deploy | Fase 2: immagine CLI, immagine del server (API e SPA) e compose di sviluppo; Kubernetes e Helm in Fase 4 | Stesso motore in CI e in locale; il server riceve i report |
| Osservabilità (interna) | Fase 2: metriche OpenTelemetry del server con esportazione OTLP opzionale e spenta (ADR-0016); Collector, Tempo, Loki, Prometheus e Grafana in Fase 4 | |
| Modello decisionale | Laya (Apache 2.0) dietro interfaccia astratta | Alternative: jevos (CPU), Jev (API) |
| LLM generativi | Interfaccia astratta; provider a zero retention o self-hosted | Configurabile per tenant |

---

## 3. Struttura del repository (monorepo)

```
code-analyzer/
├── AGENTS.md                      # regole per agenti di coding (vedi §16)
├── pyproject.toml                 # workspace uv
├── packages/
│   ├── ca-core/                   # modello dati, scoring, normalizzazione
│   │   └── src/ca_core/
│   │       ├── models/            # finding, scan_report, graph, config, scoring_config, plugin_manifest, ...
│   │       ├── pipeline/          # passi della scansione, senza Temporal (ADR-0002): workspace,
│   │       │                      #   run_plugins, normalize, exceptions, baseline, diff_baseline, gate, publish
│   │       ├── policy/            # licenze
│   │       ├── ports.py           # interfacce verso esecutore, sorgenti, artefatti, feed, storia git, baseline
│   │       ├── sarif/             # parser/serializer SARIF 2.1.0
│   │       ├── sbom/              # CycloneDX 1.7 (SPDX 3.0 non in Fase 2)
│   │       ├── fingerprint.py  normalize.py  dedup.py  correlation.py
│   │       ├── schema_export.py  schema_validation.py  vendor_schemas/
│   │       └── scoring/
│   │           ├── base.py        # ScoringContext, Factor, impatto e arrotondamento
│   │           ├── variant_a.py   # G e P della Variante A; exposure.py (E), service.py (C)
│   │           ├── models.py      # A e B in ombra; B coincide con A dove non è definita (ADR-0021)
│   │           ├── levels.py  overrides.py  score.py   # livelli da configurazione, override, ordinamento
│   │           ├── churn.py  reach.py  config.py  default.json   # configurazione di scoring completa
│   │           └── feeds/         # limiti, lettura difensiva e istantanea di EPSS e KEV (ADR-0024)
│   ├── ca-graph/                  # grafo del codice e dell'architettura
│   │   └── src/ca_graph/
│   │       ├── treesitter/        # estrattori per linguaggio, entrypoint, storia git; solo nell'immagine
│   │       ├── deps.py            # grafo dipendenze tra moduli e pacchetti
│   │       ├── smells/            # cyclic, hub-like, unstable dependency
│   │       ├── pagerank.py  reachability.py  step.py  import_names.py
│   │       └── (reconstruct/)     # Fase 4: codice + Helm/K8s/Terraform/CI
│   ├── ca-plugins/                # adattatori verso gli scanner esterni
│   │   └── src/ca_plugins/
│   │       ├── sdk.py  runner.py  signature.py  source.py  hostpaths.py   # contratto (§7), sandbox, firma
│   │       ├── feeds.py           # database offline di osv-scanner e trivy (ADR-0006)
│   │       ├── enrichment.py      # EPSS e KEV: scarico e cache (ADR-0024)
│   │       └── builtin/
│   │           ├── syft/  osv_scanner/  trivy/  scancode/
│   │           ├── semgrep/  bandit/  gitleaks/   # trufflehog fuori da Fase 1 (ADR-0012)
│   │           ├── ruff/  eslint/  checkov/  hadolint/  coverage/   # ADR-0026
│   │           └── ca_graph/      # il grafo gira in un contenitore come gli altri (ADR-0020)
│   ├── ca-cli/                    # comando `code-analyzer`: scan, sbom, gate, notify, export, upload, config validate
│   ├── ca-integrations/           # github/ (client, commento, check run), gitlab/ (report nativi), ADR-0027
│   ├── ca-api/                    # FastAPI (ADR-0016..0019, 0029, 0030)
│   │   └── src/ca_api/
│   │       ├── app.py  routes.py  models.py  problem.py  config.py
│   │       ├── auth/              # token OIDC, ruoli, tenant dall'emittente (ADR-0019)
│   │       ├── db/                # modello, migrazioni (global e per tenant), sessioni per tenant
│   │       ├── storage/           # archivio degli artefatti: file system e S3
│   │       ├── ingest.py  reads.py  findings.py   # ingestione, letture, elenco e triage
│   │       ├── spa.py  telemetry.py  limits.py  manage.py  openapi_export.py
│   ├── ca-decision/               # (Fase 3) motore decisionale (§10)
│   │   └── src/ca_decision/
│   │       ├── interface.py       # DecisionEngine (astratto)
│   │       ├── laya_engine.py
│   │       ├── jevos_engine.py
│   │       ├── jev_engine.py
│   │       └── routing.py         # instradamento per confidenza
│   ├── ca-agents/                 # (Fase 3) agenti LLM sulle 8 fasi (§11)
│   │   └── src/ca_agents/
│   │       ├── contracts/         # schemi JSON input/output per fase
│   │       ├── phases/            # p0_engage … p7_learn
│   │       ├── context/           # contesto persistente (prompt, skill, ADR)
│   │       ├── controls/          # guard, gate, probe
│   │       └── llm.py             # interfaccia provider LLM
│   └── ca-workflows/              # (non in Fase 2, ADR-0016) workflow e activity Temporal
├── web/                           # SPA React: src/{api,auth,features,layout}, token da doc/ux/tokens.json
├── deploy/
│   ├── docker/                    # cli/, server/ (sviluppo e rilascio), plugin-base/, dev-idp/, image-gate.sh, package-cli.sh
│   ├── compose/                   # server-dev.yaml, registry.yaml, dati di prova
│   └── helm/code-analyzer/        # (Fase 4)
├── integrations/
│   ├── github-action/             # action.yml composita (ADR-0027)
│   └── gitlab-component/          # template CI/CD component
├── schemas/                       # JSON Schema pubblici, generati dai modelli (ADR-0003)
│   ├── finding.schema.json  scan-report.schema.json  graph.schema.json
│   ├── plugin-manifest.schema.json  plugin-sarif-properties.schema.json
│   ├── code-analyzer-config.schema.json  scoring-config.schema.json  service-context.schema.json
│   ├── openapi.json               # il contratto dell'API (ADR-0017)
│   ├── vendor/                    # SARIF e CycloneDX fissati
│   └── phases/*.schema.json       # (Fase 3)
├── doc/                           # PROJECT.md, adr/, plan/, utente/, ux/, verifiche/
├── golden-set/                    # (Fase 3) finding annotati per valutazione e training
└── tests/
    ├── unit/  contract/  integration/  e2e/
    └── fixtures/                  # repository di prova (Python, JS/TS), casi dello scoring
```

---

## 4. Modello dati

### 4.1 Finding (modello comune)

```python
# packages/ca-core/src/ca_core/models/finding.py
from enum import StrEnum
from pydantic import BaseModel, Field
from datetime import datetime

class Category(StrEnum):
    QUALITY = "quality"
    ARCHITECTURE = "architecture"
    TEST = "test"
    SAST = "sast"
    DEPENDENCY = "dependency"
    LICENSE = "license"
    SECRET = "secret"
    IAC = "iac"
    HEALTH = "health"

class Level(StrEnum):
    CRITICAL = "critico"
    HIGH = "alto"
    MEDIUM = "medio"
    LOW = "basso"

class Status(StrEnum):
    OPEN = "aperto"
    IN_PROGRESS = "in_corso"
    ACCEPTED = "accettato"
    FALSE_POSITIVE = "falso_positivo"
    RESOLVED = "risolto"

class Location(BaseModel):
    repository: str
    commit: str | None = None                # assente fuori da un repository git
    path: str | None = None
    start_line: int | None = None
    end_line: int | None = None
    purl: str | None = None                  # per le librerie
    dependency_path: list[str] = []          # catena di dipendenza transitiva

class ImpactFactors(BaseModel):
    g: float = Field(ge=0, le=1)             # gravità
    p: float = Field(ge=0, le=1)             # probabilità
    e: float = Field(ge=0, le=1)             # esposizione
    c: float = Field(ge=0, le=1)             # criticità
    variant: str                             # "A" | "B"
    evidence: dict = {}                      # valori grezzi: cvss, epss, kev, pagerank, intensity…

class Finding(BaseModel):
    id: str
    fingerprint: str                         # stabile tra scansioni
    category: Category
    rule_id: str
    tool: str                                # es. "semgrep", "osv-scanner", "ca-graph"
    tools: list[str]                         # tutti i tool che lo riportano, dopo la dedup
    title: str
    message: str
    location: Location
    cwe: list[str] = []
    cve: list[str] = []
    license_spdx: str | None = None
    evidence: dict = {}
    impact: ImpactFactors | None = None
    score: float | None = None               # 0–100
    level: Level | None = None
    level_source: LevelSource | None = None  # tool_severity | policy | default; in Fase 2 anche score | override
    status: Status = Status.OPEN
    owner: str | None = None
    due_date: datetime | None = None
    first_seen: datetime
    last_seen: datetime
```

In Fase 1 non c'è un database: `id` coincide con `fingerprint`, `first_seen` e `last_seen` con l'istante della scansione. `impact` e `score` restano `null` (ADR-0009). La fonte dello schema è il modello in `ca_core` (ADR-0003).

### 4.2 Fingerprint

```python
# fingerprint = sha256(rule_id | tool_family | normalized_location | component)
# normalized_location:
#   - codice: path + hash del contenuto normalizzato della riga e delle 2 righe attorno
#     (non il numero di riga, che cambia a ogni modifica)
#   - librerie: purl senza versione + id vulnerabilità
#   - licenze: purl senza versione + licenza SPDX
```

Regola: due finding con lo stesso fingerprint nella stessa scansione vengono fusi (`dedup.py`), conservando tutte le evidenze e tutti i tool di origine.

### 4.3 Schema relazionale (PostgreSQL)

Tabelle principali (migrazioni Alembic):

| Tabella | Contenuto |
| --- | --- |
| `tenants` | Cliente (SaaS) o istanza unica (self-hosted) |
| `repositories` | URL, provider, branch principale, criticità (tier), servizio di catalogo |
| `scans` | Repository, commit, tipo (PR / completa / notturna), stato, durata, variante di scoring |
| `findings` | Modello §4.1; indice unico `(repository_id, fingerprint)` |
| `finding_occurrences` | Collegamento finding ↔ scansione (storico) |
| `components` | Pacchetti da SBOM (purl, versione, licenza dichiarata/rilevata) |
| `graph_nodes`, `graph_edges` | Grafo moduli/servizi; `edges.confidence ∈ {dichiarato, dedotto, osservato}` |
| `exceptions` | Eccezioni accettate con motivazione e scadenza (anche da `.code-analyzer.yml`) |
| `vex_statements` | Dichiarazioni "non impattato" con giustificazione |
| `decisions` | Log del motore decisionale: domanda, opzioni, probabilità, modello, versione |
| `agent_runs` | Fase, agente, modello, prompt hash, token, esito, controllo superato |
| `golden_labels` | Etichette umane per valutazione e fine-tuning |
| `embeddings` | Snippet di codice + vettore (pgvector) per il recupero contestuale |

Multi-tenancy SaaS: uno schema PostgreSQL per tenant + bucket separato.

---

## 5. Pipeline di scansione

I passi sono funzioni del nucleo chiamate in sequenza dalla CLI, senza Temporal (ADR-0002). In Fase 2 non c'è `ScanWorkflow`: il server non esegue scansioni, riceve il report di una già fatta in CI e ne tiene lo stato (ADR-0016, ADR-0018). Il workflow Temporal tornerebbe solo se una fase futura lo richiedesse. La sequenza è la stessa nelle due letture:

```
1. prepare_workspace     clone (shallow per PR, full per notturna), rilevamento linguaggi
2. resolve_changed_files solo per PR: in Fase 2 non restringe i plugin ai file cambiati (ADR-0025): la PR si scansiona per intero e si legge la baseline
3. run_plugins           in parallelo, ognuno in sandbox; output SARIF / CycloneDX su object storage
4. build_graph           tree-sitter → grafo moduli; smell architetturali
5. normalize             SARIF + CycloneDX → Finding; fingerprint; dedup; applica VEX ed eccezioni
6. enrich                feed EPSS/KEV/OSV; raggiungibilità (ADR-0022); contesto del servizio (C, E: ADR-0028)
7. classify              motore decisionale (§10) sui finding che lo richiedono (Fase 3)
8. score                 variante A o B (§6); livello; override
9. diff_baseline         separa finding nuovi / esistenti / risolti
10. publish              report e SARIF aggregato (CLI); commenti PR e check run (`notify`); invio al server (`upload`); ticket (Fase 3)
11. trigger_agents       solo per finding sopra soglia (§11, Fase 3)
```

Requisiti non funzionali:

- Scansione completa **< 10 minuti** sui repository pilota (Gate 1); scansione PR **< 10 minuti** (Gate 2, condizione G2.d, ADR-0009, ADR-0025): la PR non è ristretta ai file cambiati, e il tempo si misura sull'intera scansione con il confronto con la baseline.
- Ogni passo idempotente; un plugin che fallisce non blocca gli altri, rende la scansione `partial` e produce un finding di tipo `health` ("scanner non eseguito"); `gate` esce con 2 su una scansione parziale (ADR-0009).
- Timeout per plugin configurabile (default 10 min).

---

## 6. Modello di punteggio G·P·E·C

```
Impatto = 100 · G · P · E · C          (G, P, E, C ∈ [0,1])
```

Interfaccia comune:

```python
# packages/ca-core/src/ca_core/scoring/base.py
class ScoringModel(Protocol):
    name: str  # "A" | "B"
    def factors(self, f: Finding, ctx: ScoringContext) -> ImpactFactors: ...
```

La variante attiva si sceglie con `--variant`, poi con `scoring.variant` di `.code-analyzer.yml` (A | B), poi con il file di configurazione di scoring (ADR-0021). Entrambe calcolano sempre i punteggi in modalità "ombra", così da confrontarle (Gate 2): finché la configurazione di scoring ha `levels.source: provisional` (D2-10) i livelli e il gate restano quelli provvisori di ADR-0009 e A e B stanno solo in `variant_scores`. Per `quality` e `architecture` la Variante B coincide con A finché ADR-0023 non la definisce, e il report lo dichiara.

### 6.1 Variante A — generica

I valori numerici sono quelli predefiniti del file di scoring (`ca_core/scoring/default.json`), ipotesi da calibrare in X-02; le definizioni operative di «raggiungibile», «percorso confermato» e churn sono in ADR-0021 e ADR-0022. Un «percorso confermato» è un risultato di una regola `mode: taint` del prodotto, non un `codeFlow` di SARIF.

| Fattore | Calcolo |
| --- | --- |
| G | CVE: `cvss_v4_base / 10`. SAST/IaC/smell: mappa severità regola → {critical 1.0, high 0.75, medium 0.5, low 0.25}. Licenze: vietata in prodotto distribuito 1.0, da approvare 0.6, obbligo di attribuzione mancante 0.3 |
| P | CVE: `1.0` se in KEV, altrimenti `max(epss, 0.01)`. SAST: 0.8 se percorso sorgente→sink confermato, 0.4 altrimenti. Smell/qualità: percentile di churn del file negli ultimi 90 giorni |
| E | 1.0 se raggiungibile da un entrypoint e servizio esposto su internet; 0.6 raggiungibile ma interno; 0.3 raggiungibilità ignota; 0.2 dipendenza solo di sviluppo/test |
| C | Tier del servizio dal catalogo: tier 1 = 1.0, tier 2 = 0.7, tier 3 = 0.4; default 0.7 se catalogo assente |

### 6.2 Variante B — basata sulle pubblicazioni (smell e debito architetturale)

Si applica a `category ∈ {quality, architecture}`; per le altre categorie usa la Variante A.

| Fattore | Calcolo | Riferimento |
| --- | --- | --- |
| G code smell | Indice di intensità: per ogni metrica della regola, quanto il valore supera la soglia, normalizzato in [0,1] con quantili sulla distribuzione di benchmark | Arcelli Fontana et al., MTD 2015 |
| G architectural smell | Severità per tipo (Cyclic, Hub-Like, Unstable Dependency) × dimensione normalizzata (n. componenti coinvolti) | Arcelli Fontana et al., ICSME 2016; ICSAW 2017 |
| P | Combinazione di churn e densità di violazioni di regole di codifica come predittore di change-proneness | Tollin et al., EASE 2017 |
| E | Identico alla Variante A | — |
| C | PageRank del componente sul grafo delle dipendenze, normalizzato in [0,1] | Arcelli Fontana et al., ECSA 2019 |
| Aggregato | Architectural Debt Index per modulo, con trend tra versioni | Roveda et al., SEAA 2018 |

Vincoli di implementazione:

- Motori separati per code smell e architectural smell (non derivare gli uni dagli altri).
- Pesi e soglie esposti in configurazione e mostrati nella UI accanto al punteggio.
- Non presentare gli architectural smell come predittori di bug di concorrenza.

### 6.3 Livelli e override

| Livello | Intervallo | Override che alzano il livello minimo |
| --- | --- | --- |
| Critico | [70, 100] | CVE in KEV e raggiungibile; licenza vietata in prodotto distribuito |
| Alto | [40, 70) | CVE con EPSS ≥ 0.1 raggiungibile; SAST con percorso confermato in servizio esposto |
| Medio | [15, 40) | Architectural smell in un hotspot; copertura < 50% su codice critico modificato spesso |
| Basso | [0, 15) | — |

Il punteggio si arrotonda a due decimali prima di confrontarlo con gli intervalli, che sono semiaperti. Le soglie, i pesi e gli override stanno nel file di configurazione di scoring (`scoring-config`, schema versionato), mai nel codice di `scoring/` e mai in `.code-analyzer.yml`, che è modificabile da chi modifica il branch (ADR-0014): lo cambia il tenant sul server o chi lancia la CLI con `--scoring-config`. Un override alza il livello, non lo abbassa, e non scatta su un dato mancante. L'override «segreto valido esposto» non è applicabile in Fase 2: richiede una verifica online vietata da ADR-0006 e ADR-0012. Test di regressione con la tabella di casi attesi in `tests/fixtures/scoring/cases.json` e proprietà con hypothesis (ADR-0021).

---

## 7. Contratto dei plugin

### 7.1 Manifest

```yaml
# plugin.yaml
apiVersion: code-analyzer/v1
name: semgrep
version: 1.0.0
image: registry.example.com/ca-plugins/semgrep:1.0.0@sha256:...
capabilities: [detect]          # detect | fix | enrich
languages: [python, javascript, typescript]
categories: [sast]
inputs:
  workspace: readonly
  sbom: optional
  config: optional
outputs:
  sarif: /out/results.sarif
  cyclonedx: null
  cyclonedx_version: null       # obbligatorio se c'è `cyclonedx`
  max_bytes: 16777216           # limite di lettura dell'output
resources:
  cpu: "2"
  memory: 2Gi
  timeout: 600s
network: none                   # sempre none: i feed si sincronizzano a parte (ADR-0006)
# feeds:                        # solo per i plugin con database offline
#   sync_command: [python, /opt/ca-plugin/adapter.py, sync, npm, PyPI]
#   ecosystems: [npm, PyPI]
#   mount: /feeds
#   sync_timeout: 900s
```

### 7.2 Regole di esecuzione

- Workspace montato in sola lettura in `/workspace`; output in `/out`.
- Nessuna rete durante l'analisi. I feed si scaricano in un'esecuzione separata e si montano in sola lettura (ADR-0006).
- Isolamento: `gvisor` obbligatorio sul server; `hardened-container` ammesso in CI e in locale (ADR-0004).
- Immagine indicata per digest, firmata con cosign e verificata prima dell'esecuzione (ADR-0005).
- Exit code ≠ 0 → scansione marcata parziale, finding `health` generato.
- Output validato contro lo schema SARIF 2.1.0 o CycloneDX nella versione dichiarata dal manifest, oggi solo 1.7; output non valido o oltre `max_bytes` = plugin fallito.

### 7.3 Plugin built-in per l'MVP

| Plugin | Categoria | Note |
| --- | --- | --- |
| syft | dependency | SBOM CycloneDX |
| osv-scanner | dependency | CVE; remediation guidata per npm |
| trivy | dependency, iac | Vulnerabilità container, config |
| scancode | license | Licenza rilevata nei file |
| semgrep | sast | Regole custom YAML in `rules/` |
| bandit | sast | Python |
| gitleaks | secret | Anche storia git (scansione completa) |
| ruff | quality | Python |
| eslint | quality | JS/TS |
| checkov, hadolint | iac | Dockerfile, K8s, Terraform |
| coverage | test | Import LCOV / Cobertura dalla CI |
| ca-graph (interno) | architecture | Cyclic, Hub-Like, Unstable Dependency |

Verificare la licenza d'uso di ogni motore prima dell'inclusione nell'immagine distribuita.

---

## 8. Configurazione per repository

```yaml
# .code-analyzer.yml
version: 1
languages: [python, typescript]
service:                            # dichiarazione non verificata: vale solo se manca il file di contesto
  catalog_id: payments-api          # (ADR-0028); la fonte attendibile è il server o `--service-context`
  tier: 1
  internet_facing: true
paths:
  exclude: ["tests/fixtures/**"]    # glob relativi; predefiniti per node_modules, .venv, dist, .git
scoring:
  variant: A                        # A | B: solo la scelta; soglie e pesi non stanno qui (ADR-0021)
gate:
  mode: all                         # all | new-findings-only: con una baseline valida blocca solo i nuovi (ADR-0025)
  block_on: [critico, alto]
  warn_on: [medio]
licenses:
  forbidden: [AGPL-3.0-only, AGPL-3.0-or-later, SSPL-1.0]
  require_approval: [GPL-2.0-only, GPL-2.0-or-later, GPL-3.0-only, GPL-3.0-or-later, LGPL-2.1-only, LGPL-2.1-or-later, LGPL-3.0-only, LGPL-3.0-or-later]
  distributed_product: true
plugins:
  disable: []
  semgrep:
    rules: [rules/semgrep/]
exceptions:
  - fingerprint: "sha256:…"
    reason: "Falso positivo confermato: input sanificato a monte"
    expires: 2027-03-31
    approved_by: "@security-lead"
agents:                             # accettata e inerte fino alla Fase 3
  enabled: true
  max_phase: 5                      # oltre la 5 serve abilitazione esplicita
  llm_provider: self-hosted
```

Il file è validato da `schemas/code-analyzer-config.schema.json` (`config validate`, ADR-0014). È un input non fidato, modificabile da chi modifica il branch: per questo non porta le soglie né i pesi dello scoring, il tier o l'esposizione attendibili, la fonte della baseline né il percorso dei file di contesto. Nelle PR vale quello del branch base (ADR-0025). Le eccezioni valgono per il gate della CI; quelle approvate sul server non le legge (ADR-0018).

---

## 9. API e CLI

### 9.1 CLI

```
code-analyzer scan [PATH] [--output-dir DIR] [--format table|json|sarif] [--min-isolation L] [--offline]
                   [--pr [--base COMMIT] [--baseline FILE] [--baseline-source S] [--pull-request N]]
                   [--variant A|B] [--scoring-config FILE] [--service-context FILE]
code-analyzer sbom [PATH] --format cyclonedx [--output FILE]
code-analyzer gate [--report FILE] [--fail-on critico,alto] [--allow-partial]
code-analyzer notify --provider github [--report FILE] [--repo O/N] [--pull-request N] [--head-sha SHA]
code-analyzer export --format gitlab [--report FILE] [--sbom FILE] [--output-dir DIR]
code-analyzer upload --server URL [--report FILE] [--audience A]
code-analyzer config validate
```

Exit code: 0 ok, 1 gate fallito (solo `gate`), 2 errore di esecuzione; `notify` esce con 0 o 2, mai 1. Fuori dalla Fase 2: `sbom --format spdx`, `explain FINDING_ID`, `plugin list|verify|run NAME`, e il comando `service-context` di ADR-0028 (l'endpoint del server c'è, il comando della CLI no). Dettagli in ADR-0010 e nei suoi emendamenti.

### 9.2 API REST (FastAPI)

Il contratto è `schemas/openapi.json`, generato dal codice e verificato in CI (ADR-0017); gli errori sono tutti `application/problem+json` (ADR-0017). Percorsi di Fase 2 (ADR-0029):

| Metodo | Percorso | Scopo | Ruolo |
| --- | --- | --- | --- |
| POST | `/v1/scans` | Riceve il report di una scansione già fatta (report, SARIF, SBOM, grafo): idempotente, con i limiti di dimensione | pipeline |
| GET | `/v1/scans/{id}` | Stato, plugin, avvisi, gate, scoring, baseline | lettore; pipeline del proprio repository |
| GET | `/v1/scans/{id}/sarif` | SARIF aggregato | idem |
| GET | `/v1/repositories` | Repository del tenant con la scansione corrente | lettore |
| GET, PATCH | `/v1/repositories/{id}` | Dettaglio; tier, esposizione e catalogo | lettore; amministratore |
| GET | `/v1/repositories/{id}/scans` | Elenco delle scansioni | lettore |
| GET | `/v1/repositories/{id}/findings` | Filtri: livello, categoria, stato, strumento, nuovi, ricerca; ordinamenti totali; cursore opaco | lettore |
| GET, PATCH | `/v1/findings/{id}` | Dettaglio con le due varianti; stato, owner, eccezione e revoca, con `approved_by` dall'identità autenticata | lettore; triage; approvatore |
| GET | `/v1/repositories/{id}/sbom` | CycloneDX | lettore |
| GET | `/v1/repositories/{id}/graph` | Grafo moduli | lettore |
| GET | `/v1/me`, `/v1/service-context`, `/v1/health` | Identità e ruoli; contesto del servizio per la pipeline; salute | utente; pipeline; nessuno |

Non in Fase 2: `POST /v1/findings/{id}/agents/run` e i webhook (Fase 3). Il server non avvia scansioni (ADR-0016).

Autenticazione: OIDC per utenti (client pubblico con PKCE, token in memoria); OIDC dei provider CI per le pipeline (nessun token a lunga durata); quattro ruoli (`lettore`, `triage`, `approvatore`, `amministratore`) e il tenant dall'emittente (ADR-0019).

---

## 10. Motore decisionale

### 10.1 Interfaccia

```python
# packages/ca-decision/src/ca_decision/interface.py
from typing import Protocol, Literal
from pydantic import BaseModel

class Decision(BaseModel):
    question_id: str
    kind: Literal["boolean", "choice", "score"]
    probabilities: dict[str, float]      # per boolean/choice
    score: float | None = None           # per score
    confidence: float
    model: str
    model_version: str

class DecisionEngine(Protocol):
    def decide(self, question_id: str, question: str, evidence: str,
               options: list[str] | None, kind: str) -> Decision: ...
```

Implementazioni: `LayaEngine` (predefinito), `JevosEngine` (CPU), `JevEngine` (API gestita, per confronto). Le chiamate concrete alle librerie vanno verificate sulla loro documentazione al momento dell'implementazione.

### 10.2 Domande gestite

| `question_id` | Tipo | Evidenza passata (snippet breve) |
| --- | --- | --- |
| `is_true_positive` | boolean | Finding + ±20 righe di codice |
| `smell_category` | choice | Metriche + firma del componente |
| `reachability` | score | Percorso di chiamata parziale |
| `column_data_class` | choice | Nome tabella/colonna + uso nel codice |
| `license_needs_legal` | boolean | Testo licenza rilevato + manifest |
| `route_phase` | choice | Riepilogo finding + livello |

Vincolo: l'evidenza deve stare nel contesto del checkpoint (≈1.024 token per `laya-typed-decisions`; 512 per il checkpoint inglese base). Selezionare gli snippet, mai file interi.

### 10.3 Instradamento per confidenza

```python
def route(d: Decision, low_risk_action: bool, t_high: float, t_low: float) -> str:
    if d.confidence >= t_high and low_risk_action:
        return "auto"          # applica
    if d.confidence >= t_low:
        return "llm_agent"     # agente LLM legge il codice e motiva
    return "human"             # revisione umana
```

Soglie per `question_id`, calibrate sul golden set (curva di affidabilità). Laya va specializzato con fine-tuning sul golden set: in zero-shot è poco sopra il caso. Ogni modello è versionato e fissato; ogni decisione è registrata in `decisions`.

Backend opzionale per sviluppatori su Mac: laya-mlx (solo Apple Silicon), dietro la stessa interfaccia, solo per la CLI.

---

## 11. Agenti LLM — modello operativo a 8 fasi

### 11.1 Fasi, attori e controlli

| Fase | Chi agisce | Input | Output | Controllo che chiude la fase |
| --- | --- | --- | --- | --- |
| 0 · Ingaggio | Agente Q&A + team | Repo, catalogo servizi | `.code-analyzer.yml` proposto | Validazione schema |
| 1 · Triage | Motore decisionale + scoring; agente triage per bassa confidenza | Finding | Stato suggerito, livello, issue | Fingerprint/dedup; soglia di confidenza |
| 2 · Analisi | Agente remediation o architettura | Finding + contesto | Opzioni (upgrade, patch, refactoring, eccezione) con pro/contro | Opzione ammessa dalle policy |
| 3 · Piano | Agente pianificatore | Opzione scelta | Passi, file, test | File entro il perimetro permesso; budget token |
| 4 · Codice | Agente remediation in sandbox | Piano | Diff | Build e test verdi |
| 5 · Verifica | Agente revisore (modello diverso) + scanner | Diff | Verdetto + riscansione | Finding chiuso, nessun finding nuovo, approvazione umana |
| 6 · Rilascio | Pipeline CI/CD | PR approvata | Merge/deploy | Gate CI; rollback disponibile |
| 7 · Apprendimento | Agente di analisi | Esiti, telemetria, falsi positivi | Proposte di nuove regole/controlli e di contesto | Revisione umana della proposta |

### 11.2 Regole

- Input e output di ogni fase sono **contratti JSON** in `schemas/phases/`; un agente è sostituibile senza toccare le altre fasi.
- Nessuna fase viene saltata; un finding Basso può fermarsi alla fase 1.
- La fase 5 usa un agente/modello diverso dalla fase 4.
- La fase 7 non modifica direttamente prompt o regole: apre una PR su `ca-agents/context/` o `controls/`.
- Eventi esterni (PR, alert, PR di Renovate/Dependabot, commenti) entrano dalla fase 1.

### 11.3 Contesto persistente e controlli deterministici

```
ca-agents/context/
├── instructions/      # istruzioni di sistema per fase
├── prompts/           # template versionati
├── skills/            # procedure riusabili (es. "aggiorna dipendenza npm")
├── adr/               # decisioni architetturali del cliente
└── policies/          # licenze, eccezioni, perimetri
ca-agents/controls/
├── guards/            # redazione segreti, perimetro file, budget
├── gates/             # condizioni di chiusura per fase
├── contracts/         # validazione JSON Schema
└── probes/            # build, test, riscansione
```

### 11.4 Guardrail

- Redazione di segreti e dati sensibili prima di ogni prompt.
- Solo gli snippet necessari, recuperati via pgvector.
- Provider LLM a zero retention o self-hosted.
- Budget token per scansione; log completo di prompt e risposte in `agent_runs`.

---

## 12. Integrazioni

### 12.1 GitHub Action

Forma decisa in ADR-0027 e D2-13 (2026-11-17): Action **composita** nella sottocartella del monorepo, `integrations/github-action/action.yml`, usata dalla CI di questo repository; nessun repository dedicato né Marketplace finché vale la decisione del 2026-11-10 sulla pubblicazione. L'immagine della CLI non ha un valore predefinito: `image` e `public-key` (la chiave cosign dei plugin, fuori dal repository) sono ingressi obbligatori. Passi, in quest'ordine: rifiuto di `pull_request_target`; commit base e baseline (artefatto `code-analyzer-baseline` del branch principale, altrimenti scansione del base nello stesso job); `scan` (con `--pr` su una PR) **senza** `--fail-on`; SARIF in Code Scanning anche dopo un fallimento; `notify` su una PR; `gate`, per ultimo, con l'esito del job.

```yaml
permissions:
  contents: read
  actions: read            # cercare la baseline tra gli artefatti
  security-events: write   # SARIF
  pull-requests: write     # commento
  checks: write            # check run
jobs:
  analyze:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@<hash>
        with: { fetch-depth: 2, persist-credentials: false }
      - uses: ./integrations/github-action
        with:
          image: <immagine della CLI>
          public-key: <chiave cosign, fuori dal repository>
          fail-on: critico,alto   # la soglia sta qui: .code-analyzer.yml lo cambia chi modifica il branch
```

Il flusso verso il server è un passo a parte: `code-analyzer upload` con il token OIDC del job (`id-token: write`). `server-url` e `variant` non sono ingressi dell'Action. Verificare le versioni correnti delle action citate al momento dell'implementazione; per i dettagli, `doc/utente/ci-github.md`.

### 12.2 GitLab CI component

- Componente in `integrations/gitlab-component/templates/code-analyzer.yml`.
- Produce report negli artefatti nativi con `code-analyzer export --format gitlab`: `sast`, `dependency_scanning`, `codequality` e l'SBOM CycloneDX portato dalla 1.7 alla 1.6 che GitLab legge.
- Il job fallisce secondo `gate` (soglia fissata dalla pipeline, come per l'Action). Scritto ma mai eseguito su GitLab: D2-12 (rimandata) ha lasciato senza istanza il progetto specchio e i test E2E (N-08).

### 12.3 Renovate e Dependabot

| Funzione | Implementazione |
| --- | --- |
| Arricchire PR dei bot | Webhook PR → scansione → commento con punteggio di impatto e controllo licenza della nuova versione |
| Priorità | Generare `packageRules` Renovate che alzano la priorità degli aggiornamenti che chiudono finding Critico/Alto e propongono automerge solo per patch a basso rischio |
| Dependabot | Leggere alert via API, deduplicare con OSV; proporre chiusura con giustificazione VEX (azione confermata da un umano) |
| Remediation | L'agente preferisce la PR del bot già aperta; patch propria solo se manca |

---

## 13. Piano di lavoro per fasi

Ogni fase si chiude con un gate misurabile. Valori da confermare dopo il pilota.

### Fase 1 — MVP: inventario (Python, JS/TS)

- [x] Monorepo, CI del progetto, immagini Docker base — monorepo, immagine base dei plugin, CI delle verifiche (`verify.yml`), build, firma ed E2E in CI (`e2e.yml`, O-02) e job dello snapshot dei feed (`feeds-snapshot.yml`, O-03), tutti verdi su `main` il 2026-11-10. Immagine CLI (I-03) rinviata alla Fase 2.
- [x] `ca-core`: modello Finding, fingerprint, dedup, SARIF/CycloneDX I/O
- [x] Runner plugin in sandbox + manifest + verifica firma — R-09 chiuso il 2026-11-09 (`doc/verifiche/sicurezza-fase-1.md`). Firma provata con chiave di test: registry e chiave definitivi attendono D-0005.
- [x] Plugin: syft, osv-scanner, trivy, scancode, gitleaks, semgrep, bandit — provati su immagini firmate localmente. La verifica legale per la distribuzione resta in D-0015.
- [x] Policy licenze da `.code-analyzer.yml`
- [x] CLI `scan`, `sbom`, `gate`, `config validate` — pacchetto provato con registry locale e chiave di test (I-04); pubblicazione sul registry alla decisione di rilascio (D-0005).
- [x] Output SARIF aggregato
- [x] Fixture repo Python e JS/TS con problemi noti

**Gate 1:** 3 repository pilota scansionati; scansione completa < 10 minuti (ADR-0009); tutti i problemi noti delle fixture rilevati.

Stato del Gate 1 al 2026-11-09: superato, con due scostamenti confermati dall'utente (`doc/verifiche/gate-1.md`). 3 pilota `complete` sotto i 10 minuti, 247,7 s il più lento; problemi noti delle fixture rilevati dagli E2E. La valutazione D-0015 è condizione per il primo rilascio (I-06), non per la chiusura della Fase 1.

Fase 1 chiusa il 2026-11-10 (X-07, `doc/verifiche/gate-1.md`). D-0015 approvata lo stesso giorno dal responsabile: il primo rilascio attende solo l'approvazione esplicita della pubblicazione.

### Fase 2 — Qualità e impatto

Stato al 2026-11-18, voce per voce (dettagli e limiti in `doc/plan/fase-2.md`):

- [x] `ca-graph`: tree-sitter, grafo dipendenze, smell Cyclic/Hub-Like/Unstable, PageRank, raggiungibilità e churn — in un contenitore come gli altri plugin (ADR-0020). Le definizioni degli smell non sono ancora confrontate con le pubblicazioni.
- [x] Plugin ruff, eslint, checkov, hadolint, coverage — per sviluppo e uso interno: la pubblicazione delle immagini attende D2-14 e D2-16 (I-07).
- [x] Feed EPSS/KEV/OSV con cache (ADR-0024); **il mirror è fuori dalla Fase 2** (D2-05: nessun mirror, solo fonti pubbliche e cache).
- [ ] Scoring Variante A e Variante B (modalità ombra entrambe) — A realizzata e in ombra; la Variante B coincide con A finché ADR-0023 non la definisce (D2-11, K-06..K-10).
- [x] Livelli, override, baseline e finding nuovi — con `levels.source: provisional` fino al Gate 2 (D2-10).
- [x] API REST, DB, UI elenco finding — il server riceve i report e non esegue scansioni (ADR-0016); UI centrata sull'elenco, portfolio in Fase 4 (D2-15).
- [ ] GitHub Action, GitLab component, commenti PR, check run — scritti e provati in locale; né l'Action né il componente sono stati eseguiti su GitHub o GitLab (N-05, N-08), e nessuna pubblicazione (N-09).

**Gate 2** (`doc/plan/fase-2.md`, sezione 2): G2.a entrambe le varianti calcolate in ombra su ogni finding dei repository del gate; G2.b ordinamento validato dai team (metodo Martini et al., ECSA 2018; con D2-03 un validatore unico e una variante predefinita provvisoria); G2.c scelta della variante predefinita; **G2.d scansione PR < 10 minuti**, che §5 e ADR-0009 assegnavano al Gate 2 senza che questa sezione lo dicesse.

### Fase 3 — Agenti LLM e motore decisionale

- [ ] `ca-decision`: interfaccia, LayaEngine, routing per confidenza
- [ ] Golden set iniziale annotato; fine-tuning Laya; calibrazione soglie
- [ ] `ca-agents`: contratti di fase, fasi 0–5, controlli
- [ ] Sandbox di build/test per la fase 4
- [ ] PR in bozza; integrazione Renovate/Dependabot

**Gate 3:** precisione del triage ≥ 80% sul golden set.

### Fase 4 — Scala e plugin

- [ ] SDK plugin pubblico + registry firmato
- [ ] Dashboard portfolio
- [ ] Linguaggi: Java/Kotlin, Go, C#, Rust
- [ ] Ricostruzione dell'architettura (codice + Helm/K8s/Kustomize/Terraform/CI), export C4
- [ ] Packaging SaaS (multi-tenant) e self-hosted (Helm, bundle feed offline)

**Gate 4:** grafo architetturale confermato dai team su 3 sistemi.

### Fase 5 — Dati e osservabilità

- [ ] Data mapping e lineage: migrazioni, sqlglot, ORM, serializer, frontend; export OpenLineage
- [ ] Classificazione colonne via motore decisionale + conferma umana
- [ ] Integrazione OpenTelemetry/Tempo/Loki/Prometheus per confermare archi e raggiungibilità
- [ ] Fase 7 degli agenti con telemetria

---

## 14. Strategia di test

| Livello | Cosa | Strumento |
| --- | --- | --- |
| Unit | Fingerprint, dedup, scoring A/B, livelli, parser SARIF/CycloneDX; per la SPA i componenti e gli stati di ogni vista | pytest, hypothesis; vitest, Testing Library, axe-core |
| Contratto | Output plugin vs JSON Schema; ogni schema di `schemas/` con casi validi e non validi e l'equivalenza col modello; l'OpenAPI e i tipi generati della SPA; contratti di fase agenti (Fase 3) | jsonschema |
| Integrazione | Plugin su immagini reali e CLI su fixture (E2E con registry locale e immagini firmate). Dalla Fase 2: `ca-api` su PostgreSQL 16 vero con archivio su file system e S3 di prova, e le risposte vere confrontate con l'OpenAPI (nessun Temporal) | Docker; testcontainers (PostgreSQL, server S3 di prova) |
| Regressione scoring | Tabella di casi con punteggio e livello attesi | pytest parametrizzato |
| Valutazione decisionale | Accuratezza e calibrazione per `question_id` sul golden set | script in `golden-set/eval/` |
| Valutazione agenti | Patch: build verde, finding chiuso, nessun finding nuovo, approvazione | harness offline con fake LLM in CI |
| E2E | Action/GitLab su repository di prova | job CI dedicati |

Regola: nessun test in CI chiama LLM a pagamento; si usano fake deterministici.

---

## 15. Sicurezza e osservabilità del prodotto

- Plugin in sandbox senza rete; immagini firmate; SBOM del prodotto stesso pubblicato a ogni release.
- Segreti dei tenant in un secret manager; nessun segreto in log o prompt.
- Workspace effimeri, cancellati a fine scansione (SaaS).
- Telemetria OpenTelemetry: durata scansioni, errori plugin, coda worker, token per agente, decisioni per confidenza.
- Dashboard Grafana incluse nel chart Helm.

---

## 16. Regole per gli agenti di coding (base per `AGENTS.md`)

1. Ogni modifica a modelli o schemi aggiorna anche `schemas/` e i test di contratto.
2. Nessuna dipendenza nuova senza verificarne licenza e manutenzione; aggiornare l'SBOM.
3. Le soglie e i pesi di scoring stanno in configurazione, mai hard-coded nella logica.
4. Ogni plugin nuovo include manifest, fixture e test di contratto.
5. Comandi di verifica prima di ogni PR:
   ```
   uv run ruff check . && uv run ruff format --check .
   uv run ty check packages --error-on-warning
   uv run pytest -q
   uv run lint-imports
   uv run python -m ca_core.schema_export --check
   bun run --cwd web lint && bun run --cwd web test
   ```
6. Messaggi di commit: Conventional Commits.
7. Nessuna chiamata a servizi esterni nei test.

---

## 17. Definition of Done

Una funzionalità è completa quando:

- [ ] Test unitari e di contratto verdi; copertura ≥ 80% sul codice nuovo di `ca-core`
- [ ] Schemi JSON aggiornati e validati
- [ ] Documentazione utente aggiornata
- [ ] Telemetria aggiunta per le operazioni lunghe (in Fase 1: durate nel report, ADR-0010)
- [ ] Nessun nuovo finding Critico/Alto quando Code Analyzer analizza se stesso (in Fase 1 sull'intero repository, ADR-0009)

---

## 18. Decisioni aperte

- [ ] Catalogo servizi disponibile per C ed E? Formato e fonte.
- [x] Elenco licenze vietate o soggette ad approvazione — D-0013, 2026-11-08. Gli identificatori sono esatti secondo SPDX; rivedere la policy con il referente legale prima della distribuzione.
- [ ] Provider LLM ammessi dalle policy.
- [ ] Hardware per Laya in self-hosted (GPU o solo CPU → valutare jevos).
- [ ] Variante di scoring predefinita (esito del Gate 2).

---

## 19. Riferimenti

Standard e strumenti: CycloneDX 1.7 (ECMA-424), SPDX 3.0, SARIF 2.1.0, CVSS 4.0, EPSS v4, CISA KEV, OSV-Scanner v2, ScanCode Toolkit, Laya (github.com/NandhaKishorM/laya), Jev (TypeSafe AI), jevos.

Pubblicazioni per la Variante B:

- Arcelli Fontana, Ferme, Zanoni, Roveda. *Towards a prioritization of code debt: A code smell intensity index.* IEEE MTD 2015.
- Arcelli Fontana, Pigazzini, Roveda, Zanoni. *Automatic detection of instability architectural smells.* IEEE ICSME 2016.
- Arcelli Fontana, Roveda, Zanoni. *Technical debt indexes provided by tools: A preliminary discussion.* IEEE MTD 2016.
- Tollin, Arcelli Fontana, Zanoni, Roveda. *Change prediction through coding rules violations.* EASE 2017.
- Arcelli Fontana, Pigazzini, Roveda, Tamburri, Zanoni, Di Nitto. *Arcan: A tool for architectural smells detection.* IEEE ICSAW 2017.
- Rizzi, Arcelli Fontana, Roveda. *Support for architectural smell refactoring.* IWoR 2018.
- Martini, Arcelli Fontana, Biaggi, Roveda. *Identifying and prioritizing architectural debt through architectural smells.* ECSA 2018.
- Roveda, Arcelli Fontana, Pigazzini, Zanoni et al. *Towards an architectural debt index.* SEAA 2018.
- Arcelli Fontana, Lenarduzzi, Roveda, Taibi. *Are architectural smells independent from code smells?* JSS 154, 2019.
- Arcelli Fontana, Pigazzini, Raibulet, Basciano, Roveda. *PageRank and criticality of architectural smells.* ECSA 2019.
- Arcelli Fontana, Avgeriou, Pigazzini, Roveda. *A study on architectural smells prediction.* SEAA 2019.
- Tamburri, Arcelli Fontana, Roveda, Lenarduzzi. *Architecture Smells vs. Concurrency Bugs: an Exploratory Study and Negative Results.* arXiv:2303.17862, 2023.
