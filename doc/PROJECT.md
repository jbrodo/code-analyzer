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
| Linguaggio core | Python 3.12+ | Gestione dipendenze con `uv` |
| Orchestrazione | Temporal (Python SDK) | Workflow durevoli, retry, ripresa |
| API | FastAPI + Pydantic v2 | OpenAPI generata automaticamente |
| UI | React + TypeScript + Vite | Pacchetto separato `web/` |
| Database | PostgreSQL 16 + pgvector | Migrazioni con Alembic |
| Object storage | S3 / MinIO | SARIF, SBOM, report grezzi |
| Parsing codice | tree-sitter (py-tree-sitter) | Grammatiche Python, JS, TS, TSX |
| Isolamento plugin | Container con gVisor (runsc) o Firecracker | Rete disattivata per default |
| Deploy | Kubernetes + Helm; immagine CLI unica | Stesso motore in CI, server e locale |
| Osservabilità (interna) | OpenTelemetry → Collector → Tempo / Loki / Prometheus → Grafana | |
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
│   │       ├── models/            # Finding, Component, Graph, Scan (Pydantic)
│   │       ├── sarif/             # parser/serializer SARIF 2.1.0
│   │       ├── sbom/              # CycloneDX 1.7, SPDX 3.0
│   │       ├── fingerprint.py
│   │       ├── normalize.py       # SARIF+CycloneDX → modello comune
│   │       ├── dedup.py
│   │       ├── vex.py
│   │       └── scoring/
│   │           ├── base.py        # interfaccia ScoringModel
│   │           ├── variant_a.py   # G·P·E·C generico
│   │           ├── variant_b.py   # G·P·E·C basato sulle pubblicazioni
│   │           ├── levels.py      # soglie e override
│   │           └── feeds/         # EPSS, KEV, OSV
│   ├── ca-graph/                  # grafo del codice e dell'architettura
│   │   └── src/ca_graph/
│   │       ├── treesitter/        # estrattori per linguaggio
│   │       ├── deps.py            # grafo dipendenze tra moduli
│   │       ├── smells/            # cyclic, hub-like, unstable dependency
│   │       ├── pagerank.py
│   │       └── reconstruct/       # (Fase 4) codice + Helm/K8s/Terraform/CI
│   ├── ca-plugins/                # adattatori verso gli scanner esterni
│   │   └── src/ca_plugins/
│   │       ├── sdk.py             # contratto plugin (§7)
│   │       ├── runner.py          # esecuzione in sandbox
│   │       └── builtin/
│   │           ├── syft/  osv_scanner/  trivy/  scancode/
│   │           ├── semgrep/  bandit/  gitleaks/  trufflehog/
│   │           ├── ruff/  eslint/  checkov/  hadolint/
│   │           └── coverage/      # import LCOV / Cobertura
│   ├── ca-decision/               # motore decisionale (§10)
│   │   └── src/ca_decision/
│   │       ├── interface.py       # DecisionEngine (astratto)
│   │       ├── laya_engine.py
│   │       ├── jevos_engine.py
│   │       ├── jev_engine.py
│   │       └── routing.py         # instradamento per confidenza
│   ├── ca-agents/                 # agenti LLM sulle 8 fasi (§11)
│   │   └── src/ca_agents/
│   │       ├── contracts/         # schemi JSON input/output per fase
│   │       ├── phases/            # p0_engage … p7_learn
│   │       ├── context/           # contesto persistente (prompt, skill, ADR)
│   │       ├── controls/          # guard, gate, probe
│   │       └── llm.py             # interfaccia provider LLM
│   ├── ca-workflows/              # workflow e activity Temporal
│   ├── ca-api/                    # FastAPI
│   ├── ca-cli/                    # comando `code-analyzer`
│   └── ca-integrations/           # GitHub, GitLab, Renovate, Dependabot
├── web/                           # UI React
├── deploy/
│   ├── helm/code-analyzer/
│   ├── docker/                    # Dockerfile server, worker, cli, plugin base
│   └── compose/                   # ambiente di sviluppo locale
├── integrations/
│   ├── github-action/             # action.yml
│   └── gitlab-component/          # template CI/CD component
├── schemas/                       # JSON Schema pubblici
│   ├── finding.schema.json
│   ├── plugin-manifest.schema.json
│   ├── code-analyzer-config.schema.json
│   └── phases/*.schema.json
├── golden-set/                    # finding annotati per valutazione e training
└── tests/
    ├── unit/  integration/  e2e/
    └── fixtures/repos/            # repository di prova (Python, JS/TS)
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
    commit: str
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
    status: Status = Status.OPEN
    owner: str | None = None
    due_date: datetime | None = None
    first_seen: datetime
    last_seen: datetime
```

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

Workflow Temporal `ScanWorkflow`:

```
1. prepare_workspace     clone (shallow per PR, full per notturna), rilevamento linguaggi
2. resolve_changed_files solo per PR: diff rispetto alla baseline del branch principale
3. run_plugins           in parallelo, ognuno in sandbox; output SARIF / CycloneDX su object storage
4. build_graph           tree-sitter → grafo moduli; smell architetturali
5. normalize             SARIF + CycloneDX → Finding; fingerprint; dedup; applica VEX ed eccezioni
6. enrich                feed EPSS/KEV/OSV; raggiungibilità; catalogo servizi (C, E)
7. classify              motore decisionale (§10) sui finding che lo richiedono
8. score                 variante A o B (§6); livello; override
9. diff_baseline         separa finding nuovi / esistenti / risolti
10. publish              DB, SARIF aggregato, commenti PR, check run, ticket
11. trigger_agents       solo per finding sopra soglia (§11)
```

Requisiti non funzionali:

- Scansione PR incrementale **< 10 minuti** sui repository pilota (Gate 1).
- Ogni activity idempotente; un plugin che fallisce non blocca gli altri e produce un finding di tipo `health` ("scanner non eseguito").
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

La variante si sceglie per repository in `.code-analyzer.yml` (`scoring.variant: A | B`). Entrambe calcolano sempre i punteggi in modalità "ombra" durante il pilota, così da confrontarle (Gate 2).

### 6.1 Variante A — generica

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

| Livello | Soglia | Override che forzano il livello |
| --- | --- | --- |
| Critico | ≥ 70 | CVE in KEV e raggiungibile; segreto valido esposto; licenza vietata in prodotto distribuito |
| Alto | 40–69 | CVE con EPSS ≥ 0.1 raggiungibile; SAST con percorso confermato in servizio esposto |
| Medio | 15–39 | Architectural smell in un hotspot; copertura < 50% su codice critico modificato spesso |
| Basso | < 15 | — |

Soglie in `scoring/levels.py`, sovrascrivibili per tenant. Test di regressione con tabella di casi attesi.

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
resources:
  cpu: "2"
  memory: 2Gi
  timeout: 600s
network: none                   # none | feeds-only
```

### 7.2 Regole di esecuzione

- Workspace montato in sola lettura in `/workspace`; output in `/out`.
- Nessuna rete salvo `feeds-only` (mirror interni di OSV/EPSS/KEV).
- Immagine firmata (cosign) e verificata prima dell'esecuzione.
- Exit code ≠ 0 → scansione marcata parziale, finding `health` generato.
- Output validato contro lo schema SARIF 2.1.0 / CycloneDX 1.7; output non valido = plugin fallito.

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
service:
  catalog_id: payments-api          # per C ed E dal catalogo servizi
  tier: 1
  internet_facing: true
scoring:
  variant: A                        # A | B
gate:
  mode: new-findings-only           # valuta solo i finding nuovi rispetto alla baseline
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
agents:
  enabled: true
  max_phase: 5                      # oltre la 5 serve abilitazione esplicita
  llm_provider: self-hosted
```

Il file è validato da `schemas/code-analyzer-config.schema.json` (controllo che chiude la fase 0).

---

## 9. API e CLI

### 9.1 CLI

```
code-analyzer scan [PATH] [--pr --base main] [--format sarif|json|table] [--variant A|B]
code-analyzer sbom [PATH] --format cyclonedx|spdx
code-analyzer explain FINDING_ID
code-analyzer gate --fail-on critico,alto
code-analyzer config validate
code-analyzer plugin list|verify|run NAME
```

Exit code: 0 ok, 1 gate fallito, 2 errore di esecuzione.

### 9.2 API REST (FastAPI)

| Metodo | Percorso | Scopo |
| --- | --- | --- |
| POST | `/v1/scans` | Avvia una scansione |
| GET | `/v1/scans/{id}` | Stato e riepilogo |
| GET | `/v1/scans/{id}/sarif` | SARIF aggregato |
| GET | `/v1/repositories/{id}/findings` | Filtri: livello, categoria, stato, nuovi |
| PATCH | `/v1/findings/{id}` | Stato, owner, eccezione |
| GET | `/v1/repositories/{id}/sbom` | CycloneDX / SPDX |
| GET | `/v1/repositories/{id}/graph` | Grafo moduli/servizi |
| POST | `/v1/findings/{id}/agents/run` | Avvia il ciclo agenti fino a `max_phase` |
| POST | `/v1/webhooks/github`, `/v1/webhooks/gitlab` | Eventi PR, push, alert |

Autenticazione: OIDC per utenti; OIDC dei provider CI per le pipeline (nessun token a lunga durata).

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

```yaml
# integrations/github-action/action.yml
name: Code Analyzer
description: Scansione incrementale e gate per pull request
inputs:
  server-url: { required: false, description: "Vuoto = modalità locale" }
  fail-on:    { required: false, default: "critico,alto" }
  variant:    { required: false, default: "A" }
runs:
  using: docker
  image: docker://registry.example.com/code-analyzer/cli:1
  args: ["scan", "--pr", "--format", "sarif", "--fail-on", "${{ inputs.fail-on }}"]
```

Uso nel workflow del cliente:

```yaml
permissions:
  contents: read
  security-events: write
  pull-requests: write
  id-token: write          # OIDC verso il server
jobs:
  analyze:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with: { fetch-depth: 0 }
      - uses: org/code-analyzer-action@v1
      - uses: github/codeql-action/upload-sarif@v3
        with: { sarif_file: code-analyzer.sarif }
```

Verificare le versioni correnti delle action citate al momento dell'implementazione.

### 12.2 GitLab CI component

- Componente in `integrations/gitlab-component/templates/code-analyzer.yml`.
- Produce report negli artefatti nativi: `sast`, `dependency_scanning`, `codequality`, `cyclonedx`.
- Job fallisce secondo `gate.block_on`.

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

- [ ] Monorepo, CI del progetto, immagini Docker base
- [ ] `ca-core`: modello Finding, fingerprint, dedup, SARIF/CycloneDX I/O
- [ ] Runner plugin in sandbox + manifest + verifica firma
- [ ] Plugin: syft, osv-scanner, trivy, scancode, gitleaks, semgrep, bandit
- [ ] Policy licenze da `.code-analyzer.yml`
- [ ] CLI `scan`, `sbom`, `gate`, `config validate`
- [ ] Output SARIF aggregato
- [ ] Fixture repo Python e JS/TS con problemi noti

**Gate 1:** 3 repository pilota scansionati; scansione < 10 minuti; tutti i problemi noti delle fixture rilevati.

### Fase 2 — Qualità e impatto

- [ ] `ca-graph`: tree-sitter, grafo dipendenze, smell Cyclic/Hub-Like/Unstable
- [ ] Plugin ruff, eslint, checkov, hadolint, coverage
- [ ] Feed EPSS/KEV/OSV con cache e mirror
- [ ] Scoring Variante A e Variante B (modalità ombra entrambe)
- [ ] Livelli, override, baseline e finding nuovi
- [ ] API REST, DB, UI elenco finding
- [ ] GitHub Action, GitLab component, commenti PR, check run

**Gate 2:** ordinamento validato dai team (metodo Martini et al., ECSA 2018); scelta della variante predefinita.

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
| Unit | Fingerprint, dedup, scoring A/B, livelli, parser SARIF/CycloneDX | pytest, hypothesis |
| Contratto | Output plugin vs JSON Schema; contratti di fase agenti | jsonschema |
| Integrazione | Workflow Temporal end-to-end su fixture | Temporal test server, testcontainers (Postgres, MinIO) |
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
   uv run mypy packages
   uv run pytest -q
   pnpm --dir web lint && pnpm --dir web test
   ```
6. Messaggi di commit: Conventional Commits.
7. Nessuna chiamata a servizi esterni nei test.

---

## 17. Definition of Done

Una funzionalità è completa quando:

- [ ] Test unitari e di contratto verdi; copertura ≥ 80% sul codice nuovo di `ca-core`
- [ ] Schemi JSON aggiornati e validati
- [ ] Documentazione utente aggiornata
- [ ] Telemetria aggiunta per le operazioni lunghe
- [ ] Nessun nuovo finding Critico/Alto quando Code Analyzer analizza se stesso

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
