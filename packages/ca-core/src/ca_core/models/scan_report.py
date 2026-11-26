"""Contratto `scan-report` (ADR-0010, con ADR-0004, 0005, 0006, 0009, 0012, 0014). Solo dati.

È l'unico ingresso di `gate` e l'artefatto ispezionabile di `scan`. Contiene informazioni
sul repository analizzato e sugli esiti dei plugin: i testi liberi hanno lunghezza limitata e
non devono mai riportare valori letti dall'output di un plugin (ADR-0012).

Fuori dal contratto, finché D-0005 è aperta: registry, chiavi e identità di firma. Del plugin
si registrano solo versione, digest, esito della verifica (`signature`) e isolamento.
"""

from datetime import date
from enum import StrEnum
from typing import Annotated, Literal, Self

from pydantic import (
    AwareDatetime,
    BaseModel,
    ConfigDict,
    Field,
    StrictBool,
    StrictFloat,
    model_validator,
)

from ca_core.models.config import CodeAnalyzerConfig, GateMode, SchemaVersion1
from ca_core.models.finding import FINGERPRINT_PATTERN, BaselineState, Finding, Level

DIGEST_PATTERN = r"^sha256:[0-9a-f]{64}$"
_PLUGIN_NAME = r"^[a-z][a-z0-9-]{0,62}$"
_DURATION = Field(ge=0, description="Secondi.")
_TEXT = Annotated[str, Field(min_length=1, max_length=500)]


class ReportStatus(StrEnum):
    COMPLETE = "complete"
    PARTIAL = "partial"


class HistoryCoverage(StrEnum):
    FULL = "full"
    SHALLOW = "shallow"  # clone superficiale: i segreti nella storia possono mancare (ADR-0012)
    ABSENT = "absent"  # cartella non git (ADR-0008)


class Isolation(StrEnum):
    GVISOR = "gvisor"
    HARDENED_CONTAINER = "hardened-container"


class Signature(StrEnum):
    """Firma assente o non valida non genera un report (exit 2, ADR-0005): resta `skipped`."""

    VERIFIED = "verified"
    SKIPPED = "skipped"  # CA_INSECURE_ALLOW_UNSIGNED=1


class Outcome(StrEnum):
    OK = "ok"
    FAILED = "failed"  # genera un finding `health` e rende la scansione parziale (ADR-0007)


class InertSection(StrEnum):
    """Sezioni di `.code-analyzer.yml` validate ma senza effetto in Fase 1 (ADR-0014)."""

    SERVICE = "service"
    SCORING = "scoring"
    AGENTS = "agents"


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Repository(_Strict):
    name: _TEXT
    commit: str | None = Field(default=None, pattern=r"^[0-9a-f]{40,64}$")  # None: non git
    history: HistoryCoverage


class Gate(_Strict):
    """Configurazione di gate effettiva. IPOTESI D-0009-A: `effective_mode` va tolto con essa.

    `block_on` e `warn_on` sono quelli di `.code-analyzer.yml`, non risolti: il valore
    predefinito e la precedenza di `--fail-on` stanno nel gate (ADR-0009), mai nel report.
    """

    mode: GateMode
    effective_mode: GateMode
    block_on: list[Level] | None = None
    warn_on: list[Level] | None = None


class FeedSnapshot(_Strict):
    origin: _TEXT  # etichetta dell'origine della sincronizzazione, non un URL da seguire
    synced_at: AwareDatetime
    sync_failed: StrictBool = Field(
        default=False, description="Sincronizzazione fallita: usato lo snapshot precedente."
    )


class PluginRun(_Strict):
    model_config = ConfigDict(
        extra="forbid",
        json_schema_extra={
            "if": {"properties": {"outcome": {"const": "failed"}}, "required": ["outcome"]},
            "then": {"properties": {"failure": {"type": "string"}}, "required": ["failure"]},
            "else": {"properties": {"failure": {"type": "null"}}},
        },
    )

    name: str = Field(pattern=_PLUGIN_NAME)
    version: str = Field(min_length=1, max_length=128)
    digest: str = Field(pattern=DIGEST_PATTERN)  # quello eseguito, mai un tag (ADR-0005)
    signature: Signature
    isolation: Isolation
    duration_seconds: StrictFloat = _DURATION
    outcome: Outcome
    failure: _TEXT | None = None  # solo codice e causa generica, senza contenuto dell'output
    feed: FeedSnapshot | None = None  # solo per i plugin con `feeds` nel manifest

    @model_validator(mode="after")
    def _failure_only_when_failed(self) -> Self:
        if (self.outcome is Outcome.FAILED) != (self.failure is not None):
            raise ValueError("failure se e solo se outcome è failed")
        return self


class AppliedException(_Strict):
    """Eccezione con fingerprint corrispondente e `expires` non superata (ADR-0014)."""

    fingerprint: str = Field(pattern=FINGERPRINT_PATTERN)
    reason: str = Field(min_length=1)
    expires: date
    approved_by: str = Field(min_length=1)  # dichiarazione, non autenticata


class Warning_(_Strict):  # noqa: N801 - `Warning` è un builtin
    """Avviso del motore, ad es. `exception-expired`, `new-findings-only-as-all`."""

    code: str = Field(pattern=r"^[a-z][a-z0-9-]{0,63}$")
    message: _TEXT
    subject: _TEXT | None = None  # plugin, fingerprint o altra voce a cui si riferisce


class ScanKind(StrEnum):
    FULL = "full"
    PR = "pr"  # scansione completa più confronto con la baseline (ADR-0025)


class ScanInfo(_Strict):
    """Tipo di scansione (ADR-0025, ADR-0018): servono a `scans` sul server."""

    kind: ScanKind = ScanKind.FULL
    base_commit: str | None = Field(default=None, pattern=r"^[0-9a-f]{40,64}$")
    pull_request: int | None = Field(default=None, ge=1, le=2_147_483_647)

    @model_validator(mode="after")
    def _pr_fields_only_for_pr(self) -> Self:
        if self.kind is ScanKind.PR and self.base_commit is None:
            raise ValueError("una scansione pr ha un commit base")
        if self.kind is ScanKind.FULL and (self.base_commit or self.pull_request):
            raise ValueError("commit base e PR solo per una scansione pr")
        return self


class BaselineStatus(StrEnum):
    VALID = "valid"
    MISSING = "missing"  # nessuna baseline: avviso `baseline-missing`, il gate valuta tutto
    REJECTED = "rejected"  # trovata ma non utilizzabile: `reason` dice perché


class BaselineSourceKind(StrEnum):
    CI_ARTIFACT = "ci-artifact"
    BASE_SCAN = "base-scan"
    SERVER = "server"


class ResolvedFinding(_Strict):
    """Un finding della baseline assente ora, con tutti i suoi strumenti riusciti (ADR-0025)."""

    fingerprint: str = Field(pattern=FINGERPRINT_PATTERN)
    rule_id: _TEXT
    title: _TEXT
    path: str | None = Field(default=None, max_length=4096)


class Baseline(_Strict):
    """Esito del confronto con la baseline (ADR-0025, §7). I conteggi quadrano con i finding."""

    status: BaselineStatus
    commit: str | None = Field(default=None, pattern=r"^[0-9a-f]{40,64}$")
    source: BaselineSourceKind | None = None
    reason: str | None = Field(
        default=None,
        pattern=r"^[a-z][a-z0-9-]{0,62}$",
        description="Codice dell'avviso (`baseline-commit-mismatch`, `baseline-partial`...).",
    )
    new: int = Field(default=0, ge=0)
    existing: int = Field(default=0, ge=0)
    resolved: list[ResolvedFinding] = Field(default_factory=list, max_length=10_000)
    updated: list[Annotated[str, Field(pattern=FINGERPRINT_PATTERN)]] = Field(
        default_factory=list,
        max_length=10_000,
        description="Fingerprint degli `existing` con posizione o livello cambiati: il SARIF li "
        "marca `updated` (ADR-0011, ADR-0025).",
    )
    not_evaluated: int = Field(
        default=0,
        ge=0,
        description="Finding della baseline che mancano perché il loro plugin è fallito: non "
        "sono né risolti né esistenti e il report lo dice (ADR-0025).",
    )

    @model_validator(mode="after")
    def _consistent(self) -> Self:
        if self.status is BaselineStatus.VALID:
            if self.commit is None or self.source is None:
                raise ValueError("una baseline valida ha commit e fonte")
        elif self.new or self.existing or self.resolved or self.not_evaluated or self.updated:
            raise ValueError("conteggi senza una baseline valida")
        if self.status is not BaselineStatus.REJECTED and self.reason is not None:
            raise ValueError("reason solo per una baseline rifiutata")
        if self.status is BaselineStatus.REJECTED and self.reason is None:
            raise ValueError("una baseline rifiutata ha un motivo")
        return self


class ScoringInfo(_Strict):
    """Quale configurazione di scoring ha prodotto i punteggi (G2.a, D2-10)."""

    active_variant: Literal["A", "B"]
    config_version: Annotated[str, Field(min_length=1, max_length=64)]
    shadow: StrictBool = Field(
        default=True, description="A e B calcolate entrambe: la seconda non decide il livello."
    )
    benchmark_version: Annotated[str, Field(min_length=1, max_length=64)] | None = Field(
        default=None,
        description="Distribuzione di benchmark della Variante B (ADR-0023): versione e impronta.",
    )


class ServiceValue(_Strict):
    value: Annotated[int, Field(ge=1, le=3)] | StrictBool | None = None
    source: Literal["catalog", "repository", "default"]


class ServiceContext(_Strict):
    """Fonte di C ed E (ADR-0028): da dove venivano tier ed esposizione di un punteggio."""

    tier: ServiceValue
    internet_facing: ServiceValue
    catalog_id: Annotated[str, Field(max_length=200)] | None = None


class EnrichmentSnapshot(_Strict):
    """Snapshot EPSS o KEV usato (ADR-0024): basta a riprodurre un punteggio a posteriori."""

    feed: Literal["epss", "kev"]
    origin: Literal["public", "mirror", "cache"]  # un'etichetta, non un indirizzo
    downloaded_at: AwareDatetime
    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    content: dict[str, Annotated[str, Field(max_length=128)]] = Field(
        default_factory=dict, max_length=8
    )


class ScanReport(_Strict):
    """Un plugin `failed` rende `status` `partial` (un solo verso, anche nello schema).

    Vincoli solo del modello: nomi in `plugins` unici e disgiunti da `disabled_plugins`.
    """

    model_config = ConfigDict(
        extra="forbid",
        json_schema_extra={
            "if": {
                "properties": {
                    "plugins": {
                        "type": "array",
                        "contains": {
                            "properties": {"outcome": {"const": "failed"}},
                            "required": ["outcome"],
                        },
                    }
                },
                "required": ["plugins"],
            },
            "then": {"properties": {"status": {"const": "partial"}}},
        },
    )

    version: SchemaVersion1
    status: ReportStatus
    started_at: AwareDatetime  # `first_seen` e `last_seen` dei finding (ADR-0008)
    duration_seconds: StrictFloat = _DURATION
    repository: Repository
    gate: Gate
    plugins: list[PluginRun] = Field(
        description="Nomi unici (vincolo del modello, non dello schema)."
    )
    disabled_plugins: list[str] = Field(
        default_factory=list,
        description="Disattivati da `plugins.disable`; disgiunti dai nomi in `plugins` "
        "(vincolo del modello, non dello schema).",
    )
    exclusions: list[str] = Field(
        default_factory=list, description="Glob effettivi: predefiniti più `paths.exclude`."
    )
    correlation_version: str | None = Field(
        default=None,
        pattern=r"^[0-9]{1,4}$",
        description="Versione della tabella di correlazione usata (K-21): un gruppo assegnato con "
        "una tabella diversa non è confrontabile.",
    )
    exceptions: list[AppliedException] = Field(default_factory=list)
    inert_sections: list[InertSection] = Field(default_factory=list)
    warnings: list[Warning_] = Field(default_factory=list)
    scan: ScanInfo = Field(default_factory=ScanInfo)
    baseline: Baseline | None = None
    effective_config: CodeAnalyzerConfig | None = Field(
        default=None,
        description="Configurazione con cui la scansione è stata eseguita, per intero (ADR-0025): "
        "serve a una scansione di PR che usa questo report come baseline. Assente nei report "
        "della Fase 1, che quindi non valgono come baseline per la configurazione.",
    )
    scoring: ScoringInfo | None = None
    service_context: ServiceContext | None = None
    enrichment: list[EnrichmentSnapshot] = Field(default_factory=list, max_length=2)
    findings: list[Finding]

    @model_validator(mode="after")
    def _consistent(self) -> Self:
        names = [plugin.name for plugin in self.plugins]
        if len(set(names)) != len(names):
            raise ValueError("plugin duplicati")
        if set(names) & set(self.disabled_plugins):
            raise ValueError("un plugin disattivato non può avere un'esecuzione")
        failed = any(plugin.outcome is Outcome.FAILED for plugin in self.plugins)
        if failed and self.status is ReportStatus.COMPLETE:
            raise ValueError("un plugin fallito rende la scansione partial")
        self._check_baseline()
        if self.gate.effective_mode is GateMode.NEW_FINDINGS_ONLY and not (
            self.baseline and self.baseline.status is BaselineStatus.VALID
        ):
            raise ValueError("new-findings-only effettivo richiede una baseline valida")
        feeds = [s.feed for s in self.enrichment]
        if len(set(feeds)) != len(feeds):
            raise ValueError("snapshot duplicati per feed")
        return self

    def _check_baseline(self) -> None:
        """Lo stato rispetto alla baseline e i conteggi quadrano tra loro (ADR-0025)."""
        states = [f.baseline_state for f in self.findings]
        valid = self.baseline is not None and self.baseline.status is BaselineStatus.VALID
        if not valid:
            if any(state is not None for state in states):
                raise ValueError("stato rispetto alla baseline senza una baseline valida")
            return
        assert self.baseline is not None
        if self.scan.kind is not ScanKind.PR:
            raise ValueError("una baseline vale solo per una scansione pr")
        if states.count(BaselineState.NEW) != self.baseline.new:
            raise ValueError("conteggio dei nuovi diverso dai finding")
        if states.count(BaselineState.EXISTING) != self.baseline.existing:
            raise ValueError("conteggio degli esistenti diverso dai finding")
        if any(state is None for state in states):
            raise ValueError("con una baseline valida ogni finding ha uno stato")
        existing = {
            f.fingerprint for f in self.findings if f.baseline_state is BaselineState.EXISTING
        }
        if (
            len(set(self.baseline.updated)) != len(self.baseline.updated)
            or not set(self.baseline.updated) <= existing
        ):
            raise ValueError("`updated` elenca finding che non sono esistenti")
