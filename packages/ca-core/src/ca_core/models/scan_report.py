"""Contratto `scan-report` (ADR-0010, con ADR-0004, 0005, 0006, 0009, 0012, 0014). Solo dati.

È l'unico ingresso di `gate` e l'artefatto ispezionabile di `scan`. Contiene informazioni
sul repository analizzato e sugli esiti dei plugin: i testi liberi hanno lunghezza limitata e
non devono mai riportare valori letti dall'output di un plugin (ADR-0012).

Fuori dal contratto, finché D-0005 è aperta: registry, chiavi e identità di firma. Del plugin
si registrano solo versione, digest, esito della verifica (`signature`) e isolamento.
"""

from datetime import date
from enum import StrEnum
from typing import Annotated, Self

from pydantic import (
    AwareDatetime,
    BaseModel,
    ConfigDict,
    Field,
    StrictBool,
    StrictFloat,
    model_validator,
)

from ca_core.models.config import GateMode, SchemaVersion1
from ca_core.models.finding import FINGERPRINT_PATTERN, Finding, Level

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
        return self
