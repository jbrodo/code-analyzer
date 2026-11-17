"""Modelli dell'API v1 (C-08, ADR-0029). Solo dati.

I modelli del nucleo (`Finding`, `PluginRun`, `Gate`, `Graph`, ...) sono riusati, non copiati
(ADR-0017): un test di contratto confronta i componenti dell'OpenAPI con `schemas/`. Qui stanno solo
i modelli che esistono nell'API: pagine, riepiloghi, richieste di triage. Tutti `extra="forbid"`:
le richieste sono rigide; i client devono ignorare i campi di risposta che non conoscono.
"""

from datetime import date
from enum import StrEnum
from typing import Annotated, Literal
from uuid import UUID

from pydantic import (
    AwareDatetime,
    BaseModel,
    ConfigDict,
    Field,
    JsonValue,
    StrictBool,
    StrictInt,
)

from ca_core.models.finding import Category, Finding, Level, LevelSource, Status, VariantScore
from ca_core.models.scan_report import (
    Baseline,
    EnrichmentSnapshot,
    Gate,
    PluginRun,
    ReportStatus,
    ScanKind,
    ScoringInfo,
    Warning_,
)


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


def _examples(*examples: JsonValue) -> ConfigDict:
    return ConfigDict(extra="forbid", json_schema_extra={"examples": list(examples)})


_UUID = "0192f3a2-7c1e-7b55-9d0a-3f6c8e2b4a10"
_UUID_2 = "0192f3a2-7c1e-7b55-9d0a-3f6c8e2b4a11"
_FP = "sha256:" + "a" * 64
_SHA = "b" * 40
_NOW = "2026-11-17T12:00:00Z"


class Role(StrEnum):
    """ADR-0019. Un utente può averne più d'uno; `amministratore` non include `approvatore`."""

    READER = "lettore"
    TRIAGE = "triage"
    APPROVER = "approvatore"
    ADMIN = "amministratore"


# --- identità ----------------------------------------------------------------------------------


class Me(_Strict):
    model_config = _examples(
        {
            "issuer": "https://idp.example",
            "subject": "user-42",
            "name": "Ada",
            "tenant": "acme",
            "roles": ["lettore", "triage"],
        }
    )

    issuer: str
    subject: str
    name: Annotated[str, Field(max_length=200)] | None = None
    email: Annotated[str, Field(max_length=320)] | None = None
    tenant: str
    roles: list[Role]


# --- repository e scansioni --------------------------------------------------------------------


class ScanSummary(_Strict):
    model_config = _examples(
        {
            "id": _UUID,
            "repository_id": _UUID_2,
            "kind": "full",
            "ref": "refs/heads/main",
            "commit": _SHA,
            "status": "complete",
            "started_at": _NOW,
            "duration_seconds": 412.5,
        }
    )

    id: UUID
    repository_id: UUID
    kind: ScanKind
    ref: Annotated[str, Field(max_length=500)] | None = None
    pull_request: Annotated[int, Field(ge=1)] | None = None
    commit: str = Field(pattern=r"^[0-9a-f]{40,64}$")
    status: ReportStatus
    started_at: AwareDatetime
    duration_seconds: Annotated[float, Field(ge=0)]


class RepositorySummary(_Strict):
    model_config = _examples(
        {
            "id": _UUID_2,
            "provider": "github",
            "name": "acme/shop",
            "default_branch": "main",
            "tier": 1,
            "internet_facing": True,
        }
    )

    id: UUID
    provider: Literal["github", "gitlab"]
    name: Annotated[str, Field(max_length=500)]
    default_branch: Annotated[str, Field(max_length=200)] | None = None
    tier: Annotated[int, Field(ge=1, le=3)] | None = None
    internet_facing: StrictBool | None = None
    catalog_id: Annotated[str, Field(max_length=200)] | None = None
    current_scan: ScanSummary | None = Field(
        default=None, description="La scansione corrente (ADR-0018), se ce n'è una."
    )


class RepositoryPage(_Strict):
    items: list[RepositorySummary]
    next_cursor: str | None = None


class ScanPage(_Strict):
    items: list[ScanSummary]
    next_cursor: str | None = None


class ScanDetail(_Strict):
    """I campi del report che non sono finding (ADR-0029): il server li ha dal report."""

    summary: ScanSummary
    plugins: list[PluginRun]
    warnings: list[Warning_]
    gate: Gate
    scoring: ScoringInfo | None = None
    enrichment: list[EnrichmentSnapshot] = Field(default_factory=list)
    baseline: Baseline | None = Field(
        default=None,
        description="Solo per una scansione di PR: conteggi di nuovi, esistenti, risolti.",
    )


class ScanRef(_Strict):
    id: UUID


class RepositoryPatch(_Strict):
    """Registrazione di tier ed esposizione (ADR-0028). Solo `amministratore`."""

    tier: Annotated[int, Field(ge=1, le=3)] | None = None
    internet_facing: StrictBool | None = None
    catalog_id: Annotated[str, Field(max_length=200)] | None = None


# --- finding -----------------------------------------------------------------------------------


class SortKey(StrEnum):
    IMPACT = "impact"
    FIRST_SEEN = "first_seen"
    PATH = "path"
    SCORE_A = "score_a"
    SCORE_B = "score_b"


class ExceptionOrigin(StrEnum):
    SERVER = "server"
    REPOSITORY = "repository"


class FindingListItem(_Strict):
    """Forma breve (ADR-0029): evidenze, fattori e passi di correzione stanno nel dettaglio."""

    model_config = _examples(
        {
            "id": _UUID,
            "fingerprint": _FP,
            "level": "alto",
            "level_source": "tool_severity",
            "title": "Chiamata a subprocess con shell=True",
            "rule_id": "B602",
            "category": "sast",
            "tools": ["bandit"],
            "path": "app/run.py",
            "start_line": 3,
            "status": "aperto",
            "new": True,
            "first_seen": _NOW,
            "last_seen": _NOW,
            "score_a": 49.0,
            "level_a": "alto",
            "score_b": 49.0,
            "level_b": "alto",
        }
    )

    id: UUID
    fingerprint: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    level: Level | None = None
    level_source: LevelSource | None = None
    title: Annotated[str, Field(max_length=500)]
    rule_id: Annotated[str, Field(max_length=200)]
    category: Category
    tools: list[str]
    path: Annotated[str, Field(max_length=4096)] | None = None
    start_line: Annotated[int, Field(ge=1)] | None = None
    status: Status
    exception_origin: ExceptionOrigin | None = Field(
        default=None, description="Origine dell'eccezione che rende il finding `accettato`."
    )
    new: StrictBool | None = Field(
        default=None, description="Nuovo rispetto alla baseline (ADR-0025); assente senza baseline."
    )
    first_seen: AwareDatetime | None = Field(
        default=None, description="Nullo per un finding visto solo in una PR (ADR-0018)."
    )
    last_seen: AwareDatetime | None = None
    owner: Annotated[str, Field(max_length=200)] | None = None
    score_a: Annotated[float, Field(ge=0, le=100)] | None = None
    level_a: Level | None = None
    score_b: Annotated[float, Field(ge=0, le=100)] | None = None
    level_b: Level | None = None


class FindingPage(_Strict):
    model_config = _examples(
        {
            "items": [],
            "next_cursor": None,
            "total": 0,
            "total_new": 0,
        }
    )

    items: list[FindingListItem]
    next_cursor: str | None = None
    total: StrictInt = Field(ge=0, description="Finding con i filtri attivi.")
    total_new: StrictInt = Field(ge=0, description="Di questi, i nuovi rispetto alla baseline.")


class ExceptionRecord(_Strict):
    id: UUID
    origin: ExceptionOrigin
    reason: Annotated[str, Field(min_length=1, max_length=2000)]
    expires: date
    approved_by: Annotated[str, Field(max_length=300)]
    approved_by_verified: StrictBool = Field(
        description="Falso per `repository`: è una dichiarazione, non verificata (ADR-0018)."
    )
    revoked_at: AwareDatetime | None = None


class FindingEvent(_Strict):
    at: AwareDatetime
    actor: Annotated[str, Field(max_length=300)]
    action: Annotated[str, Field(pattern=r"^[a-z][a-z0-9-]{0,63}$")]
    from_state: Status | None = None
    to_state: Status | None = None
    reason: Annotated[str, Field(max_length=2000)] | None = None


class Occurrence(_Strict):
    """Occorrenza nella scansione corrente, con fattori ed evidenze delle due varianti."""

    scan_id: UUID
    commit: str = Field(pattern=r"^[0-9a-f]{40,64}$")
    variant_scores: list[VariantScore] = Field(default_factory=list, max_length=2)


class FindingDetail(_Strict):
    finding: Finding
    occurrence: Occurrence | None = None
    exceptions: list[ExceptionRecord] = Field(default_factory=list)
    events: list[FindingEvent] = Field(default_factory=list, description="Dal più recente.")


class SetStatus(_Strict):
    model_config = _examples(
        {"action": "set-status", "status": "falso_positivo", "reason": "Input già validato a monte"}
    )

    action: Literal["set-status"] = "set-status"
    status: Literal["aperto", "in_corso", "falso_positivo"]
    reason: Annotated[str, Field(min_length=1, max_length=2000)] | None = Field(
        default=None, description="Obbligatoria per `falso_positivo`."
    )


class SetOwner(_Strict):
    action: Literal["set-owner"] = "set-owner"
    owner: Annotated[str, Field(max_length=200)] | None = None


class CreateException(_Strict):
    """`approved_by` non è nel corpo: è l'identità autenticata (ADR-0019)."""

    model_config = _examples(
        {
            "action": "create-exception",
            "reason": "Accettato fino alla migrazione",
            "expires": "2027-06-30",
        }
    )

    action: Literal["create-exception"] = "create-exception"
    reason: Annotated[str, Field(min_length=1, max_length=2000)]
    expires: date = Field(description="Futura; non oltre il massimo configurato dal server.")


class RevokeException(_Strict):
    action: Literal["revoke-exception"] = "revoke-exception"
    exception_id: UUID


FindingPatch = Annotated[
    SetStatus | SetOwner | CreateException | RevokeException, Field(discriminator="action")
]
