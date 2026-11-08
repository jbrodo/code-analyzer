"""Porte del nucleo (ADR-0001, ADR-0002): `Protocol` e dati scambiati, solo libreria standard e
Pydantic. Gli adattatori reali stanno fuori da `ca-core`; i fake in `ca_core.fakes`.

Ingressi e uscite sono modelli serializzabili (JSON): ogni passo della pipeline resta
invocabile come activity senza modifiche. I percorsi sono stringhe, mai oggetti del sistema.
"""

from datetime import datetime
from enum import StrEnum
from typing import Protocol, runtime_checkable

from pydantic import BaseModel, ConfigDict, Field

from ca_core.models.plugin_manifest import PackagedPluginManifest


class _Frozen(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class SourceError(Exception):
    """Lettura rifiutata: percorso fuori dalla radice, non regolare o troppo grande."""


class RunOutcome(StrEnum):
    OK = "ok"  # container terminato con exit 0
    FAILED = "failed"  # exit diverso da zero, o container non avviato
    TIMEOUT = "timeout"


class Isolation(StrEnum):
    GVISOR = "gvisor"
    HARDENED_CONTAINER = "hardened-container"


class PluginRunRequest(_Frozen):
    manifest: PackagedPluginManifest  # il digest da eseguire è quello di `image`
    workspace: str  # directory dell'host, montata in sola lettura
    sbom: str | None = None  # file da montare come `inputs.sbom`, se il manifest lo ammette
    config: str | None = None  # file da montare come `inputs.config`
    feeds_snapshot: str | None = None  # directory dello snapshot, in sola lettura


class FeedsSyncRequest(_Frozen):
    """Sincronizzazione: stessa immagine, né workspace né dati derivati dal repository."""

    manifest: PackagedPluginManifest
    snapshot_dir: str


class PluginRunResult(_Frozen):
    outcome: RunOutcome
    exit_code: int | None  # None se il container non è partito
    isolation: Isolation
    duration_seconds: float = Field(ge=0)
    output_dir: str  # directory /out dell'esecuzione, da leggere con `SourceReader`
    detail: str | None = None  # messaggio breve per il finding `health`; mai output dello scanner


class ArtifactRef(_Frozen):
    name: str  # percorso relativo nell'area di output
    location: str  # dove l'adattatore l'ha messo
    size: int = Field(ge=0)


@runtime_checkable
class PluginExecutor(Protocol):
    """Esegue le immagini dei plugin. Il parallelismo è affare dell'adattatore (ADR-0002)."""

    def run(self, request: PluginRunRequest) -> PluginRunResult: ...

    def sync_feeds(self, request: FeedsSyncRequest) -> PluginRunResult: ...


@runtime_checkable
class SourceReader(Protocol):
    """Lettura confinata: file regolari sotto `root`, senza seguire symlink, con limite."""

    def list_files(self, root: str) -> list[str]:
        """Percorsi relativi ordinati dei file regolari sotto `root`."""
        ...

    def read_file(self, root: str, path: str, max_bytes: int) -> bytes:
        """Contenuto di `root/path`; `SourceError` se esce da `root`, non è regolare o supera
        `max_bytes`."""
        ...


@runtime_checkable
class ArtifactSink(Protocol):
    def write(self, name: str, content: bytes) -> ArtifactRef:
        """Scrive un artefatto con nome relativo; `ValueError` se il nome esce dall'area."""
        ...


@runtime_checkable
class Clock(Protocol):
    def now(self) -> datetime:
        """Istante corrente, sempre con fuso orario."""
        ...


__all__ = [
    "ArtifactRef",
    "ArtifactSink",
    "Clock",
    "FeedsSyncRequest",
    "Isolation",
    "PluginExecutor",
    "PluginRunRequest",
    "PluginRunResult",
    "RunOutcome",
    "SourceError",
    "SourceReader",
]
