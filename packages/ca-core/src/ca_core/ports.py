"""Porte del nucleo (ADR-0001, ADR-0002): `Protocol` e dati scambiati, solo libreria standard e
Pydantic. Gli adattatori reali stanno fuori da `ca-core`; i fake in `ca_core.fakes`.

Ingressi e uscite sono modelli serializzabili (JSON): ogni passo della pipeline resta
invocabile come activity senza modifiche. I percorsi sono stringhe, mai oggetti del sistema.
"""

from collections.abc import Sequence
from datetime import datetime
from enum import StrEnum
from typing import Protocol, Self, runtime_checkable

from pydantic import BaseModel, ConfigDict, Field, model_validator

from ca_core.models.plugin_manifest import InputMode, PackagedPluginManifest
from ca_core.models.scan_report import Isolation, Signature  # enum condivisi con il report


class _Frozen(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class SourceError(Exception):
    """Lettura rifiutata: percorso fuori dalla radice, non regolare o troppo grande."""


class ScanAborted(Exception):
    """La scansione termina con exit 2 senza produrre un report (ADR-0005, ADR-0004): firma
    assente o non valida, runtime OCI assente. Un esecutore la solleva da `run`; la pipeline non
    la cattura, perché un `health` finding nasconderebbe una manomissione."""

    exit_code = 2


class SourceTooLarge(SourceError):
    """Il file supera il limite di lettura: il chiamante può proseguire senza contesto
    (ADR-0008); le altre `SourceError` fanno fallire il plugin."""


class RunOutcome(StrEnum):
    OK = "ok"  # container terminato con exit 0
    FAILED = "failed"  # exit diverso da zero, o container non avviato
    # exit 0, ma un output dichiarato è assente, non regolare, un symlink o oltre `max_bytes`
    INVALID_OUTPUT = "invalid_output"
    TIMEOUT = "timeout"


class PluginRunRequest(_Frozen):
    manifest: PackagedPluginManifest  # il digest da eseguire è quello di `image`
    workspace: str  # directory dell'host, montata in sola lettura
    sbom: str | None = None  # file da montare come `inputs.sbom`, se il manifest lo ammette
    config: str | None = None  # file da montare come `inputs.config`
    feeds_snapshot: str | None = None  # directory dello snapshot, in sola lettura

    @model_validator(mode="after")
    def _inputs_match_manifest(self) -> Self:
        inputs = self.manifest.inputs
        if self.sbom is not None and inputs.sbom is InputMode.NONE:
            raise ValueError("sbom fornito ma il manifest dichiara inputs.sbom: none")
        if self.config is not None and inputs.config is InputMode.NONE:
            raise ValueError("config fornita ma il manifest dichiara inputs.config: none")
        if self.feeds_snapshot is not None and self.manifest.feeds is None:
            raise ValueError("feeds_snapshot fornito ma il manifest non ha feeds")
        return self


class FeedsSyncRequest(_Frozen):
    """Sincronizzazione: stessa immagine, né workspace né dati derivati dal repository."""

    manifest: PackagedPluginManifest
    snapshot_dir: str
    # Tetto di byte allocati nella cartella durante la sincronizzazione (ADR-0006, R-09).
    max_bytes: int = Field(gt=0)

    @model_validator(mode="after")
    def _manifest_has_feeds(self) -> Self:
        if self.manifest.feeds is None:
            raise ValueError("il manifest non ha feeds: niente da sincronizzare")
        return self


class FeedsPurgeRequest(_Frozen):
    """Rimozione di uno snapshot scartato che l'host non riesce a eliminare (ADR-0006, R-09)."""

    manifest: PackagedPluginManifest
    snapshot_dir: str


class PluginRunResult(_Frozen):
    outcome: RunOutcome
    exit_code: int | None  # None se il container non è partito
    isolation: Isolation
    # Esito della verifica di firma di `image`: obbligatorio, mai un valore implicito (ADR-0005).
    signature: Signature
    duration_seconds: float = Field(ge=0)
    output_dir: str | None  # /out dell'esecuzione, da leggere con `SourceReader`; None se assente
    detail: str | None = None  # messaggio breve per il finding `health`; mai output dello scanner


class ArtifactRef(_Frozen):
    name: str  # percorso relativo nell'area di output
    location: str  # dove l'adattatore l'ha messo
    size: int = Field(ge=0)


@runtime_checkable
class PluginExecutor(Protocol):
    """Esegue le immagini dei plugin. Il parallelismo è affare dell'adattatore (ADR-0002).

    Un plugin non riuscito è un risultato, mai un'eccezione. Escono come eccezione solo le
    condizioni che annullano la scansione (`ScanAborted`, runtime assente)."""

    def isolation(self) -> Isolation:
        """Livello di isolamento che questo esecutore applica (ADR-0004), noto prima di `run`."""
        ...

    def run(self, request: PluginRunRequest) -> PluginRunResult: ...

    def run_many(self, requests: Sequence[PluginRunRequest]) -> list[PluginRunResult]:
        """Un risultato per richiesta, nello stesso ordine; lotto vuoto, lista vuota. Alla prima
        eccezione le esecuzioni non avviate si annullano subito e l'eccezione si propaga."""
        ...

    def sync_feeds(self, request: FeedsSyncRequest) -> PluginRunResult: ...

    def purge_feeds(self, request: FeedsPurgeRequest) -> None:
        """Rimuove il contenuto di `snapshot_dir` con la stessa immagine. Migliore sforzo: un
        fallimento non è un'eccezione."""
        ...


@runtime_checkable
class SourceReader(Protocol):
    """Lettura confinata: file regolari sotto `root`, senza seguire symlink, con limite.

    Serve sia il workspace sia l'output confinato dei plugin (`/out`): `root` è l'una o l'altra.
    """

    def list_files(self, root: str) -> list[str]:
        """Percorsi relativi ordinati dei file regolari sotto `root`."""
        ...

    def read_file(self, root: str, path: str, max_bytes: int) -> bytes:
        """Contenuto di `root/path`. `SourceTooLarge` se supera `max_bytes`; `SourceError` se
        esce da `root` o non è regolare."""
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
    "FeedsPurgeRequest",
    "FeedsSyncRequest",
    "Isolation",
    "PluginExecutor",
    "PluginRunRequest",
    "PluginRunResult",
    "RunOutcome",
    "ScanAborted",
    "Signature",
    "SourceError",
    "SourceReader",
    "SourceTooLarge",
]
