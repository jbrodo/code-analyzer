"""Porte del nucleo (ADR-0001, ADR-0002): `Protocol` e dati scambiati, solo libreria standard e
Pydantic. Gli adattatori reali stanno fuori da `ca-core`; i fake in `ca_core.fakes`.

Ingressi e uscite sono modelli serializzabili (JSON): ogni passo della pipeline resta
invocabile come activity senza modifiche. I percorsi sono stringhe, mai oggetti del sistema.
"""

import re
from collections.abc import Sequence
from datetime import date, datetime
from enum import StrEnum
from typing import Annotated, BinaryIO, Literal, Protocol, Self, runtime_checkable

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, StrictFloat, model_validator

from ca_core.models.decision import Decision, DecisionKind, QuestionId
from ca_core.models.graph import HistoryStatus
from ca_core.models.plugin_manifest import InputMode, PackagedPluginManifest
from ca_core.models.scan_report import BaselineSourceKind, Isolation, Signature
from ca_core.models.scan_report import (  # enum e modelli condivisi con il report
    EnrichmentSnapshot as FeedSnapshot,
)


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
    # Opzioni aggiunte al comando di sincronizzazione per un'origine diversa da quella del
    # pacchetto (E-04). Vengono da chi lancia la scansione, mai dal repository analizzato.
    origin_args: tuple[Annotated[str, Field(pattern=r"^--[a-z][a-z-]*=\S+$")], ...] = Field(
        default=(), max_length=4
    )

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


# --- Fase 2 (C-06): feed di arricchimento, storia git, baseline, archivio degli artefatti -------
#
# Ingressi e uscite sono modelli serializzabili (ADR-0002) salvo i flussi di byte dell'archivio. Le
# eccezioni sono per le condizioni che il chiamante deve distinguere; un dato mancante è una
# risposta (`status`), mai un'eccezione né un valore inventato (ADR-0024, ADR-0022).

CVE_PATTERN = r"^CVE-[0-9]{4}-[0-9]{4,}$"
_CVE = re.compile(CVE_PATTERN)
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_COMMIT = re.compile(r"^[0-9a-f]{7,64}$")


class FeedStatus(StrEnum):
    """Le tre risposte di ADR-0024: `feed-absent` non si confonde con una CVE non valutata."""

    FOUND = "found"
    NOT_LISTED = "not-listed"  # lo snapshot c'è e non contiene la CVE
    SNAPSHOT_ABSENT = "snapshot-absent"  # nessuno snapshot utilizzabile


def validate_cve(cve: str) -> str:
    if not _CVE.fullmatch(cve):
        raise ValueError(f"identificativo CVE non valido: {cve!r}")
    return cve


class EpssAnswer(_Frozen):
    status: FeedStatus
    score: StrictFloat | None = Field(default=None, ge=0, le=1)
    percentile: StrictFloat | None = Field(default=None, ge=0, le=1)

    @model_validator(mode="after")
    def _values_only_when_found(self) -> Self:
        has_values = self.score is not None or self.percentile is not None
        if (self.status is FeedStatus.FOUND) != (self.score is not None) or (
            has_values and self.status is not FeedStatus.FOUND
        ):
            raise ValueError("score solo con status found, e sempre con status found")
        return self


class KevAnswer(_Frozen):
    status: FeedStatus
    date_added: date | None = None
    ransomware_use: Literal["Known", "Unknown"] | None = None  # `knownRansomwareCampaignUse`

    @model_validator(mode="after")
    def _values_only_when_found(self) -> Self:
        if self.status is not FeedStatus.FOUND and (
            self.date_added is not None or self.ransomware_use is not None
        ):
            raise ValueError("valori di KEV solo con status found")
        return self


@runtime_checkable
class EnrichmentFeeds(Protocol):
    """Lettura dei feed di arricchimento (EPSS e KEV) già scaricati e validati.

    Nessun I/O di rete qui: la sincronizzazione sta in un adattatore fuori dal nucleo (ADR-0001,
    ADR-0024) e non riceve mai dati del repository analizzato.
    """

    def epss(self, cve: str) -> EpssAnswer: ...

    def kev(self, cve: str) -> KevAnswer: ...

    def snapshots(self) -> list[FeedSnapshot]:
        """Snapshot in uso, ordinati per feed; vuoto se nessuno è disponibile."""
        ...


class ChurnRequest(_Frozen):
    commit: str | None = Field(default=None, pattern=_COMMIT.pattern)  # None: il commit corrente
    window_days: int = Field(default=90, ge=1, le=3650)


class ChurnResult(_Frozen):
    """Commit per file nella finestra che precede la data del commit (ADR-0022).

    Con una storia non completa `files` è vuoto: mai un conteggio che direbbe «poco modificato» di
    ogni file perché la storia è troncata.
    """

    status: HistoryStatus
    window_days: int = Field(ge=1, le=3650)
    head_time: AwareDatetime | None = None
    commits_read: int = Field(default=0, ge=0)
    files: dict[str, int] = Field(default_factory=dict)  # percorso POSIX relativo -> commit

    @model_validator(mode="after")
    def _counts_need_a_complete_history(self) -> Self:
        if self.status is not HistoryStatus.COMPLETE and self.files:
            raise ValueError("conteggi senza una storia completa")
        if any(c < 0 for c in self.files.values()):
            raise ValueError("conteggio negativo")
        return self


class ChangedFilesRequest(_Frozen):
    base: str = Field(pattern=_COMMIT.pattern)
    head: str = Field(pattern=_COMMIT.pattern)


class ChangedFilesResult(_Frozen):
    """File cambiati tra due commit. Non serve alla modalità PR della Fase 2 (ADR-0025, §4), che
    analizza tutto il repository; la porta c'è perché una restrizione futura non cambi i passi."""

    available: bool  # falso se uno dei due commit manca dal clone (storia superficiale)
    files: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def _files_only_when_available(self) -> Self:
        if not self.available and self.files:
            raise ValueError("file elencati senza storia")
        return self


@runtime_checkable
class GitHistory(Protocol):
    """Storia git del repository analizzato, letta senza eseguire configurazione del repository
    (git ombra, ADR-0012)."""

    def churn(self, request: ChurnRequest) -> ChurnResult: ...

    def changed_files(self, request: ChangedFilesRequest) -> ChangedFilesResult: ...


class BaselineOutcome(StrEnum):
    FOUND = "found"
    MISSING = "missing"  # nessun report per quel commit: la modalità PR avvisa e valuta tutto


class BaselineLookup(_Frozen):
    """Dove sta il report del commit base. La porta non valida il contenuto: lo fa K-16, secondo
    le regole di ADR-0025 (stesso commit, scansione completa, fuori dalla directory analizzata)."""

    outcome: BaselineOutcome
    location: str | None = None  # file del report, mai dentro la directory analizzata
    source: BaselineSourceKind | None = None

    @model_validator(mode="after")
    def _found_needs_location_and_source(self) -> Self:
        found = self.outcome is BaselineOutcome.FOUND
        if found != (self.location is not None) or found != (self.source is not None):
            raise ValueError("found richiede location e source, e solo found le ammette")
        return self


@runtime_checkable
class BaselineSource(Protocol):
    def find(self, base_commit: str) -> BaselineLookup: ...


class ArtifactNotFound(Exception):
    """La chiave non esiste."""


class ArtifactConflict(Exception):
    """La chiave esiste con contenuto diverso: gli artefatti non si sovrascrivono (ADR-0016)."""


class ArtifactIntegrityError(Exception):
    """L'SHA-256 dichiarato non coincide con quello dei byte letti."""


class ArtifactTooLarge(Exception):
    """Il flusso supera `max_bytes`: la lettura si ferma, non si scrive nulla."""


_KEY_SEGMENT = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9._=-]{0,127}$")
MAX_KEY_SEGMENTS = 12


def validate_artifact_key(key: str) -> str:
    """Chiave composta solo da componenti validati, mai da un nome ricevuto dal client (ADR-0030).

    Segmenti separati da `/`, ciascuno di caratteri ammessi, nessun `.` o `..`, al più
    `MAX_KEY_SEGMENTS`. Gli adattatori la ripetono prima di comporre un percorso o una chiave S3.
    """
    segments = key.split("/")
    if len(segments) > MAX_KEY_SEGMENTS or not all(
        _KEY_SEGMENT.fullmatch(s) and s not in (".", "..") for s in segments
    ):
        raise ValueError(f"chiave dell'archivio non valida: {key!r}")
    return key


class StoredArtifact(_Frozen):
    key: str
    size: int = Field(ge=0)
    sha256: str = Field(pattern=_SHA256.pattern)


@runtime_checkable
class ArtifactStore(Protocol):
    """Archivio degli artefatti di una scansione (report, SARIF, SBOM, grafo): ADR-0030.

    Nessun elenco e nessuna sovrascrittura. Lo stesso contenuto sulla stessa chiave è una
    ripetizione e non cambia nulla; contenuto diverso è `ArtifactConflict`.
    """

    def put(
        self, key: str, stream: BinaryIO, *, max_bytes: int, sha256: str | None = None
    ) -> StoredArtifact:
        """Scrive da un flusso, leggendone al più `max_bytes` (`ArtifactTooLarge` oltre). Con
        `sha256` il digest dichiarato si verifica mentre si scrive (`ArtifactIntegrityError`)."""
        ...

    def open(self, key: str) -> BinaryIO:
        """Flusso di lettura; `ArtifactNotFound` se manca. Chi chiama lo chiude."""
        ...

    def exists(self, key: str) -> bool: ...

    def delete(self, key: str) -> None:
        """Idempotente: cancellare una chiave assente non è un errore."""
        ...


__all__ = [
    "CVE_PATTERN",
    "MAX_KEY_SEGMENTS",
    "ArtifactConflict",
    "ArtifactIntegrityError",
    "ArtifactNotFound",
    "ArtifactStore",
    "ArtifactTooLarge",
    "BaselineLookup",
    "BaselineOutcome",
    "BaselineSource",
    "BaselineSourceKind",
    "ChangedFilesRequest",
    "ChangedFilesResult",
    "ChurnRequest",
    "ChurnResult",
    "EnrichmentFeeds",
    "EpssAnswer",
    "FeedSnapshot",
    "FeedStatus",
    "GitHistory",
    "HistoryStatus",
    "KevAnswer",
    "StoredArtifact",
    "validate_artifact_key",
    "validate_cve",
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


class DecisionError(Exception):
    """Il motore non può rispondere (ADR-0036): nessuna decisione di ripiego. Il messaggio non
    riporta l'evidenza."""


class EvidenceTooLarge(DecisionError):
    """L'evidenza supera il limite del motore, che non la tronca di nascosto."""


class UnsupportedQuestion(DecisionError):
    """Domanda, tipo o opzioni che il motore non gestisce."""


class DecisionEngine(Protocol):
    """§10.1. `evidence` è il testo di una `Evidence`; `options` serve solo alle domande a
    scelta, che non esistono ancora."""

    def decide(
        self,
        question_id: QuestionId,
        question: str,
        evidence: str,
        options: list[str] | None,
        kind: DecisionKind,
    ) -> Decision: ...
