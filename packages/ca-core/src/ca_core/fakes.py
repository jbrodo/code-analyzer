"""Fake in memoria delle porte (`ca_core.ports`) per i test di `ca-core` e dei pacchetti a valle."""

import hashlib
import io
from collections.abc import Callable, Sequence
from datetime import UTC, datetime, timedelta
from pathlib import PurePosixPath
from typing import BinaryIO

from ca_core.ports import (
    ArtifactConflict,
    ArtifactIntegrityError,
    ArtifactNotFound,
    ArtifactRef,
    ArtifactTooLarge,
    BaselineLookup,
    BaselineOutcome,
    BaselineSourceKind,
    ChangedFilesRequest,
    ChangedFilesResult,
    ChurnRequest,
    ChurnResult,
    EpssAnswer,
    FeedSnapshot,
    FeedsPurgeRequest,
    FeedsSyncRequest,
    FeedStatus,
    HistoryStatus,
    Isolation,
    KevAnswer,
    PluginRunRequest,
    PluginRunResult,
    RunOutcome,
    Signature,
    SourceError,
    SourceTooLarge,
    StoredArtifact,
    validate_artifact_key,
    validate_cve,
)


def _relative(name: str) -> PurePosixPath:
    # I segmenti si controllano sulla stringa: `PurePosixPath` normalizza `a/./b` e `a//b`.
    if not name or name.startswith("/") or any(s in ("", ".", "..") for s in name.split("/")):
        raise ValueError(f"percorso non relativo o fuori dall'area: {name!r}")
    return PurePosixPath(name)


class FixedClock:
    def __init__(self, start: datetime | None = None) -> None:
        self._now = start or datetime(2026, 1, 1, tzinfo=UTC)
        if self._now.tzinfo is None:
            raise ValueError("serve un istante con fuso orario")

    def now(self) -> datetime:
        return self._now

    def advance(self, seconds: float) -> None:
        self._now += timedelta(seconds=seconds)


class InMemorySourceReader:
    """`trees` associa una radice a `{percorso relativo: contenuto}`."""

    def __init__(self, trees: dict[str, dict[str, bytes]] | None = None) -> None:
        self.trees = trees or {}

    def list_files(self, root: str) -> list[str]:
        return sorted(self.trees.get(root, {}))

    def read_file(self, root: str, path: str, max_bytes: int) -> bytes:
        try:
            key = str(_relative(path))
        except ValueError as exc:
            raise SourceError(str(exc)) from exc
        files = self.trees.get(root, {})
        if key not in files:
            raise SourceError(f"file inesistente o non regolare: {path!r}")
        if len(files[key]) > max_bytes:
            raise SourceTooLarge(f"{path!r} supera {max_bytes} byte")
        return files[key]


class InMemoryArtifactSink:
    def __init__(self, base: str = "memory://artifacts") -> None:
        self.base = base
        self.artifacts: dict[str, bytes] = {}

    def write(self, name: str, content: bytes) -> ArtifactRef:
        key = str(_relative(name))
        self.artifacts[key] = content
        return ArtifactRef(name=key, location=f"{self.base}/{key}", size=len(content))


class FakePluginExecutor:
    """Risponde per nome di plugin; registra le richieste. Senza risposta: esecuzione fallita."""

    def __init__(
        self,
        results: dict[str, PluginRunResult | Callable[[PluginRunRequest], PluginRunResult]]
        | None = None,
        isolation: Isolation = Isolation.HARDENED_CONTAINER,
    ) -> None:
        self._isolation = isolation
        self.results = results or {}
        self.runs: list[PluginRunRequest] = []
        self.syncs: list[FeedsSyncRequest] = []
        self.purges: list[FeedsPurgeRequest] = []

    @staticmethod
    def ok(output_dir: str, duration_seconds: float = 0.0) -> PluginRunResult:
        return PluginRunResult(
            outcome=RunOutcome.OK,
            exit_code=0,
            isolation=Isolation.HARDENED_CONTAINER,
            signature=Signature.VERIFIED,
            duration_seconds=duration_seconds,
            output_dir=output_dir,
        )

    def isolation(self) -> Isolation:
        return self._isolation

    def run(self, request: PluginRunRequest) -> PluginRunResult:
        self.runs.append(request)
        entry = self.results.get(request.manifest.name)
        if entry is None:
            return PluginRunResult(
                outcome=RunOutcome.FAILED,
                exit_code=None,
                isolation=self._isolation,
                signature=Signature.SKIPPED,
                duration_seconds=0,
                output_dir=None,
                detail="nessuna risposta configurata nel fake",
            )
        if isinstance(entry, PluginRunResult):
            return entry
        return entry(request)

    def run_many(self, requests: Sequence[PluginRunRequest]) -> list[PluginRunResult]:
        return [self.run(r) for r in requests]

    def sync_feeds(self, request: FeedsSyncRequest) -> PluginRunResult:
        self.syncs.append(request)
        return self.ok(request.snapshot_dir)

    def purge_feeds(self, request: FeedsPurgeRequest) -> None:
        self.purges.append(request)


class FakeEnrichmentFeeds:
    """EPSS e KEV in memoria. Con `available=False` ogni risposta è `snapshot-absent`."""

    def __init__(
        self,
        epss: dict[str, tuple[float, float]] | None = None,
        kev: dict[str, KevAnswer] | None = None,
        snapshots: list[FeedSnapshot] | None = None,
        *,
        available: bool = True,
    ) -> None:
        self._epss = epss or {}
        self._kev = kev or {}
        self._snapshots = snapshots or []
        self.available = available
        self.queries: list[tuple[str, str]] = []

    def epss(self, cve: str) -> EpssAnswer:
        validate_cve(cve)
        self.queries.append(("epss", cve))
        if not self.available:
            return EpssAnswer(status=FeedStatus.SNAPSHOT_ABSENT)
        if cve not in self._epss:
            return EpssAnswer(status=FeedStatus.NOT_LISTED)
        score, percentile = self._epss[cve]
        return EpssAnswer(status=FeedStatus.FOUND, score=score, percentile=percentile)

    def kev(self, cve: str) -> KevAnswer:
        validate_cve(cve)
        self.queries.append(("kev", cve))
        if not self.available:
            return KevAnswer(status=FeedStatus.SNAPSHOT_ABSENT)
        return self._kev.get(cve, KevAnswer(status=FeedStatus.NOT_LISTED))

    def snapshots(self) -> list[FeedSnapshot]:
        return sorted(self._snapshots, key=lambda s: s.feed) if self.available else []


class InMemoryGitHistory:
    """Storia git finta: conteggi di churn e coppie di commit con i file cambiati."""

    def __init__(
        self,
        churn: dict[str, int] | None = None,
        *,
        status: HistoryStatus = HistoryStatus.COMPLETE,
        head_time: datetime | None = None,
        commits_read: int = 0,
        changed: dict[tuple[str, str], list[str]] | None = None,
    ) -> None:
        self._churn = churn or {}
        self._status = status
        self._head_time = head_time
        self._commits_read = commits_read
        self._changed = changed or {}
        self.requests: list[object] = []

    def churn(self, request: ChurnRequest) -> ChurnResult:
        self.requests.append(request)
        complete = self._status is HistoryStatus.COMPLETE
        return ChurnResult(
            status=self._status,
            window_days=request.window_days,
            head_time=self._head_time if complete else None,
            commits_read=self._commits_read,
            files=dict(self._churn) if complete else {},
        )

    def changed_files(self, request: ChangedFilesRequest) -> ChangedFilesResult:
        self.requests.append(request)
        key = (request.base, request.head)
        if key not in self._changed:
            return ChangedFilesResult(available=False)
        return ChangedFilesResult(available=True, files=sorted(self._changed[key]))


class FakeBaselineSource:
    """Un report per commit base. `source` è la fonte da dichiarare nella risposta."""

    def __init__(
        self,
        locations: dict[str, str] | None = None,
        source: BaselineSourceKind = BaselineSourceKind.CI_ARTIFACT,
    ) -> None:
        self._locations = locations or {}
        self._source = source
        self.queries: list[str] = []

    def find(self, base_commit: str) -> BaselineLookup:
        self.queries.append(base_commit)
        location = self._locations.get(base_commit)
        if location is None:
            return BaselineLookup(outcome=BaselineOutcome.MISSING)
        return BaselineLookup(outcome=BaselineOutcome.FOUND, location=location, source=self._source)


class InMemoryArtifactStore:
    """Archivio finto con la stessa semantica degli adattatori reali (ADR-0030)."""

    def __init__(self) -> None:
        self.objects: dict[str, bytes] = {}

    def put(
        self, key: str, stream: BinaryIO, *, max_bytes: int, sha256: str | None = None
    ) -> StoredArtifact:
        validate_artifact_key(key)
        if max_bytes < 1:
            raise ValueError("max_bytes deve essere positivo")
        data = stream.read(max_bytes + 1)
        if len(data) > max_bytes:
            raise ArtifactTooLarge(f"oltre {max_bytes} byte")
        digest = hashlib.sha256(data).hexdigest()
        if sha256 is not None and sha256 != digest:
            raise ArtifactIntegrityError("sha256 dichiarato diverso da quello dei byte")
        existing = self.objects.get(key)
        if existing is not None and existing != data:
            raise ArtifactConflict("la chiave esiste con contenuto diverso")
        self.objects.setdefault(key, data)
        return StoredArtifact(key=key, size=len(data), sha256=digest)

    def open(self, key: str) -> BinaryIO:
        validate_artifact_key(key)
        if key not in self.objects:
            raise ArtifactNotFound(key)
        return io.BytesIO(self.objects[key])

    def exists(self, key: str) -> bool:
        validate_artifact_key(key)
        return key in self.objects

    def delete(self, key: str) -> None:
        validate_artifact_key(key)
        self.objects.pop(key, None)
