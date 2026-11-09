"""Fake in memoria delle porte (`ca_core.ports`) per i test di `ca-core` e dei pacchetti a valle."""

from collections.abc import Callable, Sequence
from datetime import UTC, datetime, timedelta
from pathlib import PurePosixPath

from ca_core.ports import (
    ArtifactRef,
    FeedsPurgeRequest,
    FeedsSyncRequest,
    Isolation,
    PluginRunRequest,
    PluginRunResult,
    RunOutcome,
    Signature,
    SourceError,
    SourceTooLarge,
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
        return entry(request) if callable(entry) else entry

    def run_many(self, requests: Sequence[PluginRunRequest]) -> list[PluginRunResult]:
        return [self.run(r) for r in requests]

    def sync_feeds(self, request: FeedsSyncRequest) -> PluginRunResult:
        self.syncs.append(request)
        return self.ok(request.snapshot_dir)

    def purge_feeds(self, request: FeedsPurgeRequest) -> None:
        self.purges.append(request)
