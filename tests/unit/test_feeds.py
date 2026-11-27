"""R-06: sincronizzazione dei feed con un esecutore finto e snapshot simulati. Nessuna rete."""

import os
import subprocess
from collections.abc import Callable
from datetime import timedelta
from pathlib import Path

import pytest

from ca_core.fakes import FakePluginExecutor, FixedClock
from ca_core.models import PackagedPluginManifest
from ca_core.models.plugin_manifest import _EXAMPLE_FULL
from ca_core.ports import (
    FeedsPurgeRequest,
    FeedsSyncRequest,
    Isolation,
    PluginRunRequest,
    PluginRunResult,
    RunOutcome,
    ScanAborted,
    Signature,
)
from ca_plugins.feeds import POINTER, FeedsError, _validate_tree, ensure_snapshot
from ca_plugins.runner import OciExecutor

MANIFEST = PackagedPluginManifest.model_validate(_EXAMPLE_FULL)
DAY = timedelta(days=1)


class SyncStub(FakePluginExecutor):
    """`sync_feeds` scrive nello snapshot come farebbe il container, o fallisce."""

    def __init__(self, write: Callable[[Path], None] | None, outcome: RunOutcome = RunOutcome.OK):
        super().__init__()
        self.write, self.outcome = write, outcome

    def sync_feeds(self, request: FeedsSyncRequest) -> PluginRunResult:
        self.syncs.append(request)
        if self.write:
            self.write(Path(request.snapshot_dir))
        return PluginRunResult(
            outcome=self.outcome,
            exit_code=0,
            isolation=Isolation.HARDENED_CONTAINER,
            signature=Signature.VERIFIED,
            duration_seconds=0,
            output_dir=None,
        )


def good(snap: Path) -> None:
    (snap / "osv-scalibr" / "npm").mkdir(parents=True)
    (snap / "osv-scalibr" / "npm" / "all.zip").write_bytes(b"zip")


@pytest.fixture
def cache(tmp_path: Path) -> Path:
    return tmp_path / "cache"


def snaps(cache: Path) -> list[str]:
    return sorted(p.name for p in (cache / "osv-scanner").glob("snap-*"))


def test_first_sync_publishes_snapshot_and_fresh_reuses_it(cache: Path) -> None:
    clock, ex = FixedClock(), SyncStub(good)
    first = ensure_snapshot(MANIFEST, ex, cache, clock)
    assert first.failure is None and first.feed is not None and not first.feed.sync_failed
    assert first.snapshot_dir is not None and (Path(first.snapshot_dir) / "osv-scalibr").is_dir()
    clock.advance(3600)
    again = ensure_snapshot(MANIFEST, ex, cache, clock)
    assert again.snapshot_dir == first.snapshot_dir and len(ex.syncs) == 1


def test_sync_request_has_no_workspace_or_repo_data(cache: Path) -> None:
    ex = SyncStub(good)
    ensure_snapshot(MANIFEST, ex, cache, FixedClock())
    assert set(FeedsSyncRequest.model_fields) == {
        "manifest",
        "snapshot_dir",
        "max_bytes",
        "origin_args",
    }
    assert ex.syncs[0].origin_args == ()
    assert Path(ex.syncs[0].snapshot_dir).parent == cache / "osv-scanner"


def test_old_snapshot_is_replaced_and_new_directory_each_time(cache: Path) -> None:
    clock, ex = FixedClock(), SyncStub(good)
    first = ensure_snapshot(MANIFEST, ex, cache, clock)
    clock.advance(2 * 86400)
    second = ensure_snapshot(MANIFEST, ex, cache, clock)
    assert second.snapshot_dir != first.snapshot_dir and len(ex.syncs) == 2
    clock.advance(2 * 86400)
    third = ensure_snapshot(MANIFEST, ex, cache, clock)
    assert len(snaps(cache)) == 2 and Path(third.snapshot_dir or "").name in snaps(cache)


def test_failed_sync_uses_previous_snapshot_with_warning(cache: Path) -> None:
    clock = FixedClock()
    first = ensure_snapshot(MANIFEST, SyncStub(good), cache, clock)
    clock.advance(2 * 86400)
    out = ensure_snapshot(MANIFEST, SyncStub(None, RunOutcome.FAILED), cache, clock)
    assert out.snapshot_dir == first.snapshot_dir and out.failure is None
    assert out.feed is not None and out.feed.sync_failed
    assert [w.code for w in out.warnings] == ["feeds-sync-failed"]
    assert len(snaps(cache)) == 1  # la cartella nuova è stata rimossa


def test_no_snapshot_and_failed_sync_fails_the_plugin(cache: Path) -> None:
    out = ensure_snapshot(MANIFEST, SyncStub(good, RunOutcome.TIMEOUT), cache, FixedClock())
    assert out.snapshot_dir is None and out.feed is None and out.failure
    assert snaps(cache) == [] and not (cache / "osv-scanner" / POINTER).exists()


def test_untrusted_snapshot_is_rejected_and_pointer_kept(cache: Path, tmp_path: Path) -> None:
    def with_symlink(snap: Path) -> None:
        good(snap)
        (snap / "escape").symlink_to(tmp_path)

    clock = FixedClock()
    first = ensure_snapshot(MANIFEST, SyncStub(good), cache, clock)
    clock.advance(2 * 86400)
    for bad in (with_symlink, lambda snap: None):  # symlink; snapshot vuoto
        out = ensure_snapshot(MANIFEST, SyncStub(bad), cache, clock)
        assert out.snapshot_dir == first.snapshot_dir and out.feed and out.feed.sync_failed
    assert len(snaps(cache)) == 1


def test_size_limit(cache: Path) -> None:
    out = ensure_snapshot(MANIFEST, SyncStub(good), cache, FixedClock(), max_bytes=2)
    assert out.failure is not None


def test_offline_never_syncs(cache: Path) -> None:
    clock, ex = FixedClock(), SyncStub(good)
    none = ensure_snapshot(MANIFEST, ex, cache, clock, offline=True)
    assert none.failure and ex.syncs == []
    ensure_snapshot(MANIFEST, ex, cache, clock)
    clock.advance(5 * 86400)
    stale = ensure_snapshot(MANIFEST, ex, cache, clock, offline=True)
    assert len(ex.syncs) == 1 and stale.snapshot_dir and not stale.failure
    assert [w.code for w in stale.warnings] == ["feeds-stale"]


def test_signature_abort_is_not_a_fallback(cache: Path) -> None:
    clock = FixedClock()
    ensure_snapshot(MANIFEST, SyncStub(good), cache, clock)
    clock.advance(2 * 86400)

    class Aborting(SyncStub):
        def sync_feeds(self, request: FeedsSyncRequest) -> PluginRunResult:
            raise ScanAborted("firma")

    with pytest.raises(ScanAborted):
        ensure_snapshot(MANIFEST, Aborting(None), cache, clock)
    assert len(snaps(cache)) == 1


def test_changed_image_digest_forces_sync(cache: Path) -> None:
    clock, ex = FixedClock(), SyncStub(good)
    ensure_snapshot(MANIFEST, ex, cache, clock)
    other = MANIFEST.model_copy(update={"image": MANIFEST.image[:-64] + "1" * 64})
    ensure_snapshot(other, ex, cache, clock)
    assert len(ex.syncs) == 2


def test_tampered_pointer_is_ignored(cache: Path) -> None:
    clock, ex = FixedClock(), SyncStub(good)
    ensure_snapshot(MANIFEST, ex, cache, clock)
    pointer = cache / "osv-scanner" / POINTER
    for text in ('{"dir":"../../etc","synced_at":"2026-01-01T00:00:00Z","image_digest":"x"}', "x"):
        pointer.write_text(text)
        out = ensure_snapshot(MANIFEST, ex, cache, clock)
        assert out.snapshot_dir and Path(out.snapshot_dir).parent == cache / "osv-scanner"
    assert len(ex.syncs) == 3


def test_cache_must_be_private(cache: Path) -> None:
    cache.mkdir(mode=0o700)
    cache.chmod(0o777)
    with pytest.raises(FeedsError):
        ensure_snapshot(MANIFEST, SyncStub(good), cache, FixedClock())
    assert oct(os.stat(cache).st_mode & 0o777) == "0o777"  # non lo "ripara" in silenzio


def test_manifest_without_feeds_is_refused(cache: Path) -> None:
    plain = MANIFEST.model_copy(update={"feeds": None})
    with pytest.raises(ValueError, match="feeds"):
        ensure_snapshot(plain, SyncStub(good), cache, FixedClock())


def test_real_executor_sync_has_network_and_no_workspace_scan_has_no_network(
    cache: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Invariante "codice o rete" sui comandi reali di `OciExecutor`, con il client sostituito."""
    monkeypatch.setattr("ca_plugins.runner.FEEDS_MIN_FREE_BYTES", 0)  # indipendente dal disco
    created: list[list[str]] = []

    class Recording(OciExecutor):
        def _detect(self) -> None:
            self._isolation = Isolation.HARDENED_CONTAINER
            self._cli_path = "/bin/false"

        def _cli(self, *args: str, timeout: float = 0) -> subprocess.CompletedProcess[bytes]:
            if args[0] == "create" and not any(a.startswith("ca-hold-") for a in args):
                created.append(list(args))  # la custodia di /out non è il plugin
            code = 0 if args[0] in {"create", "start", "wait", "kill", "rm", "volume"} else 1
            out = b"0 false" if args[0] == "inspect" else b""
            return subprocess.CompletedProcess(args, code, out, b"")

    ws = tmp_path / "ws"
    ws.mkdir()
    with Recording(work_dir=str(tmp_path)) as ex:
        out = ensure_snapshot(MANIFEST, ex, cache, FixedClock())
        assert out.failure  # nessun file scritto: snapshot vuoto rifiutato
        ex.run(PluginRunRequest(manifest=MANIFEST, workspace=str(ws), feeds_snapshot=str(ws)))
    sync, scan = created
    assert "--network" not in sync and not any("dst=/workspace" in a for a in sync)
    assert sync[sync.index("--entrypoint") + 1] == MANIFEST.feeds.sync_command[0]  # type: ignore[union-attr]
    assert scan[scan.index("--network") + 1] == "none" and any("dst=/workspace" in a for a in scan)


# --- R-09: tetto di byte nella richiesta, `purge_feeds` e guardia (ADR-0006) ----------------


def locked_tree(snap: Path) -> None:
    """Come un plugin 65534: sottodirectory 0555 con un file, non eliminabile con `rmtree`."""
    good(snap)
    (snap / "locked").mkdir()
    (snap / "locked" / "f").write_text("x")
    (snap / "locked").chmod(0o555)


class PurgingStub(SyncStub):
    """Come il container di `purge_feeds`: restituisce i permessi e svuota la cartella."""

    def purge_feeds(self, request: FeedsPurgeRequest) -> None:
        super().purge_feeds(request)
        for current, dirs, _ in os.walk(request.snapshot_dir):
            for d in dirs:
                (Path(current) / d).chmod(0o700)


@pytest.fixture(autouse=True)
def _unlock(cache: Path) -> object:
    yield
    for path in cache.rglob("*") if cache.exists() else []:
        if path.is_dir() and not path.is_symlink():
            path.chmod(0o755)


def test_sync_request_carries_max_bytes(cache: Path) -> None:
    ex = SyncStub(good)
    ensure_snapshot(MANIFEST, ex, cache, FixedClock(), max_bytes=1234)
    assert ex.syncs[0].max_bytes == 1234
    with pytest.raises(ValueError):
        FeedsSyncRequest(manifest=MANIFEST, snapshot_dir="/s", max_bytes=0)
    with pytest.raises(ValueError):
        FeedsSyncRequest.model_validate({"manifest": MANIFEST, "snapshot_dir": "/s"})


def test_failed_sync_with_undeletable_tree_asks_the_executor_to_purge(cache: Path) -> None:
    clock = FixedClock()
    first = ensure_snapshot(MANIFEST, SyncStub(good), cache, clock)
    clock.advance(2 * 86400)
    ex = PurgingStub(locked_tree, RunOutcome.FAILED)
    out = ensure_snapshot(MANIFEST, ex, cache, clock)
    assert out.snapshot_dir == first.snapshot_dir and out.feed and out.feed.sync_failed
    assert [Path(p.snapshot_dir).name for p in ex.purges] == [Path(ex.syncs[0].snapshot_dir).name]
    assert len(snaps(cache)) == 1  # la cartella scartata è sparita davvero


def test_purge_is_not_called_when_the_host_can_delete(cache: Path) -> None:
    clock = FixedClock()
    ensure_snapshot(MANIFEST, SyncStub(good), cache, clock)
    clock.advance(2 * 86400)
    ex = PurgingStub(good, RunOutcome.FAILED)
    ensure_snapshot(MANIFEST, ex, cache, clock)
    assert ex.purges == []


def test_prune_purges_old_snapshots_the_host_cannot_delete(cache: Path) -> None:
    clock = FixedClock()
    ex = PurgingStub(locked_tree)
    ensure_snapshot(MANIFEST, ex, cache, clock)  # snapshot 1 (con directory bloccata)
    for _ in range(2):
        clock.advance(2 * 86400)
        ensure_snapshot(MANIFEST, ex, cache, clock)
    assert len(ex.purges) == 1 and len(snaps(cache)) == 2  # il primo è stato scartato e purgato


def test_interruption_or_abort_never_purges(cache: Path) -> None:
    class Interrupted(PurgingStub):
        def sync_feeds(self, request: FeedsSyncRequest) -> PluginRunResult:
            locked_tree(Path(request.snapshot_dir))
            raise KeyboardInterrupt

    ex = Interrupted(None)
    with pytest.raises(KeyboardInterrupt):
        ensure_snapshot(MANIFEST, ex, cache, FixedClock())
    assert ex.purges == []  # la cartella resta: la rimuove `_prune` alla prossima sincronizzazione


def test_fake_and_real_executors_implement_purge_feeds() -> None:
    assert callable(FakePluginExecutor().purge_feeds) and callable(OciExecutor.purge_feeds)


# --- N-03 / M-02 / B-07 di S-01 -------------------------------------------------------------


def hide(snap: Path) -> None:
    """File nascosti sotto una directory 000 (come un plugin 65534 ostile)."""
    (snap / "hidden" / "deeper").mkdir(parents=True)
    for i in range(5):
        (snap / "hidden" / "deeper" / f"empty-{i}").touch()
    (snap / "hidden").chmod(0o000)


def hidden_tree(snap: Path) -> None:
    good(snap)  # un feed valido accanto al sottoalbero nascosto
    hide(snap)


def test_tree_with_an_unreadable_subtree_is_never_published(cache: Path) -> None:
    ex = PurgingStub(hidden_tree)
    out = ensure_snapshot(MANIFEST, ex, cache, FixedClock())
    assert out.snapshot_dir is None and out.failure is not None
    assert not (cache / "osv-scanner" / POINTER).exists() and snaps(cache) == []
    assert len(ex.purges) == 1  # la cartella scartata è rimossa chiedendo all'esecutore


def test_unreadable_subtree_keeps_the_previous_snapshot(cache: Path) -> None:
    clock = FixedClock()
    first = ensure_snapshot(MANIFEST, SyncStub(good), cache, clock)
    clock.advance(2 * 86400)
    out = ensure_snapshot(MANIFEST, PurgingStub(hidden_tree), cache, clock)
    assert out.snapshot_dir == first.snapshot_dir and out.feed and out.feed.sync_failed


def test_validate_tree_accepts_a_readable_tree_and_rejects_unreadable_or_vanished(
    tmp_path: Path,
) -> None:
    good(tmp_path)
    assert _validate_tree(tmp_path, 10**6)  # controllo positivo
    hide(tmp_path)
    try:
        assert not _validate_tree(tmp_path, 10**6)
    finally:
        (tmp_path / "hidden").chmod(0o700)


def test_prune_never_follows_a_snap_symlink(cache: Path, tmp_path: Path) -> None:
    clock = FixedClock()
    ex = PurgingStub(good)
    ensure_snapshot(MANIFEST, ex, cache, clock)
    target = tmp_path / "elsewhere"
    target.mkdir()
    (target / "keep").write_text("x")
    (cache / "osv-scanner" / "snap-AAAAAAAA").symlink_to(target)
    clock.advance(2 * 86400)
    ensure_snapshot(MANIFEST, ex, cache, clock)
    assert ex.purges == [] and (target / "keep").exists()  # nessun montaggio della destinazione
    assert not (cache / "osv-scanner" / "snap-AAAAAAAA").is_symlink()
