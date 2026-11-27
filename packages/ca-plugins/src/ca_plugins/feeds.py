"""Sincronizzazione dei feed di vulnerabilità (R-06, ADR-0006 con gli emendamenti).

Invariante: un container ha il codice o la rete, mai entrambi. Qui la rete serve solo a
`PluginExecutor.sync_feeds`, che non monta il workspace; `FeedsSyncRequest` non ha nemmeno un campo
per il workspace e non porta alcun dato derivato dal repository (l'elenco degli ecosistemi è nel
manifest). La verifica della firma (R-04) è del verificatore dell'esecutore, prima di ogni
container: un `ScanAborted` non si cattura qui, né ripiega sullo snapshot precedente.

Cache per utente: `<cache>/<plugin>/current.json` punta a `snap-*`, una cartella nuova per ogni
sincronizzazione. Lo snapshot scaricato è non fidato: si scambia il puntatore (scrittura atomica)
solo se il container ha avuto successo e l'albero contiene soli file regolari e directory, senza
symlink, entro un limite di byte; altrimenti la cartella nuova è rimossa e il puntatore resta.
Il puntatore e la cache sono letti come dati non fidati (nome confinato, `O_NOFOLLOW`, limite).

Scelte conservative: una cache non posseduta dall'utente o scrivibile da altri è rifiutata; il
digest dell'immagine diverso da quello dello snapshot lo rende da rinnovare ma ancora utilizzabile
come ripiego; con `offline` si usa lo snapshot esistente, anche vecchio (avviso `feeds-stale`).
Il contenuto interno dello snapshot (layout per ecosistema) non è verificato: lo controlla
l'adattatore del plugin (ADR-0006, `could not load db`).
"""

import contextlib
import hashlib
import os
import re
import shutil
import stat
import tempfile
from datetime import timedelta
from pathlib import Path
from typing import Literal

from pydantic import AwareDatetime, BaseModel, ConfigDict, ValidationError

from ca_core.models import PackagedPluginManifest
from ca_core.models.scan_report import FeedSnapshot, Warning_
from ca_core.ports import Clock, FeedsPurgeRequest, FeedsSyncRequest, PluginExecutor, RunOutcome

POINTER = "current.json"
DEFAULT_MAX_AGE = timedelta(days=1)
DEFAULT_MAX_BYTES = 8 * 1024**3  # trivy: 1,6 GB; osv-scanner npm+PyPI: 250 MB (V-05)
_SNAP = re.compile(r"^snap-[A-Za-z0-9_]{8}$")
_POINTER_MAX = 4096


class FeedsError(RuntimeError):
    """Cache non utilizzabile (proprietario o permessi): da trattare come errore di ambiente."""


class _Pointer(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    dir: str
    synced_at: AwareDatetime
    image_digest: str
    # Etichetta per il report e impronta delle opzioni di origine: mai l'indirizzo. I puntatori
    # precedenti a E-04 non li hanno e valgono come origine pubblica.
    origin: Literal["public", "mirror"] = "public"
    origin_key: str = ""


class FeedsOutcome(BaseModel):
    """`snapshot_dir` None: nessuno snapshot utilizzabile, il plugin fallisce con `failure`."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    snapshot_dir: str | None
    feed: FeedSnapshot | None
    warnings: list[Warning_]
    failure: str | None


def default_cache_dir(environ: dict[str, str] | None = None) -> Path:
    env = os.environ if environ is None else environ
    base = env.get("XDG_CACHE_HOME") or str(Path.home() / ".cache")
    return Path(base) / "code-analyzer" / "feeds"


def _private_dir(path: Path) -> None:
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o022:
        raise FeedsError(f"cache dei feed non privata: {path.name}")


def _load(plugin_dir: Path) -> _Pointer | None:
    try:
        fd = os.open(plugin_dir / POINTER, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except OSError:
        return None
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            return None
        raw = os.read(fd, _POINTER_MAX + 1)
    finally:
        os.close(fd)
    if len(raw) > _POINTER_MAX:
        return None
    try:
        pointer = _Pointer.model_validate_json(raw)
    except ValidationError:
        return None
    target = plugin_dir / pointer.dir
    if not _SNAP.fullmatch(pointer.dir) or not stat.S_ISDIR(_lstat_mode(target)):
        return None
    return pointer


def _lstat_mode(path: Path) -> int:
    try:
        return path.lstat().st_mode
    except OSError:
        return 0


def _validate_tree(root: Path, max_bytes: int) -> bool:
    """Soli file regolari e directory, nessun symlink, almeno un file, entro `max_bytes`.

    Qualunque errore di attraversamento (directory illeggibile, voce sparita) è un rifiuto: un
    sottoalbero che l'host non legge non si può controllare, quindi non si pubblica (M-02, N-03).
    """
    files = total = 0
    failed = False

    def onerror(_: OSError) -> None:
        nonlocal failed
        failed = True

    try:
        for current, dirs, names in os.walk(root, followlinks=False, onerror=onerror):
            for entry in [*dirs, *names]:
                mode = (Path(current) / entry).lstat().st_mode
                if not (stat.S_ISDIR(mode) or stat.S_ISREG(mode)):  # symlink compresi
                    return False
            for name in names:
                files += 1
                total += (Path(current) / name).lstat().st_size
            if total > max_bytes:
                return False
    except OSError:
        return False
    return files > 0 and not failed


def _publish(plugin_dir: Path, pointer: _Pointer) -> None:
    fd, tmp = tempfile.mkstemp(prefix="pointer-", dir=plugin_dir)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(pointer.model_dump_json())
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp, plugin_dir / POINTER)  # atomico: lo scambio avviene solo qui
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(tmp)
        raise


def _discard(path: Path, manifest: PackagedPluginManifest, executor: PluginExecutor) -> None:
    """Rimuove una cartella scartata (ADR-0006, M-01): file di 65534 in sottodirectory 0755 non
    sono eliminabili dall'host, quindi dopo un `rmtree` fallito si chiede all'esecutore.

    Non si chiama con un `ScanAborted` o un'interruzione in corso: l'immagine può non essere
    verificata, e la cartella resta alla prossima sincronizzazione, che la rimuove con `_prune`.
    """
    shutil.rmtree(path, ignore_errors=True)
    if path.exists():
        executor.purge_feeds(FeedsPurgeRequest(manifest=manifest, snapshot_dir=str(path)))
        shutil.rmtree(path, ignore_errors=True)


def _prune(
    plugin_dir: Path,
    keep: str,
    previous: str | None,
    manifest: PackagedPluginManifest,
    executor: PluginExecutor,
) -> None:
    kept = {keep, previous}
    for entry in plugin_dir.iterdir():
        if _SNAP.fullmatch(entry.name) and entry.name not in kept:
            if stat.S_ISLNK(_lstat_mode(entry)):  # B-07: mai seguire un link, nemmeno per purgare
                with contextlib.suppress(OSError):
                    entry.unlink()
            else:
                _discard(entry, manifest, executor)


def _warning(code: str, message: str, subject: str) -> Warning_:
    return Warning_(code=code, message=message, subject=subject)


def _use(
    pointer: _Pointer, plugin_dir: Path, *, failed: bool, warnings: list[Warning_]
) -> FeedsOutcome:
    return FeedsOutcome(
        snapshot_dir=str(plugin_dir / pointer.dir),
        feed=FeedSnapshot(origin=pointer.origin, synced_at=pointer.synced_at, sync_failed=failed),
        warnings=warnings,
        failure=None,
    )


def ensure_snapshot(
    manifest: PackagedPluginManifest,
    executor: PluginExecutor,
    cache_dir: Path,
    clock: Clock,
    *,
    max_age: timedelta = DEFAULT_MAX_AGE,
    offline: bool = False,
    max_bytes: int = DEFAULT_MAX_BYTES,
    origin_args: tuple[str, ...] = (),
) -> FeedsOutcome:
    """Snapshot da montare in `/feeds` per `manifest`, sincronizzando se manca, è vecchio o viene
    da un'altra origine. `origin_args` sono le opzioni di un'origine diversa da quella del
    pacchetto (`origins.FeedOrigins.sync_args`). Se la sincronizzazione non riesce si ripiega
    sullo snapshot precedente, che nel report conserva l'etichetta della sua origine."""
    if manifest.feeds is None:
        raise ValueError("il manifest non ha feeds")
    name = manifest.name
    digest = manifest.image.rpartition("@")[2]
    origin: Literal["public", "mirror"] = "mirror" if origin_args else "public"
    origin_key = hashlib.sha256("\n".join(origin_args).encode()).hexdigest() if origin_args else ""
    _private_dir(cache_dir)
    plugin_dir = cache_dir / name
    _private_dir(plugin_dir)

    current = _load(plugin_dir)
    now = clock.now()
    fresh = (
        current is not None
        and current.image_digest == digest
        and current.origin_key == origin_key
        and timedelta(0) <= now - current.synced_at <= max_age
    )
    if current is not None and fresh:
        return _use(current, plugin_dir, failed=False, warnings=[])
    if offline:
        if current is None:
            return FeedsOutcome(
                snapshot_dir=None,
                feed=None,
                warnings=[],
                failure="feeds: modalità offline e nessuno snapshot",
            )
        stale = _warning("feeds-stale", "snapshot dei feed non aggiornato (offline)", name)
        return _use(current, plugin_dir, failed=False, warnings=[stale])

    new_dir = Path(tempfile.mkdtemp(prefix="snap-", dir=plugin_dir))
    new_dir.chmod(0o777)  # scrivibile dal plugin (65534); il padre 0700 lo isola dagli altri
    published = False
    try:
        # ScanAborted (firma) e RuntimeUnavailable si propagano: nessun ripiego.
        result = executor.sync_feeds(
            FeedsSyncRequest(
                manifest=manifest,
                snapshot_dir=str(new_dir),
                max_bytes=max_bytes,
                origin_args=origin_args,
            )
        )
        if result.outcome is RunOutcome.OK and _validate_tree(new_dir, max_bytes):
            pointer = _Pointer(
                dir=new_dir.name,
                synced_at=clock.now(),
                image_digest=digest,
                origin=origin,
                origin_key=origin_key,
            )
            _publish(plugin_dir, pointer)
            published = True
            _prune(plugin_dir, new_dir.name, current.dir if current else None, manifest, executor)
            return _use(pointer, plugin_dir, failed=False, warnings=[])
    except BaseException:
        if not published:
            shutil.rmtree(new_dir, ignore_errors=True)  # senza purge: interruzione o firma
        raise
    _discard(new_dir, manifest, executor)

    if current is None:
        return FeedsOutcome(
            snapshot_dir=None,
            feed=None,
            warnings=[],
            failure="feeds: sincronizzazione fallita e nessuno snapshot",
        )
    warning = _warning(
        "feeds-sync-failed", "sincronizzazione dei feed fallita: snapshot precedente", name
    )
    return _use(current, plugin_dir, failed=True, warnings=[warning])
