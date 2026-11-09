"""`SourceReader` locale per il workspace (R-08). Il codice analizzato è ostile.

Ogni apertura è relativa a un descrittore di directory (`openat`) con `O_NOFOLLOW`, componente per
componente: nessun controllo "prima" seguito da un'apertura "poi" sullo stesso percorso, quindi uno
scambio di una directory con un symlink durante la lettura dà un errore, mai una fuga dalla radice.
Come per `/out` (ADR-0004) nessun symlink è seguito, nemmeno se punta dentro la radice.

La radice è scelta dall'utente, non dal repository: l'ultimo componente non può essere un symlink
(`O_NOFOLLOW`), i genitori sì (il chiamante può passare `Path.resolve()`).

Limiti noti: un hard link a un file esterno è un file regolare e non è distinguibile da un file
della radice; lo impedisce il sistema (`fs.protected_hardlinks`) e l'estrazione del repository, non
questo lettore. Una scrittura concorrente nello stesso file può troncarne o allungarne la lettura:
la lettura non va mai oltre `max_bytes`.
"""

import os
from collections.abc import Sequence

from ca_core.pipeline.exclusions import is_excluded
from ca_core.ports import SourceError, SourceTooLarge
from ca_plugins.runner import _READ_CHUNK, PLUGIN_GID, PLUGIN_UID, _open_dir, _open_regular

_DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
MAX_DEPTH = 128
MAX_FILES = 1_000_000


def _segments(path: str) -> list[str]:
    parts = path.split("/")
    if not path or "\x00" in path or any(p in ("", ".", "..") for p in parts):
        raise SourceError("percorso non relativo o fuori dalla radice")
    return parts


class LocalSourceReader:
    """File regolari sotto `root`, sottodirectory incluse, senza seguire alcun symlink."""

    def __init__(self, *, max_files: int = MAX_FILES, max_depth: int = MAX_DEPTH) -> None:
        self._max_files = max_files
        self._max_depth = max_depth

    def list_files(self, root: str) -> list[str]:
        found: list[str] = []
        root_fd = _open_dir(root)
        try:
            self._walk(root_fd, "", 0, found)
        finally:
            os.close(root_fd)
        return sorted(found)

    def _walk(self, dir_fd: int, prefix: str, depth: int, found: list[str]) -> None:
        if depth > self._max_depth:
            raise SourceError("directory annidate oltre il limite")
        subdirs: list[str] = []
        with os.scandir(dir_fd) as it:
            for entry in it:
                try:
                    if entry.is_dir(follow_symlinks=False):
                        subdirs.append(entry.name)
                    elif entry.is_file(follow_symlinks=False):  # symlink, FIFO, socket: omessi
                        found.append(prefix + entry.name)
                except OSError:
                    continue  # voce sparita durante la lettura
        if len(found) > self._max_files:
            raise SourceError("troppi file nella radice")
        for name in subdirs:
            try:
                child = os.open(name, _DIR_FLAGS, dir_fd=dir_fd)
            except OSError:  # scambiata con un symlink, rimossa o illeggibile: omessa
                continue
            try:
                self._walk(child, f"{prefix}{name}/", depth + 1, found)
            finally:
                os.close(child)

    def read_file(self, root: str, path: str, max_bytes: int) -> bytes:
        *dirs, name = _segments(path)
        fds = [_open_dir(root)]
        try:
            for part in dirs:
                try:
                    fds.append(os.open(part, _DIR_FLAGS, dir_fd=fds[-1]))
                except OSError as exc:  # ELOOP (symlink), ENOENT, ENOTDIR
                    raise SourceError("directory assente o symlink") from exc
            fd, _ = _open_regular(fds[-1], name, max_bytes)
        finally:
            for open_fd in fds:
                os.close(open_fd)
        try:
            chunks: list[bytes] = []
            total = 0
            while total <= max_bytes:  # al più max_bytes + 1: se arriva, il file è cresciuto
                chunk = os.read(fd, min(_READ_CHUNK, max_bytes + 1 - total))
                if not chunk:
                    return b"".join(chunks)
                chunks.append(chunk)
                total += len(chunk)
            raise SourceTooLarge("file oltre il limite")
        finally:
            os.close(fd)


def plugin_can_read(mode: int, uid: int, gid: int, *, is_dir: bool) -> bool:
    """Se `PLUGIN_UID:PLUGIN_GID` legge: una sola classe di permessi, come Linux (non si sommano).

    File: bit `r`. Directory: `r` e `x`. Le ACL POSIX non sono considerate (ADR-0004).
    """
    if uid == PLUGIN_UID:
        bits = (mode >> 6) & 7
    elif gid == PLUGIN_GID:
        bits = (mode >> 3) & 7
    else:
        bits = mode & 7
    return bool(bits & 4) and (not is_dir or bool(bits & 1))


def count_unreadable(root: str, excluded: Sequence[str]) -> int:
    """Percorsi analizzabili sotto `root` (radice inclusa) che il plugin non può leggere.

    Analizzabili: file regolari e directory, senza seguire symlink; FIFO, socket e dispositivi no.
    I percorsi esclusi non si contano né si visitano. Conta chi non è leggibile o ha un antenato
    non leggibile; una directory che l'host non apre conta una volta. Mai nomi: solo il numero.
    `SourceError` oltre `MAX_FILES` e `MAX_DEPTH`.
    """
    root_fd = _open_dir(root)
    try:
        info = os.fstat(root_fd)
        bad = not plugin_can_read(info.st_mode, info.st_uid, info.st_gid, is_dir=True)
        return int(bad) + _count_dir(root_fd, "", 0, bad, excluded, [1])
    finally:
        os.close(root_fd)


def _count_dir(
    dir_fd: int,
    prefix: str,
    depth: int,
    ancestor_bad: bool,
    excluded: Sequence[str],
    seen: list[int],
) -> int:
    if depth > MAX_DEPTH:
        raise SourceError("directory annidate oltre il limite")
    count = 0
    subdirs: list[tuple[str, bool]] = []  # (nome, già contata)
    try:
        with os.scandir(dir_fd) as it:
            entries = list(it)
    except OSError:
        return 0  # già contata da chi ci è sceso
    for entry in entries:
        rel = prefix + entry.name
        try:
            if entry.is_symlink() or is_excluded(rel, excluded):
                continue
            is_dir = entry.is_dir(follow_symlinks=False)
            if not is_dir and not entry.is_file(follow_symlinks=False):
                continue
            info = entry.stat(follow_symlinks=False)
        except OSError:
            continue  # voce sparita durante la lettura
        seen[0] += 1
        if seen[0] > MAX_FILES:
            raise SourceError("troppi file nella radice")
        bad = ancestor_bad or not plugin_can_read(
            info.st_mode, info.st_uid, info.st_gid, is_dir=is_dir
        )
        count += int(bad)
        if is_dir:
            subdirs.append((entry.name, bad))
    for name, bad in subdirs:
        try:
            child = os.open(name, _DIR_FLAGS, dir_fd=dir_fd)
        except OSError:
            count += int(not bad)  # l'host non la apre: conta una volta
            continue
        try:
            count += _count_dir(child, f"{prefix}{name}/", depth + 1, bad, excluded, seen)
        finally:
            os.close(child)
    return count


# Nomi di lockfile (npm e PyPI: osv-scanner, trivy) ed estensioni dei sorgenti che semgrep e bandit
# analizzano. Un symlink con uno di questi nomi non viene analizzato dagli scanner (N-10).
LOCKFILE_NAMES = frozenset(
    {
        "package-lock.json",
        "npm-shrinkwrap.json",
        "yarn.lock",
        "pnpm-lock.yaml",
        "poetry.lock",
        "pipfile.lock",
        "uv.lock",
        "pdm.lock",
        "requirements.txt",
    }
)
SOURCE_EXTENSIONS = frozenset(
    {".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".mts", ".cts", ".py", ".pyi"}
)


def _is_analyzed_name(name: str) -> bool:
    lower = name.lower()
    return lower in LOCKFILE_NAMES or os.path.splitext(lower)[1] in SOURCE_EXTENSIONS


def count_skipped_symlinks(root: str, excluded: Sequence[str]) -> int:
    """Symlink sotto `root` con nome di lockfile o estensione sorgente analizzata (N-10, N-10b).

    Gli scanner non seguono questi collegamenti: il file che indicano non e' analizzato e il
    risultato sarebbe vuoto senza traccia. Non si seguono link; i percorsi esclusi non si contano
    ne' si visitano. Mai nomi: solo il numero. `SourceError` oltre `MAX_FILES` e `MAX_DEPTH`.
    """
    root_fd = _open_dir(root)
    try:
        return _count_links(root_fd, "", 0, excluded, [1])
    finally:
        os.close(root_fd)


def _count_links(
    dir_fd: int, prefix: str, depth: int, excluded: Sequence[str], seen: list[int]
) -> int:
    if depth > MAX_DEPTH:
        raise SourceError("directory annidate oltre il limite")
    try:
        with os.scandir(dir_fd) as it:
            entries = list(it)
    except OSError:
        return 0
    count = 0
    subdirs: list[str] = []
    for entry in entries:
        rel = prefix + entry.name
        try:
            if is_excluded(rel, excluded):
                continue
            link = entry.is_symlink()
            is_dir = not link and entry.is_dir(follow_symlinks=False)
        except OSError:
            continue
        seen[0] += 1
        if seen[0] > MAX_FILES:
            raise SourceError("troppi file nella radice")
        if link:
            count += int(_is_analyzed_name(entry.name))
        elif is_dir:
            subdirs.append(entry.name)
    for name in subdirs:
        try:
            child = os.open(name, _DIR_FLAGS, dir_fd=dir_fd)
        except OSError:
            continue  # gia' contata da `count_unreadable`
        try:
            count += _count_links(child, f"{prefix}{name}/", depth + 1, excluded, seen)
        finally:
            os.close(child)
    return count


__all__ = [
    "LOCKFILE_NAMES",
    "SOURCE_EXTENSIONS",
    "LocalSourceReader",
    "count_skipped_symlinks",
    "count_unreadable",
    "plugin_can_read",
]
