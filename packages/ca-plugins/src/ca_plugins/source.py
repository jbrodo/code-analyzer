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

from ca_core.ports import SourceError, SourceTooLarge
from ca_plugins.runner import _READ_CHUNK, _open_dir, _open_regular

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


__all__ = ["LocalSourceReader"]
