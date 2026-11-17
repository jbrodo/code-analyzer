"""Adattatore su file system della porta `ArtifactStore` (B-07, ADR-0030): sviluppo, test, pilota.

La chiave la costruisce il server da valori che controlla e si valida di nuovo qui prima di comporre
un percorso (`validate_artifact_key`): mai un nome di file ricevuto dal client. Ogni componente si
apre con `O_NOFOLLOW` relativo al precedente, quindi un collegamento simbolico non porta fuori dalla
radice. Cartelle 0700 e file 0600, di proprietà dell'utente del server; una radice non privata è un
errore. Scrittura su file temporaneo nella stessa cartella e `link` atomico (fallisce se la chiave
esiste, quindi nessuna sovrascrittura, nemmeno in corsa): contenuto uguale è una ripetizione,
diverso è `ArtifactConflict`. Il digest si calcola mentre si scrive.
"""

import contextlib
import hashlib
import os
import stat
import uuid
from pathlib import Path
from typing import BinaryIO

from ca_core.ports import (
    ArtifactConflict,
    ArtifactIntegrityError,
    ArtifactNotFound,
    ArtifactTooLarge,
    StoredArtifact,
    validate_artifact_key,
)

CHUNK = 1024 * 1024
_DIR = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC


class StorageError(RuntimeError):
    """Radice non utilizzabile (proprietario o permessi): errore di ambiente."""


def _digest_of(fd: int) -> str:
    sha = hashlib.sha256()
    os.lseek(fd, 0, os.SEEK_SET)
    while chunk := os.read(fd, CHUNK):
        sha.update(chunk)
    return sha.hexdigest()


class FileSystemArtifactStore:
    def __init__(self, root: str | Path) -> None:
        self._root = Path(root)
        self._root.mkdir(mode=0o700, parents=True, exist_ok=True)
        info = self._root.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
            raise StorageError("radice dell'archivio non privata")

    # --- percorsi: un componente alla volta, senza seguire collegamenti ---------------------------

    def _open_dir(self, parts: list[str], *, create: bool) -> list[int]:
        fds = [os.open(self._root, _DIR)]
        try:
            for part in parts:
                if create:
                    with contextlib.suppress(FileExistsError):
                        os.mkdir(part, 0o700, dir_fd=fds[-1])
                fds.append(os.open(part, _DIR, dir_fd=fds[-1]))
        except OSError:
            for fd in fds:
                os.close(fd)
            raise
        return fds

    @staticmethod
    def _close(fds: list[int]) -> None:
        for fd in fds:
            os.close(fd)

    # --- porta -----------------------------------------------------------------------------------

    def put(
        self, key: str, stream: BinaryIO, *, max_bytes: int, sha256: str | None = None
    ) -> StoredArtifact:
        validate_artifact_key(key)
        if max_bytes < 1:
            raise ValueError("max_bytes deve essere positivo")
        *parents, name = key.split("/")
        fds = self._open_dir(parents, create=True)
        temp = f".tmp-{uuid.uuid4().hex}"
        directory = fds[-1]
        try:
            fd = os.open(
                temp,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                0o600,
                dir_fd=directory,
            )
            sha, size = hashlib.sha256(), 0
            try:
                with os.fdopen(fd, "wb") as target:
                    while chunk := stream.read(min(CHUNK, max_bytes + 1 - size)):
                        size += len(chunk)
                        if size > max_bytes:
                            raise ArtifactTooLarge(f"oltre {max_bytes} byte")
                        sha.update(chunk)
                        target.write(chunk)
                digest = sha.hexdigest()
                if sha256 is not None and sha256 != digest:
                    raise ArtifactIntegrityError("sha256 dichiarato diverso da quello dei byte")
                try:
                    os.link(temp, name, src_dir_fd=directory, dst_dir_fd=directory)
                except FileExistsError:
                    if self._existing_digest(directory, name) != digest:
                        raise ArtifactConflict("la chiave esiste con contenuto diverso") from None
            finally:
                with contextlib.suppress(FileNotFoundError):
                    os.unlink(temp, dir_fd=directory)
            return StoredArtifact(key=key, size=size, sha256=digest)
        finally:
            self._close(fds)

    @staticmethod
    def _existing_digest(directory: int, name: str) -> str:
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=directory)
        try:
            if not stat.S_ISREG(os.fstat(fd).st_mode):
                raise ArtifactConflict("la chiave non è un file regolare")
            return _digest_of(fd)
        finally:
            os.close(fd)

    def open(self, key: str) -> BinaryIO:
        validate_artifact_key(key)
        *parents, name = key.split("/")
        try:
            fds = self._open_dir(parents, create=False)
        except OSError as exc:
            raise ArtifactNotFound(key) from exc
        try:
            fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fds[-1])
        except OSError as exc:
            raise ArtifactNotFound(key) from exc
        finally:
            self._close(fds)
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            os.close(fd)
            raise ArtifactNotFound(key)
        return os.fdopen(fd, "rb")

    def exists(self, key: str) -> bool:
        try:
            self.open(key).close()
        except ArtifactNotFound:
            return False
        return True

    def delete(self, key: str) -> None:
        validate_artifact_key(key)
        *parents, name = key.split("/")
        try:
            fds = self._open_dir(parents, create=False)
        except OSError:
            return
        try:
            with contextlib.suppress(FileNotFoundError, IsADirectoryError):
                os.unlink(name, dir_fd=fds[-1])
        finally:
            self._close(fds)
