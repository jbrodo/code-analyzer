"""Radice di composizione (ADR-0001): l'unico punto in cui si scelgono gli adattatori delle porte.

`ca-core` non conosce Docker né il disco; qui si collegano `PluginExecutor`, `SourceReader`,
`ArtifactSink` e `Clock`. Nessuna di queste costruzioni tocca il daemon o il disco: il runtime
OCI si rileva alla prima esecuzione, quindi `--help` e `config validate` funzionano anche senza.
"""

import os
import stat
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from ca_core.ports import (
    ArtifactRef,
    ArtifactSink,
    Clock,
    PluginExecutor,
    SourceReader,
)
from ca_plugins.runner import OciExecutor
from ca_plugins.signature import CosignVerifier, allow_unsigned_from_env
from ca_plugins.source import LocalSourceReader


class SystemClock:
    def now(self) -> datetime:
        return datetime.now(UTC)


class DirectoryArtifactSink:
    """Scrive artefatti sotto `base`, mai fuori: nome relativo, nessun symlink seguito.

    `base` è scelta dall'utente (`--output-dir`); i nomi vengono dalla pipeline, ma restano
    validati. Ogni componente si apre con `O_NOFOLLOW` relativo al precedente; il file con
    `O_TRUNC` (un rilancio sovrascrive i propri artefatti, ADR-0010).
    """

    _DIR = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC

    def __init__(self, base: str) -> None:
        self._base = Path(base)

    def write(self, name: str, content: bytes) -> ArtifactRef:
        parts = name.split("/")
        if not name or "\x00" in name or any(p in ("", ".", "..") for p in parts):
            raise ValueError(f"percorso non relativo o fuori dall'area: {name!r}")
        self._base.mkdir(parents=True, exist_ok=True)
        fds = [os.open(self._base, self._DIR)]
        try:
            for part in parts[:-1]:
                try:
                    os.mkdir(part, 0o755, dir_fd=fds[-1])
                except FileExistsError:
                    pass
                fds.append(os.open(part, self._DIR, dir_fd=fds[-1]))
            fd = os.open(
                parts[-1],
                os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW | os.O_CLOEXEC,
                0o644,
                dir_fd=fds[-1],
            )
            with os.fdopen(fd, "wb") as target:
                if not stat.S_ISREG(os.fstat(target.fileno()).st_mode):
                    raise ValueError(f"non è un file regolare: {name!r}")
                target.write(content)
        except OSError as exc:
            raise ValueError(f"scrittura rifiutata: {name!r}") from exc
        finally:
            for open_fd in fds:
                os.close(open_fd)
        return ArtifactRef(name=name, location=str(self._base.resolve() / name), size=len(content))


@dataclass(frozen=True)
class Context:
    """Porte collegate, passate ai gestori dei comandi."""

    executor: PluginExecutor
    source: SourceReader
    clock: Clock

    @staticmethod
    def artifact_sink(output_dir: str) -> ArtifactSink:
        return DirectoryArtifactSink(output_dir)


def build_context(
    *,
    public_key: str | None = None,
    cosign: str | None = None,
    allow_http_registry: bool = False,
    environ: Mapping[str, str] | None = None,
) -> Context:
    """`allow_http_registry` solo da chi cabla (registry locale), mai da `.code-analyzer.yml`.

    Senza chiave pubblica (D-0005 aperta: nessuna nel pacchetto) la prima esecuzione esce con 2,
    salvo `CA_INSECURE_ALLOW_UNSIGNED=1`, che segna `signature: skipped`.
    """
    env = os.environ if environ is None else environ
    verifier = CosignVerifier(
        public_key=public_key or env.get("CA_COSIGN_PUBLIC_KEY"),
        cosign=cosign or env.get("COSIGN"),
        allow_http_registry=allow_http_registry,
        allow_unsigned=allow_unsigned_from_env(env),
    )
    return Context(
        executor=OciExecutor(verifier=verifier), source=LocalSourceReader(), clock=SystemClock()
    )
