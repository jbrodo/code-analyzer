"""Modalità immagine CLI (I-01; ADR-0004, emendamento per I-03, M-11).

Con la CLI in un container e il socket del daemon montato, i plugin sono container fratelli: i
sorgenti dei `--mount` li risolve il daemon sull'host. Tre variabili d'ambiente, tutte o nessuna,
danno il percorso host dei tre montaggi che hanno destinazione fissa nell'immagine. Valgono solo
dall'ambiente, mai da `.code-analyzer.yml` (ADR-0014).

`translate` fallisce chiusa: un percorso fuori dalla radice del proprio tipo è `ScanAborted`,
senza ripiego. La prova che le radici viste dalla CLI sono le stesse viste dal daemon è
dell'esecutore (`OciExecutor`), che è l'unico a parlare con il runtime.
"""

import os
import shutil
import stat
import time
from collections.abc import Iterator, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Final, Literal

from ca_core.ports import ScanAborted

Kind = Literal["workspace", "inputs", "snapshot"]

ENV: Final[dict[Kind, str]] = {
    "workspace": "CA_HOST_WORKSPACE",
    "inputs": "CA_HOST_WORK",
    "snapshot": "CA_HOST_CACHE",
}
ROOTS: Final[dict[Kind, str]] = {
    "workspace": "/ca/workspace",
    "inputs": "/ca/work",
    "snapshot": "/ca/cache",
}
OUTPUT_ROOT: Final = "/ca/output"
IMAGE_MARKER: Final = "CA_CLI_IMAGE"  # impostata dal Dockerfile dell'immagine CLI
# Un percorso host uguale a uno di questi, o loro antenato, darebbe ai plugin il socket del
# daemon o i file system del kernel (N-32).
FORBIDDEN_HOST: Final = ("/", "/run", "/var/run", "/proc", "/sys")
PLUGIN_UID: Final = 65534
WORK_PREFIX: Final = "ca-oci-"
WORK_MAX_AGE_SECONDS: Final = 24 * 3600


class HostPathsError(RuntimeError):
    """Modalità immagine non utilizzabile: exit 2 prima di qualunque container."""

    exit_code = 2


def _covers(candidate: Path, target: Path) -> bool:
    """`candidate` è `target` o un suo antenato: montarlo esporrebbe `target`."""
    return candidate == target or candidate in target.parents


def _host_path(name: str, value: str) -> Path:
    if not value.startswith("/") or os.path.normpath(value) != value or "\x00" in value:
        raise HostPathsError(f"{name} deve essere un percorso assoluto e normalizzato")
    path = Path(value)
    for forbidden in FORBIDDEN_HOST:
        if _covers(path, Path(forbidden)):
            raise HostPathsError(f"{name} non può essere {forbidden} né un suo antenato")
    return path


@dataclass(frozen=True)
class HostPaths:
    """Percorsi host dei tre montaggi. `roots` e `output` cambiano solo nei test."""

    hosts: Mapping[Kind, Path]
    roots: Mapping[Kind, Path] = field(
        default_factory=lambda: {kind: Path(root) for kind, root in ROOTS.items()}
    )
    output: Path = Path(OUTPUT_ROOT)

    def translate(self, kind: Kind, path: Path | str) -> Path:
        """Percorso visto dalla CLI -> percorso host, solo sotto la radice di `kind` (N-33)."""
        root = self.roots[kind]
        try:
            real = Path(os.path.realpath(path, strict=True))
        except (OSError, ValueError) as exc:
            raise ScanAborted(f"percorso di montaggio non risolvibile ({kind})") from exc
        if not real.is_relative_to(root):
            raise ScanAborted(f"percorso di montaggio fuori da {root} ({kind})")
        return self.hosts[kind] / real.relative_to(root)

    def check_container(self, mountinfo: str | None = None, uid: int | None = None) -> None:
        """Controlli dentro l'immagine, senza daemon: uid, radici reali e montate (N-32, N-39)."""
        if (os.getuid() if uid is None else uid) == PLUGIN_UID:
            raise HostPathsError(f"la CLI non può girare con l'uid dei plugin ({PLUGIN_UID})")
        if mountinfo is None:
            try:
                mountinfo = Path("/proc/self/mountinfo").read_text(errors="replace")
            except OSError as exc:
                raise HostPathsError("montaggi non leggibili") from exc
        mounted = {fields[4] for line in mountinfo.splitlines() if len(fields := line.split()) > 4}
        for root in (*self.roots.values(), self.output):
            if os.path.realpath(root) != str(root):
                raise HostPathsError(f"{root} non è un percorso reale")
            if str(root) not in mounted:
                raise HostPathsError(f"{root} non è un montaggio")

    def check_daemon(self, docker_root: str, socket: str | None) -> None:
        """Rifiuta un percorso host che espone i dati del daemon o il suo socket (N-32)."""
        targets = [docker_root, socket, os.path.realpath(socket) if socket else None]
        for target in targets:
            if not target or not target.startswith("/"):
                continue
            for kind, host in self.hosts.items():
                if _covers(host, Path(os.path.normpath(target))):
                    raise HostPathsError(f"{ENV[kind]} espone {target}")

    def sockets(self) -> Iterator[Path]:
        """Socket sotto le radici, senza seguire link: un plugin che lo monta parla con chi
        ascolta, anche senza rete (N-34)."""
        for root in self.roots.values():
            pending = [str(root)]
            while pending:
                try:
                    with os.scandir(pending.pop()) as entries:
                        for entry in entries:
                            try:
                                mode = entry.stat(follow_symlinks=False).st_mode
                            except OSError:
                                continue
                            if stat.S_ISSOCK(mode):
                                yield Path(entry.path)
                            elif stat.S_ISDIR(mode):
                                pending.append(entry.path)
                except OSError:
                    continue

    def sweep_work(self, now: float | None = None) -> None:
        """Rimuove le sole radici di lavoro `ca-oci-*` scadute, lasciate da un processo ucciso.

        `/ca/work` sopravvive al container della CLI. Migliore sforzo, mai un link seguito.
        """
        limit = (time.time() if now is None else now) - WORK_MAX_AGE_SECONDS
        try:
            with os.scandir(self.roots["inputs"]) as entries:
                stale = [
                    entry.path
                    for entry in entries
                    if entry.name.startswith(WORK_PREFIX)
                    and entry.is_dir(follow_symlinks=False)
                    and entry.stat(follow_symlinks=False).st_mtime < limit
                ]
        except OSError:
            return
        for path in stale:
            shutil.rmtree(path, ignore_errors=True)


def from_env(environ: Mapping[str, str]) -> HostPaths | None:
    """`None` fuori dall'immagine. Tre variabili, tutte o nessuna; nell'immagine sono dovute."""
    values = {kind: environ.get(name, "") for kind, name in ENV.items()}
    if not any(values.values()):
        if environ.get(IMAGE_MARKER) == "1":
            raise HostPathsError("nell'immagine CLI servono " + ", ".join(ENV.values()))
        return None
    missing = [ENV[kind] for kind, value in values.items() if not value]
    if missing:
        raise HostPathsError("variabili mancanti: " + ", ".join(missing))
    hosts = {kind: _host_path(ENV[kind], value) for kind, value in values.items()}
    kinds = list(hosts)
    for index, first in enumerate(kinds):
        for second in kinds[index + 1 :]:
            if _covers(hosts[first], hosts[second]) or _covers(hosts[second], hosts[first]):
                raise HostPathsError(f"{ENV[first]} e {ENV[second]} coincidono o sono annidati")
    return HostPaths(hosts=hosts)
