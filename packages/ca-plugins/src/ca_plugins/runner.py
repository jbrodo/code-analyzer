"""Adattatore `OciExecutor` della porta `PluginExecutor` (R-02) e lettura sicura di `/out` (R-03).

ADR-0002: la pipeline non vive qui, questo è solo l'adattatore. ADR-0004: un container per plugin,
profilo `hardened-container`, nessun ripiego su sottoprocesso. Il codice analizzato e l'output degli
scanner sono dati ostili: ogni cosa che attraversa il confine host/plugin è validata qui.

Ciclo di un'esecuzione: volume tmpfs per `/out` e custodia (ADR-0004, R-09) -> `create` (con
`--name` univoco) -> `start` -> `wait` con timeout -> `inspect` -> copia del solo file dichiarato
dalla custodia -> `kill` e `rm -f` di plugin e custodia, `volume rm`, in ogni caso.
Non si usa `docker run`: uccidere il client non ferma il container (T-02). Il log del
container è disattivato (`--log-driver none`): l'output dello scanner non finisce né sul
disco del daemon né nel report.

Non provati qui (runtime assenti): gVisor (`runsc`) e Podman; vedi i commenti `UNPROVEN`.
"""

import contextlib
import json
import os
import re
import shutil
import stat
import subprocess
import tarfile
import tempfile
import threading
import time
import uuid
import weakref
from collections.abc import Callable, Sequence
from concurrent.futures import FIRST_EXCEPTION, Future, ThreadPoolExecutor, wait
from pathlib import Path
from typing import IO, Final

from ca_core.models.plugin_manifest import (
    CONFIG_MOUNT,
    FEEDS_MOUNT,
    OUT_DIR,
    SBOM_MOUNT,
    WORKSPACE_MOUNT,
    Outputs,
    PackagedPluginManifest,
)
from ca_core.ports import (
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

PLUGIN_UID: Final = 65534
PLUGIN_GID: Final = 65534
PLUGIN_USER: Final = f"{PLUGIN_UID}:{PLUGIN_GID}"
_CLIENT_ENV_ALLOWLIST: Final = (
    "PATH",
    "HOME",
    "USER",
    "DOCKER_HOST",
    "DOCKER_CONTEXT",
    "DOCKER_CONFIG",
    "CONTAINER_HOST",
    "XDG_RUNTIME_DIR",
)
_CREATE_TIMEOUT: Final = 120
_CP_TIMEOUT: Final = 120
_ABORT_TIMEOUT: Final = 10
_PURGE_TIMEOUT: Final = 300
_EXPIRES_GRACE: Final = 900  # secondi oltre il timeout dell'esecuzione (ADR-0004, M-03)
_HOLD_EXTRA: Final = 300
EXPIRES_LABEL: Final = "code-analyzer.expires"
OUT_MARGIN_MIN: Final = 16 * 1024**2  # provvisorio, da confermare in X-04
FEEDS_MIN_FREE_BYTES: Final = 2 * 1024**3  # provvisorio, da confermare in X-04 (ADR-0006)
FEEDS_MIN_FREE_INODES: Final = 100_000  # provvisorio, da confermare in X-04 (N-03 di S-01)
FEEDS_MAX_ENTRIES: Final = 200_000
FEEDS_POLL_SECONDS: Final = 1
_SAFE_NAME: Final = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,200}")
# Comando fisso di `purge_feeds`: nessun dato dal manifest né dal repository. Dà `u+rwx` alle
# directory scendendo, poi rimuove tutto il contenuto di /feeds senza seguire symlink.
_PURGE_CODE: Final = (
    "import os\n"
    "from os.path import islink, join\n"
    "for cur, dirs, _ in os.walk('/feeds'):\n"
    "    for d in dirs:\n"
    "        if not islink(join(cur, d)):\n"
    "            os.chmod(join(cur, d), 0o700)\n"
    "for cur, dirs, files in os.walk('/feeds', topdown=False):\n"
    "    for f in files:\n"
    "        os.unlink(join(cur, f))\n"
    "    for d in dirs:\n"
    "        p = join(cur, d)\n"
    "        os.unlink(p) if islink(p) else os.rmdir(p)\n"
)
_QUICK_TIMEOUT: Final = 60
_PULL_TIMEOUT: Final = 600
_READ_CHUNK: Final = 1 << 16
DEFAULT_MAX_PARALLEL: Final = 4


class RuntimeUnavailable(RuntimeError):
    """Nessun runtime OCI utilizzabile: la CLI esce con 2, nessun ripiego (ADR-0004)."""

    exit_code = 2


class IsolationUnsatisfied(RuntimeError):
    """`--min-isolation` non soddisfatto: exit 2 prima di avviare qualunque container (ADR-0004)."""

    exit_code = 2


_ISOLATION_RANK: Final = {Isolation.HARDENED_CONTAINER: 0, Isolation.GVISOR: 1}


def require_isolation(available: Isolation, minimum: Isolation | None) -> None:
    """Chiamata dalla radice di composizione con `executor.isolation()` e il flag CLI.

    Il minimo viene solo dal flag `--min-isolation` o dal server, mai da `.code-analyzer.yml`.
    """
    if minimum is not None and _ISOLATION_RANK[available] < _ISOLATION_RANK[minimum]:
        raise IsolationUnsatisfied(
            f"isolamento richiesto {minimum.value}, disponibile {available.value}"
        )


class _RunError(Exception):
    """Fallimento del singolo plugin, con messaggio breve per il finding `health`."""


class _InvalidOutput(_RunError):
    """Exit 0 ma un output dichiarato è assente, non regolare, un symlink o troppo grande."""


# --- Costruzione dei comandi (funzioni pure) ----------------------------------------------------


def digest_ref(image: str) -> str:
    """`registro/percorso:tag@sha256:...` -> `registro/percorso@sha256:...` (mai per tag)."""
    name_and_tag, sep, digest = image.rpartition("@")
    if not sep:
        raise ValueError("l'immagine impacchettata richiede il digest")
    return f"{name_and_tag.rpartition(':')[0]}@{digest}"


def parse_duration(value: str) -> int:
    return int(value.removesuffix("s"))


def memory_bytes(value: str) -> int:
    """`512Mi`/`2Gi` del manifest (binari) in byte."""
    return int(value[:-2]) * (1024**2 if value.endswith("Mi") else 1024**3)


def out_tmpfs_bytes(outputs: Outputs) -> int:
    """Dimensione del volume tmpfs di `/out` (ADR-0004, R-09): dati dichiarati più un margine.

    Il margine copre i temporanei dell'adattatore e fa riconoscere un output appena oltre
    `max_bytes` come `invalid_output` e non come scrittura troncata. Provvisorio fino a X-04.
    """
    declared = sum(p is not None for p in (outputs.sarif, outputs.cyclonedx))
    data = declared * outputs.max_bytes
    return data + max(OUT_MARGIN_MIN, data // 4)


def out_volume_args(volume: str, size: int, expires: int) -> list[str]:
    """Argomenti di `<runtime> volume create` per `/out`: tmpfs con tetto, proprietario 65534."""
    options = (
        f"size={size},nr_inodes=1024,uid={PLUGIN_UID},gid={PLUGIN_GID},mode=0700,"
        "noexec,nosuid,nodev"
    )
    return [
        "volume", "create", "--driver", "local",
        "--label", "code-analyzer.executor=1",
        "--label", f"{EXPIRES_LABEL}={expires}",
        "--opt", "type=tmpfs", "--opt", "device=tmpfs",
        "--opt", f"o={options}",
        volume,
    ]  # fmt: skip


def volume_mount(volume: str, dst: str, *, readonly: bool = False) -> list[str]:
    return ["--mount", f"type=volume,src={volume},dst={dst}" + (",readonly" if readonly else "")]


def bind_mount(src: Path, dst: str, *, readonly: bool) -> list[str]:
    """`--mount` e non `-v`: un sorgente mancante è un errore e non crea directory come root."""
    text = str(src)
    if any(c in text for c in ',"') or any(ord(c) < 32 for c in text):
        raise _RunError("percorso non ammesso per il montaggio (virgola, virgolette o controllo)")
    spec = f"type=bind,src={text},dst={dst}" + (",readonly" if readonly else "")
    return ["--mount", spec]


def container_args(
    *,
    name: str,
    image: str,
    manifest: PackagedPluginManifest,
    mounts: Sequence[list[str]],
    isolation: Isolation,
    network: bool = False,
    entrypoint: str | None = None,
    command: Sequence[str] = (),
    extra_memory: int = 0,
    file_size_limit: int | None = None,
    expires: int | None = None,
) -> list[str]:
    """Argomenti di `<runtime> create` per il profilo `hardened-container` (lista, mai shell).

    `--memory` e `--memory-swap` sono in byte: `resources.memory` più `extra_memory`, le pagine
    del tmpfs di `/out` addebitate al cgroup (ADR-0004). `file_size_limit`: `--ulimit fsize`.

    Nessuna variabile dell'host: solo `HOME=/tmp`, scritta per esteso (mai `-e NOME`).
    `network=True` solo per la sincronizzazione dei feed, che non monta mai il workspace.
    """
    if network and any(re.search(rf",dst={WORKSPACE_MOUNT}(,|$)", m[1]) for m in mounts):
        raise ValueError("codice o rete, mai entrambi (ADR-0006)")
    res = manifest.resources
    memory = str(memory_bytes(res.memory) + extra_memory)
    args = [
        "create",
        "--name", name,
        "--label", "code-analyzer.executor=1",
        *(["--label", f"{EXPIRES_LABEL}={expires}"] if expires is not None else []),
        "--pull", "never",
        "--log-driver", "none",
        "--read-only",
        "--cap-drop", "ALL",
        "--security-opt", "no-new-privileges",
        "--user", PLUGIN_USER,
        "--tmpfs", "/tmp:rw,noexec,nosuid",
        "--env", "HOME=/tmp",
        "--cpus", res.cpu,
        "--memory", memory,
        "--memory-swap", memory,
        "--pids-limit", str(res.pids),
    ]  # fmt: skip
    if not network:
        args += ["--network", "none"]
    if file_size_limit is not None:
        args += ["--ulimit", f"fsize={file_size_limit}"]
    if isolation is Isolation.GVISOR:
        args += ["--runtime", "runsc"]  # UNPROVEN: runsc non installato sulla macchina di sviluppo
    for mount in mounts:
        args += mount
    if entrypoint is not None:
        args += ["--entrypoint", entrypoint]
    return [*args, image, *command]


def holder_args(
    *, name: str, image: str, volume: str, isolation: Isolation, sleep_seconds: int, expires: int
) -> list[str]:
    """Custodia di `/out` (ADR-0004): tiene montato il volume, in sola lettura, mentre l'host copia.

    Stesso digest verificato e stesso profilo; `sleep` finito perché un client ucciso non la lasci.
    """
    args = [
        "create",
        "--name", name,
        "--label", "code-analyzer.executor=1",
        "--label", f"{EXPIRES_LABEL}={expires}",
        "--pull", "never",
        "--log-driver", "none",
        "--read-only",
        "--cap-drop", "ALL",
        "--security-opt", "no-new-privileges",
        "--user", PLUGIN_USER,
        "--network", "none",
        "--cpus", "0.1",
        "--memory", "32m",
        "--memory-swap", "32m",
        "--pids-limit", "8",
        *volume_mount(volume, OUT_DIR, readonly=True),
    ]  # fmt: skip
    if isolation is Isolation.GVISOR:
        args += ["--runtime", "runsc"]  # UNPROVEN: runsc non installato
    return [*args, "--entrypoint", "sleep", image, str(sleep_seconds)]


def feeds_usage(root: Path, max_bytes: int, max_entries: int) -> tuple[int, int, bool]:
    """(byte allocati, voci, oltre un limite) sotto `root`, senza seguire link.

    Byte da `st_blocks * 512`: contano i blocchi davvero allocati. Si ferma al primo limite
    superato. Ciò che l'host non legge non si somma (M-02 di S-01, non bloccante).
    """
    total = entries = 0
    pending = [str(root)]
    while pending:
        try:
            with os.scandir(pending.pop()) as it:
                for entry in it:
                    entries += 1
                    try:
                        info = entry.stat(follow_symlinks=False)
                        if entry.is_dir(follow_symlinks=False):
                            pending.append(entry.path)
                    except OSError:
                        continue
                    total += info.st_blocks * 512
                    if total > max_bytes or entries > max_entries:
                        return total, entries, True
        except OSError:
            continue
    return total, entries, False


def feeds_guard(path: Path, max_bytes: int) -> Callable[[], str | None]:
    """Guardia della sincronizzazione (ADR-0006): motivo fisso se si deve fermare, altrimenti None.

    Spazio libero sotto `FEEDS_MIN_FREE_BYTES` o inode sotto `FEEDS_MIN_FREE_INODES` (anche prima
    dello start: file vuoti sotto una directory 000 non si vedono, ma consumano inode), byte
    oltre `max_bytes`, voci oltre `FEEDS_MAX_ENTRIES`.
    """

    def guard() -> str | None:
        try:
            fs = os.statvfs(path)
        except OSError:
            return "spazio libero dei feed non verificabile"
        if fs.f_bavail * fs.f_frsize < FEEDS_MIN_FREE_BYTES:
            return "spazio libero insufficiente per i feed"
        if fs.f_files and fs.f_favail < FEEDS_MIN_FREE_INODES:  # f_files 0: fs senza inode fissi
            return "inode liberi insufficienti per i feed"
        _, _, over = feeds_usage(path, max_bytes, FEEDS_MAX_ENTRIES)
        if over:
            return "sincronizzazione dei feed oltre i limiti di byte o di voci"
        return None

    return guard


def _client_env() -> dict[str, str]:
    return {k: v for k in _CLIENT_ENV_ALLOWLIST if (v := os.environ.get(k)) is not None}


def _brief(data: bytes) -> str:
    line = data.decode("utf-8", "replace").strip().splitlines()[:1]
    return re.sub(r"[^\x20-\x7e]", "?", line[0])[:200] if line else ""


# --- Lettura sicura di /out (R-03) --------------------------------------------------------------


def _first_level_name(path: str) -> str:
    if not path or path in {".", ".."} or "/" in path or "\x00" in path:
        raise SourceError("percorso non ammesso: solo file al primo livello")
    return path


def _open_dir(root: str) -> int:
    try:
        return os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except OSError as exc:
        raise SourceError("radice non apribile come directory") from exc


def _open_regular(dir_fd: int, name: str, max_bytes: int) -> tuple[int, int]:
    """Apre `name` senza seguire symlink e senza bloccarsi su una FIFO; rifiuta il non regolare.

    `O_NONBLOCK`: l'apertura di una FIFO senza scrittore bloccherebbe l'host per sempre.
    Ritorna (fd, dimensione); l'fd va chiuso dal chiamante.
    """
    try:
        fd = os.open(
            name,
            os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
            dir_fd=dir_fd,
        )
    except FileNotFoundError as exc:
        raise SourceError("file assente") from exc
    except OSError as exc:  # ELOOP per i symlink, ENXIO, EACCES...
        raise SourceError("file non apribile (symlink o non regolare)") from exc
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise SourceError("non è un file regolare")
        if info.st_size > max_bytes:
            raise SourceTooLarge("file oltre il limite")
    except BaseException:
        os.close(fd)
        raise
    return fd, info.st_size


class OutputReader:
    """`SourceReader` per `/out`: file regolari al primo livello, senza symlink, con limite.

    Più stretto del workspace (R-08): niente sottodirectory, perché una creata da `65534` non
    sarebbe eliminabile dall'host (ADR-0004). Nessuna lettura oltre `max_bytes`.
    """

    def list_files(self, root: str) -> list[str]:
        dir_fd = _open_dir(root)
        try:
            with os.scandir(dir_fd) as it:
                return sorted(e.name for e in it if e.is_file(follow_symlinks=False))
        finally:
            os.close(dir_fd)

    def read_file(self, root: str, path: str, max_bytes: int) -> bytes:
        name = _first_level_name(path)
        dir_fd = _open_dir(root)
        try:
            fd, _ = _open_regular(dir_fd, name, max_bytes)
        finally:
            os.close(dir_fd)
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

    def check(self, root: str, path: str, max_bytes: int) -> None:
        """Come `read_file` senza leggere: regolare, presente, entro il limite."""
        dir_fd = _open_dir(root)
        try:
            os.close(_open_regular(dir_fd, _first_level_name(path), max_bytes)[0])
        finally:
            os.close(dir_fd)


# --- Esecutore ----------------------------------------------------------------------------------


def _stage_file(src: str, dst: Path) -> None:
    """Copia un file di input nella directory dell'esecuzione, leggibile da `65534` (0644)."""
    try:
        fd = os.open(src, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    except OSError as exc:
        raise _RunError("file di input non apribile") from exc
    with os.fdopen(fd, "rb") as source:
        if not stat.S_ISREG(os.fstat(source.fileno()).st_mode):
            raise _RunError("il file di input non è regolare")
        out_fd = os.open(dst, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC, 0o644)
        with os.fdopen(out_fd, "wb") as target:
            shutil.copyfileobj(source, target)
            os.fchmod(target.fileno(), 0o644)  # indipendente da umask


def _existing_dir(path: str) -> Path:
    try:
        resolved = Path(path).resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise _RunError("directory assente") from exc
    if not resolved.is_dir():
        raise _RunError("non è una directory")
    return resolved


class OciExecutor:
    """Esegue le immagini dei plugin con Docker o Podman.

    Le directory di output (`PluginRunResult.output_dir`) vivono sotto una radice privata 0700 e
    restano leggibili fino a `release()` o `close()` (la porta non ha altro punto di pulizia);
    alla fine del processo le rimuove un `weakref.finalize`.

    `verifier`: verifica della firma (R-04), chiamato con il manifest e il riferimento per digest
    prima di ogni `create`; restituisce l'esito (`Signature`) che finisce nel risultato.
    Un'eccezione (`ScanAborted`) si propaga: nessun pull e nessun container. Con un verificatore,
    dopo la verifica si fa il pull dello stesso digest (poi `create` con `--pull never`); senza,
    l'immagine deve essere già locale.
    `image_ref`: costruisce il riferimento da eseguire; il predefinito è per digest. Serve ai
    test, dove un'immagine locale non ha digest di registry.
    """

    def __init__(
        self,
        *,
        runtime: str | None = None,
        work_dir: str | None = None,
        verifier: Callable[[PackagedPluginManifest, str], Signature] | None = None,
        image_ref: Callable[[str], str] = digest_ref,
        max_parallel: int = DEFAULT_MAX_PARALLEL,
    ) -> None:
        if max_parallel < 1:
            raise ValueError("max_parallel deve essere almeno 1")
        self._max_parallel = max_parallel
        self._lock = threading.Lock()
        self._requested = runtime
        self._work_dir = work_dir
        self._verifier = verifier
        self._image_ref = image_ref
        self._cli_path: str | None = None
        self._isolation: Isolation | None = None
        self._base: Path | None = None
        self._reader = OutputReader()
        self._active: set[str] = set()
        self._active_lock = threading.Lock()
        self._stopping = threading.Event()
        self._sweep_lock = threading.Lock()
        self._swept = False

    def __enter__(self) -> "OciExecutor":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    # -- runtime e isolamento --

    def _cli(
        self, *args: str, timeout: float = _QUICK_TIMEOUT
    ) -> subprocess.CompletedProcess[bytes]:
        assert self._cli_path is not None
        return subprocess.run(  # noqa: S603 - lista di argomenti, nessuna shell
            [self._cli_path, *args],
            capture_output=True,
            stdin=subprocess.DEVNULL,
            env=_client_env(),
            timeout=timeout,
            check=False,
        )

    def _detect(self) -> None:
        with self._lock:
            self._detect_locked()

    def _detect_locked(self) -> None:
        if self._isolation is not None:
            return
        for exe in [self._requested] if self._requested else ["docker", "podman"]:
            path = shutil.which(exe)
            if path is None:
                continue
            podman = Path(path).name == "podman"
            fmt = "{{.Host.OCIRuntime.Name}}" if podman else "{{json .Runtimes}}"
            try:
                done = subprocess.run(  # noqa: S603
                    [path, "info", "--format", fmt],
                    capture_output=True,
                    stdin=subprocess.DEVNULL,
                    env=_client_env(),
                    timeout=30,
                    check=False,
                )
            except (OSError, subprocess.TimeoutExpired):
                continue
            if done.returncode != 0:
                continue
            self._cli_path = path
            text = done.stdout.decode("utf-8", "replace").strip()
            if podman:  # UNPROVEN: Podman assente; vede solo il runtime predefinito
                gvisor = text == "runsc"
            else:
                try:
                    runtimes = json.loads(text)
                except ValueError:
                    runtimes = {}
                gvisor = isinstance(runtimes, dict) and "runsc" in runtimes
            self._isolation = Isolation.GVISOR if gvisor else Isolation.HARDENED_CONTAINER
            return
        raise RuntimeUnavailable("nessun runtime OCI (docker, podman) utilizzabile")

    def isolation(self) -> Isolation:
        self._detect()
        assert self._isolation is not None
        return self._isolation

    # -- directory di lavoro --

    def _base_dir(self) -> Path:
        with self._lock:
            if self._base is None:
                self._base = Path(tempfile.mkdtemp(prefix="ca-oci-", dir=self._work_dir))  # 0700
                weakref.finalize(self, shutil.rmtree, self._base, True)
            return self._base

    def release(self, output_dir: str) -> None:
        """Rimuove la directory di un'esecuzione (`output_dir` è `<run>/out`)."""
        run_dir = Path(output_dir).resolve().parent
        if self._base is not None and run_dir.parent == self._base.resolve():
            shutil.rmtree(run_dir, ignore_errors=True)

    def close(self) -> None:
        """Ferma i container attivi, poi rimuove la radice di lavoro. Idempotente."""
        with self._active_lock:
            busy = bool(self._active)
        if busy and not self._stopping.is_set():
            self.abort()
        if self._base is not None:
            shutil.rmtree(self._base, ignore_errors=True)
            self._base = None

    # -- interruzione e orfani (M-03) --

    def abort(self) -> None:
        """Ferma i container attivi con un solo `kill`; i `finally` di `_execute` li rimuovono.

        Chi registra un nome dopo questa scansione vede `_stopping` e non avvia nulla.
        """
        self._stopping.set()
        with self._active_lock:
            names = sorted(self._active)
        if names and self._cli_path is not None:
            with contextlib.suppress(Exception):
                self._cli("kill", *names, timeout=_ABORT_TIMEOUT)

    def _register(self, *names: str) -> None:
        with self._active_lock:
            self._active.update(names)

    def _unregister(self, *names: str) -> None:
        with self._active_lock:
            self._active.difference_update(names)

    def _expired(self, listing: bytes) -> list[str]:
        """Nomi con etichetta scaduta, assente o non numerica; mai quelli con nome inatteso."""
        now = time.time()
        found: list[str] = []
        for line in listing.decode("utf-8", "replace").splitlines():
            name, _, label = line.partition("\t")
            if not _SAFE_NAME.fullmatch(name):
                continue
            try:
                if float(label.strip()) > now:
                    continue
            except ValueError:
                pass
            found.append(name)
        return found

    def _sweep_orphans(self) -> None:
        """Una volta per istanza, prima del primo `create`: rimuove container e volumi scaduti.

        Migliore sforzo: un errore non ferma la scansione. Le scansioni in corso di altri
        processi sullo stesso daemon hanno l'etichetta nel futuro e non si toccano.
        """
        with self._sweep_lock:
            if self._swept:
                return
            self._swept = True
            fmt = f'{{{{.Names}}}}\t{{{{.Label "{EXPIRES_LABEL}"}}}}'
            vfmt = f'{{{{.Name}}}}\t{{{{.Label "{EXPIRES_LABEL}"}}}}'
            flt = ["--filter", "label=code-analyzer.executor=1"]
            with contextlib.suppress(Exception):
                if names := self._expired(self._cli("ps", "-a", *flt, "--format", fmt).stdout):
                    self._cli("rm", "--force", "--volumes", *names)
            with contextlib.suppress(Exception):
                listing = self._cli("volume", "ls", *flt, "--format", vfmt).stdout
                if names := self._expired(listing):
                    self._cli("volume", "rm", *names)  # rifiuta un volume in uso

    # -- esecuzione --

    @staticmethod
    def _prepare(request: PluginRunRequest, run_dir: Path, out: Path) -> list[list[str]]:
        # Copie dell'host (ADR-0004): non montata nel container, quindi sempre eliminabile.
        out.mkdir(mode=0o700)
        out.chmod(0o700)
        mounts = [bind_mount(_existing_dir(request.workspace), WORKSPACE_MOUNT, readonly=True)]
        inputs = run_dir / "inputs"
        inputs.mkdir()
        for source, name, target in (
            (request.config, "config.json", CONFIG_MOUNT),
            (request.sbom, "sbom.cdx.json", SBOM_MOUNT),
        ):
            if source is not None:
                _stage_file(source, inputs / name)
                mounts.append(bind_mount(inputs / name, target, readonly=True))
        if request.feeds_snapshot is not None:
            mounts.append(
                bind_mount(_existing_dir(request.feeds_snapshot), FEEDS_MOUNT, readonly=True)
            )
        return mounts

    def _verify(self, manifest: PackagedPluginManifest) -> Signature:
        """R-04: esito della verifica, o `ScanAborted`. Senza verificatore (solo test) `skipped`."""
        if self._verifier is None:
            return Signature.SKIPPED
        return self._verifier(manifest, self._image_ref(manifest.image))

    def run(self, request: PluginRunRequest) -> PluginRunResult:
        isolation = self.isolation()
        signature = self._verify(request.manifest)  # prima di directory e montaggi (ADR-0005)
        return self._run_verified(request, isolation, signature)

    def _run_verified(
        self, request: PluginRunRequest, isolation: Isolation, signature: Signature
    ) -> PluginRunResult:
        manifest = request.manifest
        run_dir = Path(tempfile.mkdtemp(prefix="run-", dir=self._base_dir()))  # 0700
        keep = False
        try:
            out = run_dir / "out"
            try:
                mounts = self._prepare(request, run_dir, out)
            except OSError as exc:  # disco pieno, permessi: questo plugin fallisce, gli altri no
                raise _RunError(f"errore di preparazione: {exc.__class__.__name__}") from exc
            result = self._execute(
                manifest,
                mounts,
                isolation,
                signature=signature,
                timeout=parse_duration(manifest.resources.timeout),
                out=out,
            )
            keep = result.outcome is RunOutcome.OK
            return result
        except _RunError as exc:
            return self._result(RunOutcome.FAILED, None, isolation, 0.0, None, str(exc), signature)
        finally:
            if not keep:
                shutil.rmtree(run_dir, ignore_errors=True)

    @staticmethod
    def _gather[T](pool: ThreadPoolExecutor, futures: list[Future[T]]) -> list[T]:
        """Risultati nell'ordine; alla prima eccezione, in qualunque posizione, annulla i futuri
        non avviati senza attendere quelli che precedono, e la rilancia (il `with` del pool
        attende solo le esecuzioni in corso, che rimuovono i propri container)."""
        wait(futures, return_when=FIRST_EXCEPTION)
        failed = next(
            (f for f in futures if f.done() and not f.cancelled() and f.exception()), None
        )
        if failed is not None:
            for f in futures:
                f.cancel()
            raise failed.exception()  # type: ignore[misc]
        return [f.result() for f in futures]

    def run_many(self, requests: Sequence[PluginRunRequest]) -> list[PluginRunResult]:
        """Esegue le richieste in parallelo (al più `max_parallel`), risultati nell'ordine dato.

        Prima si verificano le firme di tutto il lotto (una per richiesta), poi si avvia il primo
        container: una verifica fallita non ne avvia nessuno (ADR-0005). Un esito non OK non ferma
        gli altri; un'eccezione annulla subito le esecuzioni non avviate e si propaga.
        """
        if not requests:
            return []
        isolation = self.isolation()  # rileva e fallisce prima di creare thread
        with ThreadPoolExecutor(max_workers=self._max_parallel) as pool:
            try:
                signatures = self._gather(
                    pool, [pool.submit(self._verify, r.manifest) for r in requests]
                )
                return self._gather(
                    pool,
                    [
                        pool.submit(self._run_verified, r, isolation, sig)
                        for r, sig in zip(requests, signatures, strict=True)
                    ],
                )
            except BaseException:  # anche KeyboardInterrupt: la coda non deve partire (M-03)
                pool.shutdown(wait=False, cancel_futures=True)
                self.abort()
                raise

    def sync_feeds(self, request: FeedsSyncRequest) -> PluginRunResult:
        """Stessa immagine, con rete e senza workspace; `snapshot_dir` scrivibile da `65534`
        (lo prepara il chiamante, R-06)."""
        manifest = request.manifest
        feeds = manifest.feeds
        assert feeds is not None
        isolation = self.isolation()
        signature = self._verify(manifest)
        try:
            snapshot = _existing_dir(request.snapshot_dir)
            mounts = [bind_mount(snapshot, FEEDS_MOUNT, readonly=False)]
            return self._execute(
                manifest,
                mounts,
                isolation,
                signature=signature,
                timeout=parse_duration(feeds.sync_timeout),
                network=True,
                entrypoint=feeds.sync_command[0],
                command=feeds.sync_command[1:],
                guard=feeds_guard(snapshot, request.max_bytes),
                file_size_limit=request.max_bytes,
            )
        except _RunError as exc:
            return self._result(RunOutcome.FAILED, None, isolation, 0.0, None, str(exc), signature)

    def purge_feeds(self, request: FeedsPurgeRequest) -> None:
        """Rimuove il contenuto di `snapshot_dir` da un container, con l'immagine appena usata per
        la sincronizzazione (già verificata). Migliore sforzo: nessuna eccezione (ADR-0006)."""
        name = f"ca-purge-{uuid.uuid4().hex[:16]}"
        try:
            isolation = self.isolation()
            self._sweep_orphans()
            mounts = [bind_mount(_existing_dir(request.snapshot_dir), FEEDS_MOUNT, readonly=False)]
            args = container_args(
                name=name,
                image=self._image_ref(request.manifest.image),
                manifest=request.manifest,
                mounts=mounts,
                isolation=isolation,
                entrypoint="python3",
                command=["-I", "-S", "-c", _PURGE_CODE],
                expires=int(time.time()) + _PURGE_TIMEOUT + _EXPIRES_GRACE,
            )
            self._register(name)
            try:
                if self._stopping.is_set() or self._cli(*args, timeout=_CREATE_TIMEOUT).returncode:
                    return
                if self._stopping.is_set():
                    return
                if self._cli("start", name).returncode == 0 and not self._stopping.is_set():
                    self._cli("wait", name, timeout=_PURGE_TIMEOUT)
            finally:
                with contextlib.suppress(Exception):
                    self._cli("kill", name)
                with contextlib.suppress(Exception):
                    self._cli("rm", "--force", "--volumes", name)
                self._unregister(name)
        except Exception:  # noqa: S110 - migliore sforzo, la cartella resta alla prossima pulizia
            return

    def _execute(
        self,
        manifest: PackagedPluginManifest,
        mounts: Sequence[list[str]],
        isolation: Isolation,
        *,
        signature: Signature,
        timeout: int,
        out: Path | None = None,
        network: bool = False,
        entrypoint: str | None = None,
        command: Sequence[str] = (),
        guard: Callable[[], str | None] | None = None,
        file_size_limit: int | None = None,
    ) -> PluginRunResult:
        """`out`: cartella dell'host (0700) che riceve le copie dei soli file dichiarati. `/out` nel
        container è un volume tmpfs per esecuzione, tenuto da una custodia (ADR-0004, R-09).
        `guard`: chiamata ogni `FEEDS_POLL_SECONDS` durante l'attesa e prima dello start; un motivo
        ferma il container e fallisce l'esecuzione (ADR-0006)."""
        image = self._image_ref(manifest.image)
        token = uuid.uuid4().hex[:16]
        name, volume, holder = f"ca-{manifest.name}-{token}", f"ca-out-{token}", f"ca-hold-{token}"
        plugin_mounts = list(mounts)
        tmpfs = 0
        if out is not None:
            tmpfs = out_tmpfs_bytes(manifest.outputs)
            plugin_mounts.append(volume_mount(volume, OUT_DIR))
        started = time.monotonic()

        def finish(
            outcome: RunOutcome, code: int | None, detail: str | None, keep: bool = False
        ) -> PluginRunResult:
            return self._result(
                outcome,
                code,
                isolation,
                time.monotonic() - started,
                str(out) if keep and out is not None else None,
                detail,
                signature,
            )

        def stopped() -> PluginRunResult | None:
            """Segnale ricevuto (N-02): si ricontrolla prima di ogni create e start."""
            return (
                finish(RunOutcome.FAILED, None, "interrotto") if self._stopping.is_set() else None
            )

        try:
            self._sweep_orphans()
            self._register(name, holder)
            if (halt := stopped()) is not None:
                return halt
            if self._verifier is not None:  # stesso digest verificato, mai un tag
                try:
                    pulled = self._cli("pull", "--quiet", image, timeout=_PULL_TIMEOUT)
                except subprocess.TimeoutExpired:
                    return finish(RunOutcome.FAILED, None, "pull oltre il tempo massimo")
                if pulled.returncode != 0:
                    return finish(RunOutcome.FAILED, None, f"pull fallito: {_brief(pulled.stderr)}")
            if (halt := stopped()) is not None:
                return halt
            # B-08: la scadenza parte dopo il pull, che può durare quanto `_PULL_TIMEOUT`.
            expires = int(time.time()) + timeout + _EXPIRES_GRACE
            args = container_args(
                name=name,
                image=image,
                manifest=manifest,
                mounts=plugin_mounts,
                isolation=isolation,
                network=network,
                entrypoint=entrypoint,
                command=command,
                extra_memory=tmpfs,
                file_size_limit=file_size_limit,
                expires=expires,
            )
            if out is not None:  # fallimento chiuso: nessun ripiego su bind mount
                made = self._cli(*out_volume_args(volume, tmpfs, expires), timeout=_CREATE_TIMEOUT)
                if made.returncode != 0:
                    return finish(RunOutcome.FAILED, None, "volume di output non creato")
                hold = holder_args(
                    name=holder,
                    image=image,
                    volume=volume,
                    isolation=isolation,
                    sleep_seconds=timeout + _HOLD_EXTRA,
                    expires=expires,
                )
                if (halt := stopped()) is not None:
                    return halt
                if self._cli(*hold, timeout=_CREATE_TIMEOUT).returncode != 0:
                    return finish(RunOutcome.FAILED, None, "custodia di output non creata")
                if (halt := stopped()) is not None:
                    return halt
                if self._cli("start", holder).returncode != 0:
                    return finish(RunOutcome.FAILED, None, "custodia di output non avviata")
            if guard is not None and (reason := guard()) is not None:
                return finish(RunOutcome.FAILED, None, reason)
            if (halt := stopped()) is not None:
                return halt
            created = self._cli(*args, timeout=_CREATE_TIMEOUT)
            if created.returncode != 0:
                return finish(RunOutcome.FAILED, None, f"create fallito: {_brief(created.stderr)}")
            if (halt := stopped()) is not None:
                return halt
            started = time.monotonic()  # il timeout del manifest vale dall'avvio
            if (s := self._cli("start", name)).returncode != 0:
                return finish(RunOutcome.FAILED, None, f"start fallito: {_brief(s.stderr)}")
            if (halt := stopped()) is not None:  # `abort` può aver ucciso prima dello start
                self._cli("kill", name)
                return halt
            try:
                waited = self._wait(name, timeout, guard)
            except subprocess.TimeoutExpired:
                return finish(RunOutcome.TIMEOUT, None, f"timeout oltre {timeout}s")
            if isinstance(waited, str):  # motivo della guardia
                self._cli("kill", name)
                return finish(RunOutcome.FAILED, None, waited)
            if waited != 0:
                return finish(RunOutcome.FAILED, None, "wait fallito")
            info = self._cli(
                "inspect", "--format", "{{.State.ExitCode}} {{.State.OOMKilled}}", name
            ).stdout.split()
            if len(info) != 2 or not info[0].lstrip(b"-").isdigit():
                return finish(RunOutcome.FAILED, None, "stato del container non leggibile")
            code = int(info[0])
            if info[1] == b"true":
                return finish(RunOutcome.FAILED, code, "memoria esaurita")
            if code != 0:
                return finish(RunOutcome.FAILED, code, f"exit {code}")
            if out is not None:
                self._fetch_outputs(manifest, holder, out)
            return finish(RunOutcome.OK, 0, None, keep=True)
        except _InvalidOutput as exc:
            return finish(RunOutcome.INVALID_OUTPUT, 0, str(exc))
        except _RunError as exc:
            return finish(RunOutcome.FAILED, 0, str(exc))
        except (subprocess.TimeoutExpired, OSError) as exc:  # client del runtime: create/start/...
            return finish(RunOutcome.FAILED, None, f"errore del client: {exc.__class__.__name__}")
        finally:
            # Anche con eccezioni e a timeout: kill del container, non del solo client (T-02).
            # Ogni passo è protetto a sé: uno che fallisce non salta i successivi, e il residuo
            # scaduto lo rimuove `_sweep_orphans` all'avvio successivo.
            steps = [("kill", name), ("rm", "--force", "--volumes", name)]
            if out is not None:
                steps += [("kill", holder), ("rm", "--force", holder), ("volume", "rm", volume)]
            for step in steps:
                with contextlib.suppress(Exception):
                    self._cli(*step)
            self._unregister(name, holder)

    def _wait(self, name: str, timeout: int, guard: Callable[[], str | None] | None) -> int | str:
        """Codice di `wait`, oppure il motivo della guardia. `TimeoutExpired` oltre `timeout`."""
        if guard is None:
            return self._cli("wait", name, timeout=timeout).returncode
        assert self._cli_path is not None
        proc = subprocess.Popen(  # noqa: S603 - lista di argomenti, nessuna shell
            [self._cli_path, "wait", name],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            stdin=subprocess.DEVNULL,
            env=_client_env(),
        )
        deadline = time.monotonic() + timeout
        try:
            while True:
                left = deadline - time.monotonic()
                if left <= 0:
                    raise subprocess.TimeoutExpired("wait", timeout)
                try:
                    return proc.wait(timeout=min(FEEDS_POLL_SECONDS, left))
                except subprocess.TimeoutExpired:
                    if (reason := guard()) is not None:
                        return reason
        finally:
            if proc.poll() is None:
                proc.kill()
            proc.wait()

    def _fetch_outputs(self, manifest: PackagedPluginManifest, holder: str, out: Path) -> None:
        """Copia dalla custodia il solo file dichiarato, per ogni output: un assente, non
        regolare, symlink o oltre il limite fa fallire. I non dichiarati non si toccano."""
        outputs = manifest.outputs
        for declared in (outputs.sarif, outputs.cyclonedx):
            if declared is None:
                continue
            name = Path(declared).name
            try:
                self._fetch_output(holder, _first_level_name(name), outputs.max_bytes, out)
            except SourceError as exc:
                raise _InvalidOutput(f"output non valido: {name}") from exc

    def _fetch_output(self, holder: str, name: str, max_bytes: int, dest_dir: Path) -> None:
        """`<cli> cp <holder>:/out/<name> -` letto come tar in streaming: mai `extract`, mai `-L`.

        Una sola voce, di nome uguale al dichiarato e di tipo file regolare (symlink, FIFO e
        directory sono rifiutati dall'intestazione, senza aprirli), `size <= max_bytes`; scritta in
        `dest_dir/<name>` con `O_EXCL|O_NOFOLLOW`, 0600. Ogni altro esito è `_InvalidOutput`.
        """
        assert self._cli_path is not None
        invalid = _InvalidOutput(f"output non valido: {name}")
        dest = dest_dir / name
        proc = subprocess.Popen(  # noqa: S603 - lista di argomenti, nessuna shell
            [self._cli_path, "cp", f"{holder}:{OUT_DIR}/{name}", "-"],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            stdin=subprocess.DEVNULL,
            env=_client_env(),
        )
        timer = threading.Timer(_CP_TIMEOUT, proc.kill)
        timer.start()
        ok = False
        try:
            assert proc.stdout is not None
            try:
                with tarfile.open(fileobj=proc.stdout, mode="r|") as tar:
                    member = tar.next()
                    if (
                        member is None
                        or member.name != name
                        or member.type not in (tarfile.REGTYPE, tarfile.AREGTYPE)
                    ):
                        raise invalid
                    if member.size > max_bytes:
                        raise _InvalidOutput(f"output oltre il limite: {name}")
                    source = tar.extractfile(member)
                    if source is None:
                        raise invalid
                    self._write_copy(source, member.size, dest_dir, name, invalid)
                    if tar.next() is not None:  # una seconda voce
                        raise invalid
                proc.stdout.read(1 << 20)  # eventuale riempimento finale del tar
            except (tarfile.TarError, OSError, EOFError) as exc:
                raise invalid from exc
            if proc.wait() != 0:
                raise invalid
            ok = True
        finally:
            timer.cancel()
            if proc.poll() is None:
                proc.kill()
            proc.wait()
            if proc.stdout is not None:
                proc.stdout.close()
            if not ok:
                with contextlib.suppress(OSError):
                    dest.unlink()

    @staticmethod
    def _write_copy(
        source: "tarfile.ExFileObject | IO[bytes]",
        size: int,
        dest_dir: Path,
        name: str,
        invalid: _InvalidOutput,
    ) -> None:
        dir_fd = _open_dir(str(dest_dir))
        try:
            fd = os.open(
                name,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                0o600,
                dir_fd=dir_fd,
            )
        finally:
            os.close(dir_fd)
        with os.fdopen(fd, "wb") as target:
            left = size
            while left > 0:
                chunk = source.read(min(_READ_CHUNK, left))
                if not chunk:
                    raise invalid  # meno byte del dichiarato
                target.write(chunk)
                left -= len(chunk)
            os.fchmod(target.fileno(), 0o600)  # indipendente da umask

    @staticmethod
    def _result(
        outcome: RunOutcome,
        code: int | None,
        isolation: Isolation,
        duration: float,
        output_dir: str | None,
        detail: str | None,
        signature: Signature,
    ) -> PluginRunResult:
        return PluginRunResult(
            signature=signature,
            outcome=outcome,
            exit_code=code,
            isolation=isolation,
            duration_seconds=duration,
            output_dir=output_dir,
            detail=detail,
        )


__all__ = [
    "OciExecutor",
    "IsolationUnsatisfied",
    "OutputReader",
    "RuntimeUnavailable",
    "bind_mount",
    "container_args",
    "feeds_guard",
    "holder_args",
    "out_tmpfs_bytes",
    "out_volume_args",
    "digest_ref",
    "parse_duration",
    "require_isolation",
]
