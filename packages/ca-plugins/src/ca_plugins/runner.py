"""Adattatore `OciExecutor` della porta `PluginExecutor` (R-02) e lettura sicura di `/out` (R-03).

ADR-0002: la pipeline non vive qui, questo è solo l'adattatore. ADR-0004: un container per plugin,
profilo `hardened-container`, nessun ripiego su sottoprocesso. Il codice analizzato e l'output degli
scanner sono dati ostili: ogni cosa che attraversa il confine host/plugin è validata qui.

Ciclo di un'esecuzione: `create` (con `--name` univoco) -> `start` -> `wait` con timeout ->
`inspect` -> `kill` e `rm -f` in ogni caso (anche con eccezioni). Non si usa `docker run`: uccidere
il client non ferma il container (T-02). Il log del container è disattivato (`--log-driver none`):
l'output dello scanner non finisce né sul disco del daemon né nel report.

Non provati qui (runtime assenti): gVisor (`runsc`) e Podman; vedi i commenti `UNPROVEN`.
"""

import contextlib
import json
import os
import re
import shutil
import stat
import subprocess
import tempfile
import threading
import time
import uuid
import weakref
from collections.abc import Callable, Sequence
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Final

from ca_core.models.plugin_manifest import (
    CONFIG_MOUNT,
    FEEDS_MOUNT,
    OUT_DIR,
    SBOM_MOUNT,
    WORKSPACE_MOUNT,
    PackagedPluginManifest,
)
from ca_core.ports import (
    FeedsSyncRequest,
    Isolation,
    PluginRunRequest,
    PluginRunResult,
    RunOutcome,
    Signature,
    SourceError,
    SourceTooLarge,
)

PLUGIN_USER: Final = "65534:65534"
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


# --- Costruzione dei comandi (funzioni pure) ----------------------------------------------------


def digest_ref(image: str) -> str:
    """`registro/percorso:tag@sha256:...` -> `registro/percorso@sha256:...` (mai per tag)."""
    name_and_tag, sep, digest = image.rpartition("@")
    if not sep:
        raise ValueError("l'immagine impacchettata richiede il digest")
    return f"{name_and_tag.rpartition(':')[0]}@{digest}"


def parse_duration(value: str) -> int:
    return int(value.removesuffix("s"))


def _memory(value: str) -> str:
    return value.replace("Mi", "m").replace("Gi", "g")  # binari, come nel manifest


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
) -> list[str]:
    """Argomenti di `<runtime> create` per il profilo `hardened-container` (lista, mai shell).

    Nessuna variabile dell'host: solo `HOME=/tmp`, scritta per esteso (mai `-e NOME`).
    `network=True` solo per la sincronizzazione dei feed, che non monta mai il workspace.
    """
    if network and any(re.search(rf",dst={WORKSPACE_MOUNT}(,|$)", m[1]) for m in mounts):
        raise ValueError("codice o rete, mai entrambi (ADR-0006)")
    res = manifest.resources
    memory = _memory(res.memory)
    args = [
        "create",
        "--name", name,
        "--label", "code-analyzer.executor=1",
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
    if isolation is Isolation.GVISOR:
        args += ["--runtime", "runsc"]  # UNPROVEN: runsc non installato sulla macchina di sviluppo
    for mount in mounts:
        args += mount
    if entrypoint is not None:
        args += ["--entrypoint", entrypoint]
    return [*args, image, *command]


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
        if self._base is not None:
            shutil.rmtree(self._base, ignore_errors=True)
            self._base = None

    # -- esecuzione --

    @staticmethod
    def _prepare(request: PluginRunRequest, run_dir: Path, out: Path) -> list[list[str]]:
        out.mkdir()
        out.chmod(0o777)  # il plugin è 65534; la 0700 esterna lo isola dagli altri utenti
        mounts = [
            bind_mount(_existing_dir(request.workspace), WORKSPACE_MOUNT, readonly=True),
            bind_mount(out, OUT_DIR, readonly=False),
        ]
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

    def run(self, request: PluginRunRequest) -> PluginRunResult:
        manifest = request.manifest
        isolation = self.isolation()
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
                timeout=parse_duration(manifest.resources.timeout),
                out=out,
            )
            keep = result.outcome is RunOutcome.OK
            return result
        except _RunError as exc:
            return self._result(RunOutcome.FAILED, None, isolation, 0.0, None, str(exc))
        finally:
            if not keep:
                shutil.rmtree(run_dir, ignore_errors=True)

    def run_many(self, requests: Sequence[PluginRunRequest]) -> list[PluginRunResult]:
        """Esegue le richieste in parallelo (al più `max_parallel`), risultati nell'ordine dato.

        Un esito non OK (exit, timeout, output non valido) non ferma gli altri. Un'eccezione
        (es. il verificatore della firma, R-04) annulla le esecuzioni non ancora avviate, attende
        quelle in corso (che puliscono i propri container) e poi si propaga.
        """
        if not requests:
            return []
        self.isolation()  # rileva e fallisce prima di creare thread; i thread non lo condividono
        with ThreadPoolExecutor(max_workers=self._max_parallel) as pool:
            futures = [pool.submit(self.run, r) for r in requests]
            try:
                return [f.result() for f in futures]
            except BaseException:
                for f in futures:
                    f.cancel()
                raise

    def sync_feeds(self, request: FeedsSyncRequest) -> PluginRunResult:
        """Stessa immagine, con rete e senza workspace; `snapshot_dir` scrivibile da `65534`
        (lo prepara il chiamante, R-06)."""
        manifest = request.manifest
        feeds = manifest.feeds
        assert feeds is not None
        isolation = self.isolation()
        try:
            mounts = [bind_mount(_existing_dir(request.snapshot_dir), FEEDS_MOUNT, readonly=False)]
            return self._execute(
                manifest,
                mounts,
                isolation,
                timeout=parse_duration(feeds.sync_timeout),
                network=True,
                entrypoint=feeds.sync_command[0],
                command=feeds.sync_command[1:],
            )
        except _RunError as exc:
            return self._result(RunOutcome.FAILED, None, isolation, 0.0, None, str(exc))

    def _execute(
        self,
        manifest: PackagedPluginManifest,
        mounts: Sequence[list[str]],
        isolation: Isolation,
        *,
        timeout: int,
        out: Path | None = None,
        network: bool = False,
        entrypoint: str | None = None,
        command: Sequence[str] = (),
    ) -> PluginRunResult:
        image = self._image_ref(manifest.image)
        signature = Signature.SKIPPED
        if self._verifier is not None:
            signature = self._verifier(manifest, image)  # R-04: eccezione = nessun container
        name = f"ca-{manifest.name}-{uuid.uuid4().hex[:16]}"
        args = container_args(
            name=name,
            image=image,
            manifest=manifest,
            mounts=mounts,
            isolation=isolation,
            network=network,
            entrypoint=entrypoint,
            command=command,
        )
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

        try:
            if self._verifier is not None:  # stesso digest verificato, mai un tag
                try:
                    pulled = self._cli("pull", "--quiet", image, timeout=_PULL_TIMEOUT)
                except subprocess.TimeoutExpired:
                    return finish(RunOutcome.FAILED, None, "pull oltre il tempo massimo")
                if pulled.returncode != 0:
                    return finish(RunOutcome.FAILED, None, f"pull fallito: {_brief(pulled.stderr)}")
            created = self._cli(*args, timeout=_CREATE_TIMEOUT)
            if created.returncode != 0:
                return finish(RunOutcome.FAILED, None, f"create fallito: {_brief(created.stderr)}")
            started = time.monotonic()  # il timeout del manifest vale dall'avvio
            if (s := self._cli("start", name)).returncode != 0:
                return finish(RunOutcome.FAILED, None, f"start fallito: {_brief(s.stderr)}")
            try:
                waited = self._cli("wait", name, timeout=timeout)
            except subprocess.TimeoutExpired:
                return finish(RunOutcome.TIMEOUT, None, f"timeout oltre {timeout}s")
            if waited.returncode != 0:
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
                self._check_outputs(manifest, out)
            return finish(RunOutcome.OK, 0, None, keep=True)
        except _RunError as exc:
            return finish(RunOutcome.FAILED, 0, str(exc))
        finally:
            # Anche con eccezioni e a timeout: kill del container, non del solo client (T-02).
            with contextlib.suppress(Exception):
                self._cli("kill", name)
            with contextlib.suppress(Exception):
                self._cli("rm", "--force", "--volumes", name)

    def _check_outputs(self, manifest: PackagedPluginManifest, out: Path) -> None:
        """Un output dichiarato assente, non regolare, symlink o oltre il limite fa fallire."""
        outputs = manifest.outputs
        for declared in (outputs.sarif, outputs.cyclonedx):
            if declared is None:
                continue
            try:
                self._reader.check(str(out), Path(declared).name, outputs.max_bytes)
            except SourceTooLarge as exc:
                raise _RunError(f"output oltre il limite: {Path(declared).name}") from exc
            except SourceError as exc:
                raise _RunError(f"output non valido: {Path(declared).name}") from exc

    @staticmethod
    def _result(
        outcome: RunOutcome,
        code: int | None,
        isolation: Isolation,
        duration: float,
        output_dir: str | None,
        detail: str | None,
        signature: Signature = Signature.SKIPPED,
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
    "digest_ref",
    "parse_duration",
    "require_isolation",
]
