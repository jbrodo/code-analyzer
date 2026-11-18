"""Churn per file dalla storia git (G-11, ADR-0022, ADR-0012). Solo la libreria standard.

Gira nel container di estrazione e **non legge mai la configurazione git del workspace**:
`.git/config` è codice (programmi di firma, `core.fsmonitor`, pager, `ext::`), e il workspace è
un input non fidato. Si costruisce in `/tmp` una git dir ombra con una `config` scritta qui, `HEAD`
copiato e validato, e collegamenti ai soli dati (`objects`, `refs`, `packed-refs`, `shallow`,
`reftable`). Un solo comando di lettura della storia, con tetti su commit, byte e durata.

Misura: per ogni file, i commit che lo toccano nei `window_days` giorni che precedono **la data del
commit analizzato** (non quella della scansione: la stessa scansione rifatta dopo un mese dà lo
stesso valore). Esclusi i commit di merge; le rinomine non si seguono.

Stato della storia: `completa` se il clone è completo, o superficiale ma con tutti i commit di
confine più vecchi dell'inizio della finestra; `superficiale` se non copre la finestra (il churn è
ignoto per tutti i file: un conteggio direbbe «poco modificato» di ogni file); `assente` se non c'è
`.git`, se non si sa replicarlo in sicurezza, o se la lettura fallisce o supera un tetto. Mai un
valore inventato.
"""

import os
import re
import shutil
import signal
import subprocess
import tempfile
import threading
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

GIT = "/usr/bin/git"
TMP_DIR = "/tmp"  # noqa: S108 - tmpfs del profilo hardened
MAX_COMMITS = 200_000
MAX_OUTPUT_BYTES = 256 * 1024 * 1024
MAX_BOUNDARIES = 200
TIMEOUT_SECONDS = 120
COMPLETE, SHALLOW, ABSENT = "completa", "superficiale", "assente"

_HEAD = re.compile(r"(?:ref: refs/[A-Za-z0-9._/-]{1,200}|[0-9a-f]{40}|[0-9a-f]{64})\n?")
_SHA = re.compile(r"[0-9a-f]{40}|[0-9a-f]{64}")
_ALLOWED = {
    "core.repositoryformatversion": {"0", "1"},
    "extensions.objectformat": {"sha1", "sha256"},
    "extensions.refstorage": {"files", "reftable"},
}
_DATA = ("refs", "packed-refs", "shallow", "reftable")


class UnsupportedRepo(ValueError):
    """`.git` non è una git dir che si sappia replicare in sicurezza."""


class ReadFailed(ValueError):
    """La lettura della storia è fallita o ha superato un tetto."""


@dataclass
class History:
    status: str
    window_days: int
    head_time: datetime | None = None
    commits_read: int = 0
    churn: dict[str, int] = field(default_factory=dict)  # solo con `completa`

    def document(self) -> dict[str, object]:
        out: dict[str, object] = {"status": self.status, "window_days": self.window_days}
        if self.head_time is not None:
            out["head_time"] = self.head_time.isoformat()
        if self.commits_read:
            out["commits_read"] = self.commits_read
        return out


def _env(tmp_dir: str) -> dict[str, str]:
    return {
        "PATH": "/usr/local/bin:/usr/bin:/bin",
        "HOME": tmp_dir,
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_ATTR_NOSYSTEM": "1",
        "GIT_NO_LAZY_FETCH": "1",
        "GIT_NO_REPLACE_OBJECTS": "1",
        "GIT_OPTIONAL_LOCKS": "0",
        "GIT_TERMINAL_PROMPT": "0",
    }


def _kill(process: subprocess.Popen[bytes]) -> None:
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError, PermissionError:
        process.kill()


def _run(argv: list[str], tmp_dir: str, *, limit: int = 1024 * 1024) -> bytes:
    """Un comando git con un tetto sull'uscita e sulla durata; `ReadFailed` se fallisce.

    Un timer termina il processo allo scadere: la lettura dell'uscita da sola non scadrebbe mai.
    """
    expired = threading.Event()
    try:
        with subprocess.Popen(  # noqa: S603 - argv a lista, binario fissato, nessuna shell
            argv,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            env=_env(tmp_dir),
            cwd=tmp_dir,
            start_new_session=True,  # un solo gruppo: si termina anche ciò che git avvia
        ) as process:
            assert process.stdout is not None

            def stop() -> None:
                expired.set()
                _kill(process)

            timer = threading.Timer(TIMEOUT_SECONDS, stop)
            timer.start()
            try:
                data = process.stdout.read(limit + 1)
                if len(data) > limit:
                    _kill(process)
                    raise ReadFailed("uscita oltre il tetto")
                process.wait()
            finally:
                timer.cancel()
            if expired.is_set():
                raise ReadFailed("tempo scaduto")
            if process.returncode != 0:
                raise ReadFailed("git fallito")
            return data
    except OSError as exc:
        raise ReadFailed("git non eseguibile") from exc


def _config_value(git: str, config: Path, key: str, tmp_dir: str) -> str | None:
    """`git config --file` non segue gli include e non esegue nulla."""
    try:
        done = subprocess.run(  # noqa: S603
            [git, "config", "--file", str(config), "--get", key],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            env=_env(tmp_dir),
            cwd=tmp_dir,
            check=False,
            timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise UnsupportedRepo("config illeggibile") from exc
    if done.returncode == 1:
        return None
    if done.returncode != 0:
        raise UnsupportedRepo("config illeggibile")
    return done.stdout.strip()


def build_shadow(git: str, git_dir: Path, shadow: Path, tmp_dir: str) -> bool:
    """Crea la git dir ombra in `shadow`; True se il clone è superficiale."""
    if git_dir.is_symlink() or not git_dir.is_dir():
        raise UnsupportedRepo(".git non è una directory")
    config = git_dir / "config"
    lines = ["[core]", "\trepositoryformatversion = 0", "\tbare = true"]
    version = _config_value(git, config, "core.repositoryformatversion", tmp_dir)
    if version not in (None, *_ALLOWED["core.repositoryformatversion"]):
        raise UnsupportedRepo("repositoryformatversion non ammessa")
    extensions = []
    for key in ("extensions.objectformat", "extensions.refstorage"):
        value = _config_value(git, config, key, tmp_dir)
        if value is None:
            continue
        if value not in _ALLOWED[key]:
            raise UnsupportedRepo("estensione non ammessa")
        extensions.append(f"\t{key.split('.')[1]} = {value}")
    if extensions:
        lines[1] = "\trepositoryformatversion = 1"
        lines += ["[extensions]", *extensions]
    head_path = git_dir / "HEAD"
    try:
        if head_path.is_symlink():
            raise UnsupportedRepo("HEAD non ammesso")
        with head_path.open("rb") as handle:
            head = handle.read(1024).decode("ascii")
    except (OSError, UnicodeDecodeError) as exc:
        raise UnsupportedRepo("HEAD illeggibile") from exc
    if not _HEAD.fullmatch(head):
        raise UnsupportedRepo("HEAD non ammesso")
    objects = git_dir / "objects"
    if objects.is_symlink() or not objects.is_dir():
        raise UnsupportedRepo("objects assente")
    shadow.mkdir(mode=0o700)
    (shadow / "config").write_text("\n".join(lines) + "\n")
    (shadow / "HEAD").write_text(head)
    (shadow / "objects").symlink_to(objects)
    for name in _DATA:
        if (git_dir / name).exists():
            if (git_dir / name).is_symlink():
                raise UnsupportedRepo("collegamento simbolico non ammesso")
            (shadow / name).symlink_to(git_dir / name)
    return (git_dir / "shallow").exists()


def _commit_time(git: str, shadow: Path, revision: str, tmp_dir: str) -> int:
    out = _run([git, f"--git-dir={shadow}", "show", "-s", "--format=%ct", revision], tmp_dir)
    text = out.decode("ascii", "replace").strip()
    if not text.isdigit():
        raise ReadFailed("data del commit non valida")
    return int(text)


def _boundaries_older_than(git: str, git_dir: Path, shadow: Path, start: int, tmp: str) -> bool:
    """Tutti i commit di confine di un clone superficiale sono più vecchi dell'inizio?"""
    try:
        text = (git_dir / "shallow").read_text("ascii")
    except OSError, UnicodeDecodeError:
        return False
    shas = text.split()
    if not shas or len(shas) > MAX_BOUNDARIES or not all(_SHA.fullmatch(s) for s in shas):
        return False
    try:
        return all(_commit_time(git, shadow, s, tmp) < start for s in shas)
    except ReadFailed:
        return False


def parse_log(data: bytes) -> tuple[int, dict[str, int]]:
    """(commit letti, commit per file) da `git log -z --name-only --format=%x01%H%x02`."""
    counts: dict[str, int] = {}
    commits = 0
    for chunk in data.split(b"\x01")[1:]:
        _, separator, rest = chunk.partition(b"\x02")
        if not separator:
            raise ReadFailed("uscita non riconosciuta")
        commits += 1
        for name in rest.removeprefix(b"\0\n").split(b"\0"):
            if not name:
                continue
            path = name.decode("utf-8", "surrogateescape")
            counts[path] = counts.get(path, 0) + 1
    return commits, counts


def read_history(
    workspace: str, window_days: int = 90, *, git: str = GIT, tmp_dir: str = TMP_DIR
) -> History:
    git_dir = Path(workspace) / ".git"
    if not os.path.lexists(git_dir):
        return History(ABSENT, window_days)
    scratch = tempfile.mkdtemp(prefix="ca-history-", dir=tmp_dir)
    try:
        shadow = Path(scratch) / "git"
        try:
            shallow = build_shadow(git, git_dir, shadow, scratch)
            head_ts = _commit_time(git, shadow, "HEAD", scratch)
        except UnsupportedRepo, ReadFailed:
            return History(ABSENT, window_days)
        head_time = datetime.fromtimestamp(head_ts, UTC)
        start = head_ts - window_days * 86400
        if shallow and not _boundaries_older_than(git, git_dir, shadow, start, scratch):
            return History(SHALLOW, window_days, head_time)
        try:
            data = _run(
                [
                    git, f"--git-dir={shadow}", "log", "--no-merges", "--no-renames",
                    "--no-ext-diff", "--no-textconv", "-z", "--name-only",
                    "--format=%x01%H%x02", f"--since={start}", f"-n{MAX_COMMITS + 1}", "HEAD",
                ],
                scratch,
                limit=MAX_OUTPUT_BYTES,
            )  # fmt: skip
            commits, counts = parse_log(data)
        except ReadFailed:
            return History(ABSENT, window_days)
        if commits > MAX_COMMITS:
            return History(ABSENT, window_days)
        return History(COMPLETE, window_days, head_time, commits, counts)
    finally:
        shutil.rmtree(scratch, ignore_errors=True)
