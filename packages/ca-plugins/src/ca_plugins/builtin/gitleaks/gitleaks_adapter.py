"""Adattatore del plugin gitleaks (P-07). Python standard: non importa `ca_core` (ADR-0007).

Gira nell'immagine con il profilo `hardened-container` (ADR-0004): `/workspace` in sola lettura,
`/out` scrivibile, `/tmp` tmpfs, nessuna rete. Segue ADR-0012 e il suo emendamento per P-07.

Il repository analizzato e' un dato non fidato e `.git/config` e' codice (textconv, programmi di
firma, promisor `ext::`): gitleaks non legge mai la git dir del workspace. L'adattatore costruisce
in `/tmp` una git dir ombra con una `config` scritta da lui, `HEAD` copiato e collegamenti simbolici
ai soli dati (`objects`, `refs`, `packed-refs`, `shallow`, `reftable`), e la passa a `gitleaks git`
con un ambiente `GIT_*` ridotto. Niente `safe.directory` e niente `--log-opts`. La configurazione di
gitleaks e' quella predefinita del tag, passata con `--config`, e `--gitleaks-ignore-path` punta a
una cartella vuota: `.gitleaks.toml` e, in modalita' `git`, `.gitleaksignore` del repository non
hanno effetto. Senza `.git` si scansionano i file con `gitleaks dir` (nessuna storia), ma `dir`
legge sempre `<target>/.gitleaksignore` e non ha un'opzione per evitarlo (N-07, 8.30.1): con quel
file presente il plugin fallisce (uscita 6), mai un risultato vuoto. Mai `--redact`: il valore serve
per l'hash di `properties.secret_sha256` (ADR-0008) e sta solo nel file grezzo in `/tmp`.

In `/out` esce un SARIF che contiene per ogni risultato `ruleId`, regione, `uri` relativo, il
`message` oscurato del modello di K-10 (`<regola> has detected secret for file <uri>[ at commit
<sha>].`) e `secret_sha256`. Mai `snippet`, `email`, `author`, `date`, `commitMessage`.

Uscite: 0 ok; 3 gitleaks fallito, senza output o con un errore `[git]` o `dubious ownership` nel
log; 5 SARIF non conforme; 6 `.git` non ammesso (non e' una directory, `HEAD`, `config` o formato
non ammessi) oppure `.gitleaksignore` nella radice senza `.git`.
"""

import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

GITLEAKS = "/usr/local/bin/gitleaks"
GIT = "/usr/bin/git"
CONFIG = "/opt/ca-plugin/gitleaks.toml"
WORKSPACE = "/workspace"
OUT_FILE = "/out/results.sarif"
TMP_DIR = "/tmp"  # noqa: S108 - tmpfs del profilo
EXIT_TOOL, EXIT_INVALID, EXIT_REPO = 3, 5, 6
SHALLOW_NOTE = "shallow clone: history coverage is reduced"
NO_HISTORY_NOTE = "no git history: only the files of the workspace were scanned"

_HEAD = re.compile(r"(?:ref: refs/[A-Za-z0-9._/-]{1,200}|[0-9a-f]{40}|[0-9a-f]{64})\n?")
_COMMIT = re.compile(r"[0-9a-f]{7,64}")
_GIT_ERROR = re.compile(r"\b(?:ERR|FTL)\b.*\[git\]|\[git\].*\b(?:ERR|FTL)\b|dubious ownership")
_ALLOWED = {
    "core.repositoryformatversion": {"0", "1"},
    "extensions.objectformat": {"sha1", "sha256"},
    "extensions.refstorage": {"files", "reftable"},
}
_DATA = ("refs", "packed-refs", "shallow", "reftable")


class InvalidOutput(ValueError):
    """Il SARIF di gitleaks non e' conforme."""


class UnsupportedRepo(ValueError):
    """`.git` non e' una git dir che l'adattatore sappia replicare in sicurezza."""


def _git_env(tmp_dir: str) -> dict[str, str]:
    return {
        "PATH": os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin"),
        "HOME": tmp_dir,
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_ATTR_NOSYSTEM": "1",
        "GIT_NO_LAZY_FETCH": "1",
    }


def _config_value(git: str, config: Path, key: str, tmp_dir: str) -> str | None:
    """`git config --file` non segue gli include e non esegue nulla."""
    done = subprocess.run(  # noqa: S603 - argv a lista, binario fissato, nessuna shell
        [git, "config", "--file", str(config), "--get", key],
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        env=_git_env(tmp_dir),
        cwd=tmp_dir,
        check=False,
        timeout=30,
    )
    if done.returncode == 1:
        return None
    if done.returncode != 0:
        raise UnsupportedRepo("config illeggibile")
    return done.stdout.strip()


def build_shadow(git: str, git_dir: Path, shadow: Path, tmp_dir: str) -> bool:
    """Crea la git dir ombra in `shadow`; True se il clone e' superficiale."""
    if git_dir.is_symlink() or not git_dir.is_dir():
        raise UnsupportedRepo(".git non e' una directory")
    lines = ["[core]", "\trepositoryformatversion = 0", "\tbare = true"]
    version = _config_value(git, git_dir / "config", "core.repositoryformatversion", tmp_dir)
    if version not in (None, *_ALLOWED["core.repositoryformatversion"]):
        raise UnsupportedRepo("repositoryformatversion non ammessa")
    extensions = []
    for key in ("extensions.objectformat", "extensions.refstorage"):
        value = _config_value(git, git_dir / "config", key, tmp_dir)
        if value is None:
            continue
        if value not in _ALLOWED[key]:
            raise UnsupportedRepo("estensione non ammessa")
        extensions.append(f"\t{key.split('.')[1]} = {value}")
    if extensions:
        lines[1] = "\trepositoryformatversion = 1"
        lines += ["[extensions]", *extensions]
    try:
        with (git_dir / "HEAD").open("rb") as handle:  # un HEAD symlink e' rifiutato dal controllo
            head = handle.read(1024).decode("ascii")
    except (OSError, UnicodeDecodeError) as exc:
        raise UnsupportedRepo("HEAD illeggibile") from exc
    if (git_dir / "HEAD").is_symlink() or not _HEAD.fullmatch(head):
        raise UnsupportedRepo("HEAD non ammesso")
    if not (git_dir / "objects").is_dir() or (git_dir / "objects").is_symlink():
        raise UnsupportedRepo("objects assente")
    shadow.mkdir(mode=0o700)
    (shadow / "config").write_text("\n".join(lines) + "\n")
    (shadow / "HEAD").write_text(head)
    (shadow / "objects").symlink_to(git_dir / "objects")
    for name in _DATA:
        if (git_dir / name).exists():
            if (git_dir / name).is_symlink():
                raise UnsupportedRepo("collegamento simbolico non ammesso")
            (shadow / name).symlink_to(git_dir / name)
    return (git_dir / "shallow").exists()


def _relative_uri(uri: Any, workspace: str) -> str:
    if not isinstance(uri, str) or not uri or "\x00" in uri:
        raise InvalidOutput("uri assente")
    path = uri.removeprefix("file://").removeprefix(workspace + "/")
    if path.startswith("/") or ".." in path.split("/") or "://" in path:
        raise InvalidOutput("uri non relativo")
    return path


def adapt(raw: bytes, workspace: str = WORKSPACE, notes: tuple[str, ...] = ()) -> bytes:
    """SARIF grezzo di gitleaks (con i valori) -> SARIF oscurato del contratto."""
    try:
        document = json.loads(raw)
    except (ValueError, RecursionError) as exc:
        raise InvalidOutput("non e' JSON") from exc
    runs = document.get("runs") if isinstance(document, dict) else None
    if not isinstance(runs, list) or len(runs) != 1 or document.get("version") != "2.1.0":
        raise InvalidOutput("non e' SARIF 2.1.0 con un solo run")
    results: list[dict[str, Any]] = []
    for result in runs[0].get("results") or []:
        try:
            rule = result["ruleId"]
            physical = result["locations"][0]["physicalLocation"]
            region = physical["region"]
            secret = region["snippet"]["text"]
            start, end = int(region["startLine"]), int(region.get("endLine", region["startLine"]))
        except (KeyError, IndexError, TypeError, ValueError) as exc:
            raise InvalidOutput("risultato non conforme") from exc
        if not isinstance(rule, str) or not rule or not isinstance(secret, str) or not secret:
            raise InvalidOutput("risultato non conforme")
        uri = _relative_uri(physical.get("artifactLocation", {}).get("uri"), workspace)
        commit = (result.get("partialFingerprints") or {}).get("commitSha")
        at = f" at commit {commit}" if isinstance(commit, str) and _COMMIT.fullmatch(commit) else ""
        results.append(
            {
                "ruleId": rule,
                "message": {"text": f"{rule} has detected secret for file {uri}{at}."},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": uri},
                            "region": {"startLine": start, "endLine": max(start, end)},
                        }
                    }
                ],
                "properties": {"secret_sha256": hashlib.sha256(secret.encode()).hexdigest()},
            }
        )
    results.sort(key=lambda r: json.dumps(r, sort_keys=True))
    rules = [{"id": i} for i in sorted({r["ruleId"] for r in results})]
    run: dict[str, Any] = {
        "tool": {"driver": {"name": "gitleaks", "rules": rules}},
        "results": results,
    }
    if notes:
        run["invocations"] = [
            {
                "executionSuccessful": True,
                "toolExecutionNotifications": [
                    {"level": "warning", "message": {"text": n}} for n in notes
                ],
            }
        ]
    return json.dumps(
        {"version": "2.1.0", "runs": [run]}, separators=(",", ":"), ensure_ascii=True
    ).encode()


def run(
    *,
    gitleaks: str = GITLEAKS,
    git: str = GIT,
    config: str = CONFIG,
    workspace: str = WORKSPACE,
    out_file: str = OUT_FILE,
    tmp_dir: str = TMP_DIR,
) -> int:
    scratch = Path(tmp_dir, "gitleaks-work")
    raw_file, log_file = scratch / "raw.sarif", scratch / "log.txt"
    notes: tuple[str, ...] = ()
    try:
        shutil.rmtree(scratch, ignore_errors=True)  # area nostra nel tmpfs: sempre da zero
        scratch.mkdir(mode=0o700)
        (scratch / "empty").mkdir()
        (scratch / "cwd").mkdir()
        git_dir = Path(workspace, ".git")
        if os.path.lexists(git_dir):
            shadow = scratch / "shadow"
            shallow = build_shadow(git, git_dir, shadow, tmp_dir)
            mode, target = "git", str(shadow)
            notes = (SHALLOW_NOTE,) if shallow else ()
        else:
            if os.path.lexists(Path(workspace, ".gitleaksignore")):
                raise UnsupportedRepo(".gitleaksignore in modalita' dir")  # N-07
            mode, target, notes = "dir", workspace, (NO_HISTORY_NOTE,)
    except UnsupportedRepo:
        return EXIT_REPO
    except (OSError, subprocess.SubprocessError):
        return EXIT_TOOL
    argv = [
        gitleaks, mode, target, "--config", config,
        "--gitleaks-ignore-path", str(scratch / "empty"),
        "--ignore-gitleaks-allow",
        "--report-format", "sarif", "--report-path", str(raw_file),
        "--no-banner", "--no-color", "--log-level", "info",
    ]  # fmt: skip
    try:
        with log_file.open("wb") as log:
            done = subprocess.run(  # noqa: S603 - argv a lista, binario fissato, nessuna shell
                argv,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=log,
                cwd=scratch / "cwd",
                env=_git_env(tmp_dir),
                check=False,
            )
        if done.returncode not in (0, 1):  # 1 = trovati segreti
            return EXIT_TOOL
        if _GIT_ERROR.search(log_file.read_text(errors="replace")):
            return EXIT_TOOL
        raw = raw_file.read_bytes()
    except OSError:
        return EXIT_TOOL
    try:
        adapted = adapt(raw, workspace, notes)
    except InvalidOutput:
        return EXIT_INVALID
    Path(out_file).write_bytes(adapted)
    return 0


if __name__ == "__main__":
    sys.exit(run())
