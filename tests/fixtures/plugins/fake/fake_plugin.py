"""Plugin finto per provare il runner reale (T-02; ADR-0004, ADR-0005, ADR-0007).

Solo libreria standard. Non e' uno scanner: produce un SARIF fisso o simula un comportamento
ostile al confine host-plugin. Il comportamento si sceglie con `/inputs/config.json`
(`{"behavior": "<nome>"}`), il file di configurazione che il runner monta per ogni plugin con
`inputs.config: optional`. Niente segreti, niente rete, niente variabili d'ambiente: senza file
vale `success`. Il contenuto di `/workspace` non e' mai letto.

Esito: 0 se il comportamento e' andato come previsto; 3 per `exit-nonzero`; 4 se un tentativo ostile
e' RIUSCITO (violazione del profilo di isolamento: `network`, `write-workspace`, `write-rootfs`,
`exec-tmp`); 64 per ingresso non valido. A fine esecuzione stampa su stdout una riga JSON con
l'identita' del processo e gli esiti dei tentativi, per i test del confine.
"""

import json
import os
import shutil
import socket
import stat
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

BEHAVIORS = (
    "success",
    "exit-nonzero",
    "invalid-sarif",
    "oversize",
    "write-tmp",
    "write-out",
    "symlink-out",
    "network",
    "write-workspace",
    "write-rootfs",
    "exec-tmp",
    "timeout",
    # T-03: comportamenti ostili in piu' (parametri in `/inputs/config.json`)
    "report",
    "fill-out",
    "subdir-out",
    "fifo-out",
)
# Il manifest dichiara max_bytes = 1 MiB: `oversize` lo supera di un MiB.
OVERSIZE_BYTES = 2 * 1024 * 1024
MIB = 1024 * 1024
FILL_MAX_MIB = 512  # tetto della prova di riempimento: mai saturare davvero il disco
BREACH_EXIT = 4
UNREACHABLE = ("192.0.2.1", 9)  # TEST-NET-1 (RFC 5737): mai instradabile


def valid_sarif(extra_padding: int = 0) -> dict[str, Any]:
    run: dict[str, Any] = {
        "tool": {"driver": {"name": "fake-plugin", "semanticVersion": "1.0.0", "rules": []}},
        "invocations": [{"executionSuccessful": True, "toolExecutionNotifications": []}],
        "results": [
            {
                "ruleId": "fake.rule",
                "level": "warning",
                "message": {"text": "finding di prova"},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": "/workspace/app.py",
                                "uriBaseId": "%SRCROOT%",
                            },
                            "region": {"startLine": 1, "endLine": 1},
                        }
                    }
                ],
                "properties": {},
            }
        ],
    }
    if extra_padding:
        run["properties"] = {"padding": "x" * extra_padding}
    return {"version": "2.1.0", "runs": [run]}


def _write_sarif(out: Path, data: dict[str, Any]) -> None:
    (out / "results.sarif").write_text(json.dumps(data), encoding="utf-8")


def _attempt(action: Any) -> str:
    """'ok' se l'azione riesce, altrimenti il nome dell'errore (es. 'EROFS')."""
    try:
        action()
    except OSError as exc:
        return errno_name(exc)
    return "ok"


def errno_name(exc: OSError) -> str:
    return os.strerror(exc.errno) if exc.errno else type(exc).__name__


def _write(path: Path, text: str = "probe") -> None:
    path.write_text(text, encoding="utf-8")
    path.unlink()


def _network() -> str:
    try:
        with socket.create_connection(UNREACHABLE, timeout=2):
            return "ok"
    except OSError as exc:
        return errno_name(exc) if exc.errno else "timeout"


def _exec_tmp(tmp: Path) -> str:
    target = tmp / "ca-fake-exec"
    shutil.copy(sys.executable, target)
    target.chmod(stat.S_IRWXU)
    try:
        subprocess.run([str(target), "-c", "pass"], check=True, capture_output=True)
    except OSError as exc:
        return errno_name(exc)
    except subprocess.CalledProcessError:
        return "failed"
    finally:
        target.unlink(missing_ok=True)
    return "ok"


def _fill_out(out: Path, params: dict[str, Any]) -> dict[str, str]:
    """Scrive `mib` MiB in `/out/fill.bin` (tetto `FILL_MAX_MIB`); con `hold` poi dorme.

    Riporta quanti MiB sono stati scritti e l'eventuale errore. Nessun limite di quota e'
    imposto dal plugin: serve a misurare quanto il confine lascia scrivere (T-03).
    """
    target = min(int(params.get("mib", 8)), FILL_MAX_MIB)
    chunk = b"\0" * MIB
    written = 0
    error = "none"
    try:
        with (out / "fill.bin").open("wb", buffering=0) as handle:
            while written < target:
                handle.write(chunk)
                written += 1
    except OSError as exc:
        error = errno_name(exc)
    return {"fill_mib": str(written), "fill_error": error}


def _subdir_out(out: Path, params: dict[str, Any]) -> dict[str, str]:
    """Crea `/out/<name>/f` e poi imposta i permessi della sottodirectory (`mode`, intero)."""
    name = str(params.get("name", "locked"))
    mode = int(params.get("mode", 0))
    sub = out / name
    sub.mkdir()
    (sub / "f").write_text("sottodirectory del plugin", encoding="utf-8")
    sub.chmod(mode)
    return {"subdir": "ok", "subdir_mode": oct(mode)}


def run(
    behavior: str,
    params: dict[str, Any] | None = None,
    *,
    out: Path = Path("/out"),
    workspace: Path = Path("/workspace"),
    tmp: Path = Path("/tmp"),  # noqa: S108
    rootfs_probe: Path = Path("/opt/ca-fake-rootfs-probe"),
) -> tuple[int, dict[str, Any]]:
    """Esegue `behavior`; ritorna (exit code, rapporto delle prove)."""
    params = params or {}
    probes: dict[str, str] = {}
    code = 0
    if behavior == "exit-nonzero":
        print("fake-plugin: uscita simulata con errore", file=sys.stderr)
        return 3, probes
    if behavior == "timeout":
        time.sleep(3600)
        return 0, probes
    if behavior == "invalid-sarif":
        (out / "results.sarif").write_text('{"version": "2.1.0", "runs": [', encoding="utf-8")
        return 0, probes
    if behavior == "oversize":
        _write_sarif(out, valid_sarif(OVERSIZE_BYTES))
        return 0, probes
    if behavior == "symlink-out":
        # Il bersaglio e' un file leggibile del container: l'host non deve seguirlo.
        (out / "results.sarif").symlink_to("/etc/passwd")
        return 0, probes

    if behavior == "fifo-out":
        os.mkfifo(out / "results.sarif")
        return 0, probes

    if behavior == "fill-out":
        _write_sarif(out, valid_sarif())
        probes.update(_fill_out(out, params))
        if params.get("hold"):
            time.sleep(3600)
        return 0, probes
    if behavior == "subdir-out":
        probes.update(_subdir_out(out, params))
    elif behavior == "write-tmp":
        probes["tmp_write"] = _attempt(lambda: _write(tmp / "ca-fake-probe"))
    elif behavior == "write-out":
        probes["out_write"] = _attempt(lambda: (out / "extra.txt").write_text("extra"))
    elif behavior == "network":
        probes["network"] = _network()
        code = BREACH_EXIT if probes["network"] == "ok" else 0
    elif behavior == "write-workspace":
        probes["workspace_write"] = _attempt(lambda: _write(workspace / "ca-fake-probe"))
        code = BREACH_EXIT if probes["workspace_write"] == "ok" else 0
    elif behavior == "write-rootfs":
        probes["rootfs_write"] = _attempt(lambda: _write(rootfs_probe))
        code = BREACH_EXIT if probes["rootfs_write"] == "ok" else 0
    elif behavior == "exec-tmp":
        probes["tmp_exec"] = _exec_tmp(tmp)
        code = BREACH_EXIT if probes["tmp_exec"] == "ok" else 0
    _write_sarif(out, valid_sarif())
    return code, probes


def _identity() -> dict[str, Any]:
    return {
        "uid": os.getuid(),
        "gid": os.getgid(),
        "home": os.environ.get("HOME"),
        "env_keys": sorted(os.environ),
    }


def _status_fields() -> dict[str, str]:
    wanted = ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb", "NoNewPrivs", "Seccomp")
    found: dict[str, str] = {}
    for line in Path("/proc/self/status").read_text().splitlines():
        key, _, value = line.partition(":")
        if key in wanted:
            found[key] = value.strip()
    return found


def _mount_options() -> dict[str, str]:
    """Opzioni di montaggio (per-mount) dei punti che contano, da `/proc/self/mountinfo`."""
    found: dict[str, str] = {}
    for line in Path("/proc/self/mountinfo").read_text().splitlines():
        fields = line.split()
        if fields[4] in {"/", "/tmp", "/workspace", "/out", "/inputs/config.json"}:  # noqa: S108
            found[fields[4]] = fields[5]
    return found


def _cgroup_limits() -> dict[str, str]:
    found: dict[str, str] = {}
    for name in ("pids.max", "memory.max", "memory.swap.max", "cpu.max"):
        try:
            found[name] = (Path("/sys/fs/cgroup") / name).read_text().strip()
        except OSError:
            found[name] = "unreadable"
    return found


def _read_workspace(workspace: Path, name: str) -> dict[str, Any]:
    """Legge UN file al primo livello di `/workspace`, indicato dal chiamante (mai altro)."""
    try:
        target = workspace / Path(name).name
        info = target.stat()
        return {
            "uid": info.st_uid,
            "mode": oct(info.st_mode & 0o777),
            "content": target.read_text(encoding="utf-8")[:200],
        }
    except OSError as exc:
        return {"error": errno_name(exc)}


def _isolation_report(params: dict[str, Any]) -> dict[str, Any]:
    """Quello che il processo vede dall'interno (T-03): prova il profilo, non la logica."""
    return {
        "uid": os.getuid(),
        "gid": os.getgid(),
        "groups": sorted(os.getgroups()),
        "env": dict(sorted(os.environ.items())),
        "status": _status_fields(),
        "mounts": _mount_options(),
        "cgroup": _cgroup_limits(),
        "docker_sock": Path("/var/run/docker.sock").exists(),
        "workspace": (
            _read_workspace(Path("/workspace"), str(params["read"])) if "read" in params else None
        ),
        "out_mode": oct(Path("/out").stat().st_mode & 0o777),
    }


def read_params(config: Path = Path("/inputs/config.json")) -> dict[str, Any]:
    """La configurazione (oggetto JSON, al piu' 4 KiB); vuota se il file manca."""
    if not config.exists():
        return {}
    with config.open("rb") as handle:
        raw = handle.read(4097)
    if len(raw) > 4096:
        raise ValueError("configurazione troppo grande")
    value = json.loads(raw)
    behavior = value.get("behavior", "success") if isinstance(value, dict) else None
    if behavior not in BEHAVIORS:
        raise ValueError("comportamento sconosciuto")
    return dict(value)


def read_behavior(config: Path = Path("/inputs/config.json")) -> str:
    """Il comportamento dalla configurazione; `success` se il file manca."""
    return str(read_params(config).get("behavior", "success"))


def main() -> int:
    try:
        params = read_params()
    except (ValueError, OSError) as exc:
        print(f"fake-plugin: ingresso non valido: {exc}", file=sys.stderr)
        return 64
    behavior = str(params.get("behavior", "success"))
    code, probes = run(behavior, params)
    if behavior == "report" or params.get("report"):  # opt-in: cambia l'elenco dei file di /out
        report = {**_isolation_report(params), "probes": probes}
        (Path("/out") / "report.json").write_text(json.dumps(report), encoding="utf-8")
    print(json.dumps({"behavior": behavior, **_identity(), "probes": probes}, sort_keys=True))
    return code


if __name__ == "__main__":
    sys.exit(main())
