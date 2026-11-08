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
)
# Il manifest dichiara max_bytes = 1 MiB: `oversize` lo supera di un MiB.
OVERSIZE_BYTES = 2 * 1024 * 1024
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


def run(
    behavior: str,
    *,
    out: Path = Path("/out"),
    workspace: Path = Path("/workspace"),
    tmp: Path = Path("/tmp"),  # noqa: S108
    rootfs_probe: Path = Path("/opt/ca-fake-rootfs-probe"),
) -> tuple[int, dict[str, Any]]:
    """Esegue `behavior`; ritorna (exit code, rapporto delle prove)."""
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

    if behavior == "write-tmp":
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


def read_behavior(config: Path = Path("/inputs/config.json")) -> str:
    """Il comportamento dalla configurazione; `success` se il file manca."""
    if not config.exists():
        return "success"
    with config.open("rb") as handle:
        raw = handle.read(4097)
    if len(raw) > 4096:
        raise ValueError("configurazione troppo grande")
    value = json.loads(raw)
    behavior = value.get("behavior", "success") if isinstance(value, dict) else None
    if behavior not in BEHAVIORS:
        raise ValueError("comportamento sconosciuto")
    return str(behavior)


def main() -> int:
    try:
        behavior = read_behavior()
    except (ValueError, OSError) as exc:
        print(f"fake-plugin: ingresso non valido: {exc}", file=sys.stderr)
        return 64
    code, probes = run(behavior)
    print(json.dumps({"behavior": behavior, **_identity(), "probes": probes}, sort_keys=True))
    return code


if __name__ == "__main__":
    sys.exit(main())
