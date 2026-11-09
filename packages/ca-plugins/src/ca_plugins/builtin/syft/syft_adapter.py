"""Adattatore del plugin syft (P-01). Python standard: non importa `ca_core` (ADR-0007).

Gira nell'immagine con il profilo `hardened-container` (ADR-0004): `/workspace` in sola lettura,
`/out` scrivibile, `/tmp` tmpfs, nessuna rete. Esegue syft sul workspace, riscrive i percorsi in
modo che siano relativi alla radice del workspace (ADR-0007, emendamento) e scrive in `/out` un
solo file CycloneDX 1.7. L'output di syft e il repository sono dati non fidati: si leggono come
JSON, non si interpretano e non si riportano in stdout o stderr.

Uscite: 0 ok; 3 syft fallito o senza output; 5 output di syft non conforme (non JSON, non 1.7,
percorso assoluto del workspace rimasto).
"""

import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

SYFT = "/usr/local/bin/syft"
WORKSPACE = "/workspace"
OUT_FILE = "/out/sbom.cdx.json"
TMP_FILE = "/tmp/syft.cdx.json"  # noqa: S108 - tmpfs del profilo, mai un percorso condiviso
SPEC_VERSION = "1.7"
EXIT_SYFT, EXIT_INVALID = 3, 5
_LOCATION = re.compile(r"^syft:location:\d+:path$")


class InvalidOutput(ValueError):
    """L'output di syft non è un CycloneDX 1.7 con percorsi relativi."""


def _relative(value: str, workspace: str) -> str:
    if value == workspace:
        return "."
    return value.removeprefix(workspace + "/")


def _leading_slash(node: dict[str, Any]) -> None:
    """Percorsi che syft scrive con `/` iniziale ma relativi alla radice scandita."""
    if node.get("type") == "file" and isinstance(node.get("name"), str):
        node["name"] = node["name"].lstrip("/")
    if _LOCATION.match(str(node.get("name"))) and isinstance(node.get("value"), str):
        node["value"] = node["value"].lstrip("/")


def _rewrite(value: Any, workspace: str) -> Any:
    if isinstance(value, str):
        return _relative(value, workspace)
    if isinstance(value, list):
        return [_rewrite(v, workspace) for v in value]
    if isinstance(value, dict):
        node = {k: _rewrite(v, workspace) for k, v in value.items()}
        _leading_slash(node)
        return node
    return value


def _leftover(value: Any, workspace: str) -> bool:
    if isinstance(value, str):
        return workspace in value
    if isinstance(value, list):
        return any(_leftover(v, workspace) for v in value)
    if isinstance(value, dict):
        return any(_leftover(v, workspace) for v in value.values())
    return False


def adapt(raw: bytes, workspace: str = WORKSPACE) -> bytes:
    """CycloneDX di syft -> CycloneDX con percorsi relativi, o `InvalidOutput`."""
    try:
        document = json.loads(raw)
    except (ValueError, RecursionError) as exc:
        raise InvalidOutput("non è JSON") from exc
    if not isinstance(document, dict) or document.get("bomFormat") != "CycloneDX":
        raise InvalidOutput("non è CycloneDX")
    if document.get("specVersion") != SPEC_VERSION:
        raise InvalidOutput("specVersion diversa da 1.7")
    document = _rewrite(document, workspace)
    if _leftover(document, workspace):
        raise InvalidOutput("percorso assoluto del workspace")
    return json.dumps(document, separators=(",", ":")).encode()


def run(
    *,
    syft: str = SYFT,
    workspace: str = WORKSPACE,
    out_file: str = OUT_FILE,
    tmp_file: str = TMP_FILE,
) -> int:
    env = {
        "PATH": os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin"),
        "HOME": os.environ.get("HOME", "/tmp"),  # noqa: S108
        "SYFT_CHECK_FOR_APP_UPDATE": "false",
    }
    Path(tmp_file).unlink(missing_ok=True)
    try:
        done = subprocess.run(  # noqa: S603 - argv a lista, binario fissato, nessuna shell
            [syft, "scan", f"dir:{workspace}", "-q", "-o", f"cyclonedx-json@1.7={tmp_file}"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            env=env,
            check=False,
        )
        if done.returncode != 0:
            return EXIT_SYFT
        raw = Path(tmp_file).read_bytes()
    except OSError:
        return EXIT_SYFT
    try:
        adapted = adapt(raw, workspace)
    except InvalidOutput:
        return EXIT_INVALID
    Path(out_file).write_bytes(adapted)
    return 0


if __name__ == "__main__":
    sys.exit(run())
