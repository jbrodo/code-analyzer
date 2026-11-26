"""Adattatore del plugin scancode (P-06). Python standard: non importa `ca_core` (ADR-0007).

Gira nell'immagine con il profilo `hardened-container` (ADR-0004): `/workspace` in sola lettura,
`/out` scrivibile, `/tmp` tmpfs, nessuna rete. scancode non produce SARIF: l'adattatore esegue la
sola rilevazione delle licenze, legge il JSON nativo e scrive in `/out` un SARIF 2.1.0 con un
risultato per file con licenza rilevata (ADR-0007, ADR-0013): `ruleId` `ca.license`, `uri` relativo
alla radice del workspace senza `uriBaseId`, regione che copre tutte le corrispondenze del file,
`properties.license_spdx` con l'espressione SPDX del file, nessuno `snippet`. Il testo trovato nel
file non esce mai: `message.text` e' fisso.

Il contenuto del repository e' un dato non fidato; qualunque errore di scansione di un file (per
esempio il timeout) fa fallire il plugin, perche' un file non letto e' un falso negativo.

Uscite: 0 ok; 3 scancode fallito o senza output; 5 JSON non conforme (non JSON, intestazione
mancante, errori di scansione, percorso assoluto o con `..`).
"""

import json
import math
import os
import subprocess
import sys
from pathlib import Path
from typing import Any
from urllib.parse import quote

SCANCODE = "/opt/venv/bin/scancode"
WORKSPACE = "/workspace"
OUT_FILE = "/out/results.sarif"
TMP_DIR = "/tmp"  # noqa: S108 - tmpfs del profilo
CGROUP_CPU_MAX = "/sys/fs/cgroup/cpu.max"
FILE_TIMEOUT = 120  # secondi per file (come V-08)
RULE_ID = "ca.license"
MESSAGE = "Licenza rilevata da scancode"
EXIT_TOOL, EXIT_INVALID = 3, 5


class InvalidOutput(ValueError):
    """Il JSON di scancode non e' conforme o segnala errori di scansione."""


def _uri(path: str) -> str:
    """Percorso codificato per l'`uri` del SARIF (ADR-0004): l'host rifiuta `?` e `#`, scambia
    `a:` per uno schema e decodifica `%XX`. `fsencode` conserva anche i nomi non UTF-8."""
    return quote(os.fsencode(path), safe="/")


def processes(cpu_max: str = CGROUP_CPU_MAX) -> int:
    """CPU concesse al container (`--cpus`): scancode ne vedrebbe tutte quelle dell'host."""
    try:
        quota, period = Path(cpu_max).read_text().split()[:2]
        return max(1, math.ceil(int(quota) / int(period)))
    except (OSError, ValueError):
        return 1


def _safe_path(path: Any) -> str:
    if not isinstance(path, str) or not path or path.startswith("/") or "\x00" in path:
        raise InvalidOutput("percorso non relativo")
    if ".." in path.split("/"):
        raise InvalidOutput("percorso con ..")
    return path


def _region(detections: list[Any]) -> dict[str, int] | None:
    matches = [
        m
        for d in detections
        if isinstance(d, dict)
        for m in d.get("matches") or []
        if isinstance(m, dict) and isinstance(m.get("start_line"), int)
    ]
    if not matches:
        return None
    start = min(m["start_line"] for m in matches)
    ends = [m["end_line"] for m in matches if isinstance(m.get("end_line"), int)]
    return {"startLine": start, "endLine": max([start, *ends])}


def adapt(raw: bytes) -> bytes:
    """JSON nativo di scancode -> SARIF del contratto, o `InvalidOutput`."""
    try:
        document = json.loads(raw)
    except (ValueError, RecursionError) as exc:
        raise InvalidOutput("non e' JSON") from exc
    if not isinstance(document, dict) or not isinstance(document.get("files"), list):
        raise InvalidOutput("elenco `files` assente")
    headers = document.get("headers")
    if not isinstance(headers, list) or not headers or not isinstance(headers[0], dict):
        raise InvalidOutput("intestazione assente")
    if headers[0].get("errors"):
        raise InvalidOutput("errori di scansione")
    results: list[dict[str, Any]] = []
    for entry in document["files"]:
        if not isinstance(entry, dict):
            raise InvalidOutput("voce non valida")
        if entry.get("scan_errors"):
            raise InvalidOutput("errori di scansione")
        spdx = entry.get("detected_license_expression_spdx")
        if entry.get("type") != "file" or not isinstance(spdx, str) or not spdx:
            continue
        location: dict[str, Any] = {
            "artifactLocation": {"uri": _uri(_safe_path(entry.get("path")))}
        }
        region = _region(entry.get("license_detections") or [])
        if region:
            location["region"] = region
        results.append(
            {
                "ruleId": RULE_ID,
                "level": "note",
                "message": {"text": MESSAGE},
                "locations": [{"physicalLocation": location}],
                "properties": {"license_spdx": spdx[:256]},
            }
        )
    results.sort(key=lambda r: r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"])
    sarif = {
        "version": "2.1.0",
        "runs": [
            {
                "tool": {"driver": {"name": "scancode-toolkit", "rules": [{"id": RULE_ID}]}},
                "results": results,
            }
        ],
    }
    return json.dumps(sarif, separators=(",", ":")).encode()


def command(scancode: str, workspace: str, raw_file: str, nproc: int) -> list[str]:
    return [
        scancode, "--license", "--only-findings", "--strip-root", "--quiet",
        "--ignore", ".git/*", "-n", str(nproc), "--timeout", str(FILE_TIMEOUT),
        "--json", raw_file, workspace,
    ]  # fmt: skip


def run(
    *,
    scancode: str = SCANCODE,
    workspace: str = WORKSPACE,
    out_file: str = OUT_FILE,
    tmp_dir: str = TMP_DIR,
    nproc: int | None = None,
) -> int:
    env = {"PATH": os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin"), "HOME": tmp_dir}
    raw_file = Path(tmp_dir, "scancode.json")
    raw_file.unlink(missing_ok=True)
    try:
        done = subprocess.run(  # noqa: S603 - argv a lista, binario fissato, nessuna shell
            command(scancode, workspace, str(raw_file), nproc or processes()),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            cwd=tmp_dir,
            env=env,
            check=False,
        )
        if done.returncode != 0:
            return EXIT_TOOL
        raw = raw_file.read_bytes()
    except OSError:
        return EXIT_TOOL
    try:
        adapted = adapt(raw)
    except InvalidOutput:
        return EXIT_INVALID
    Path(out_file).write_bytes(adapted)
    return 0


if __name__ == "__main__":
    sys.exit(run())
