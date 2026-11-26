"""Adattatore del plugin bandit (P-08). Python standard: non importa `ca_core` (ADR-0007).

Gira nell'immagine con il profilo `hardened-container` (ADR-0004): `/workspace` in sola lettura,
`/out` scrivibile, `/tmp` tmpfs, nessuna rete. Esegue bandit (SARIF, extra `bandit[sarif]`) con
`--skip B105,B106,B107` (ADR-0012: i segreti sono compito di gitleaks) e riscrive il SARIF nel
contratto di ADR-0007: `uri` relativi alla radice del workspace senza `uriBaseId`, nessuno
`snippet` ne `contextRegion` (senza snippet non porta altro), `properties` ridotte a
`tool_severity`. B101 (`assert`) si scarta nei soli file di test (P-07, D2-08), riconosciuti dal
percorso con le regole fisse di `is_test_path`: nei test un `assert` e' la norma, altrove sparisce
con `-O` e resta un finding. La configurazione del repository (`.bandit`, `pyproject.toml`) non
si legge: e' un dato non fidato che potrebbe spegnere i controlli.

Uscite: 0 ok; 3 bandit fallito o senza output; 5 SARIF non conforme (non JSON, non 2.1.0, `uri`
fuori dal workspace).
"""

import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any
from urllib.parse import unquote

BANDIT = "/opt/venv/bin/bandit"
WORKSPACE = "/workspace"
OUT_FILE = "/out/results.sarif"
TMP_DIR = "/tmp"  # noqa: S108 - tmpfs del profilo
SKIP = "B105,B106,B107"
EXIT_TOOL, EXIT_INVALID = 3, 5
# Regole di percorso fisse, non lette dal repository (ADR-0014). Chi rinomina una cartella in
# `tests` nasconde solo i propri B101, nessun'altra regola.
TEST_ONLY_SKIP = "B101"
TEST_DIRS = frozenset({"test", "tests", "testing"})


class InvalidOutput(ValueError):
    """L'output di bandit non e' un SARIF 2.1.0 con percorsi relativi."""


def _relative_uri(uri: str, workspace: str) -> str:
    path = uri.removeprefix("file://")
    if path == workspace:
        return "."
    if not path.startswith(workspace + "/"):
        raise InvalidOutput("uri fuori dal workspace")
    return path[len(workspace) + 1 :]


def _clean(value: Any, workspace: str) -> Any:
    if isinstance(value, list):
        return [_clean(v, workspace) for v in value]
    if not isinstance(value, dict):
        return value
    out: dict[str, Any] = {}
    for key, child in value.items():
        if key.casefold() in {"snippet", "uribaseid", "contextregion"}:
            continue
        if key == "artifactLocation" and isinstance(child, dict):
            uri = child.get("uri")
            if not isinstance(uri, str):
                raise InvalidOutput("artifactLocation senza uri")
            out[key] = {"uri": _relative_uri(uri, workspace)}
        else:
            out[key] = _clean(child, workspace)
    return out


def is_test_path(uri: str) -> bool:
    """File di test dal percorso relativo: cartella di test, `test_*.py`, `*_test.py`, conftest."""
    *dirs, name = uri.casefold().split("/")
    return (
        not TEST_DIRS.isdisjoint(dirs)
        or name == "conftest.py"
        or name.startswith("test_")
        or name.endswith("_test.py")
    )


def _assert_in_test(result: dict[str, Any]) -> bool:
    if result.get("ruleId") != TEST_ONLY_SKIP:
        return False
    uris = [
        ((loc.get("physicalLocation") or {}).get("artifactLocation") or {}).get("uri")
        for loc in result.get("locations") or []
        if isinstance(loc, dict)
    ]
    return bool(uris) and all(isinstance(uri, str) and is_test_path(uri) for uri in uris)


def _contract_properties(result: dict[str, Any]) -> dict[str, Any]:
    severity = (result.get("properties") or {}).get("issue_severity")
    return {"tool_severity": severity} if isinstance(severity, str) and severity else {}


def through_symlink(workspace: str, relative: str) -> bool:
    """Un componente del percorso è un collegamento simbolico: l'host non lo legge (ADR-0004)."""
    current = Path(workspace)
    for part in relative.split("/"):
        current /= part
        if current.is_symlink():
            return True
    return False


def _reaches_a_link(result: dict[str, Any], workspace: str) -> bool:
    """Dopo `_clean`: l'`uri` è relativo, codificato come lo scrive bandit."""
    return any(
        through_symlink(workspace, unquote(uri))
        for loc in result.get("locations") or []
        if isinstance(loc, dict)
        and isinstance(
            uri := ((loc.get("physicalLocation") or {}).get("artifactLocation") or {}).get("uri"),
            str,
        )
    )


def adapt(raw: bytes, workspace: str = WORKSPACE) -> bytes:
    """SARIF di bandit -> SARIF del contratto, o `InvalidOutput`."""
    try:
        document = json.loads(raw)
    except (ValueError, RecursionError) as exc:
        raise InvalidOutput("non e' JSON") from exc
    if not isinstance(document, dict) or document.get("version") != "2.1.0":
        raise InvalidOutput("non e' SARIF 2.1.0")
    runs = document.get("runs")
    if not isinstance(runs, list) or len(runs) != 1 or not isinstance(runs[0], dict):
        raise InvalidOutput("atteso un solo run")
    run = runs[0]
    results = [r for r in run.get("results") or [] if isinstance(r, dict)]
    cleaned = [{**_clean(r, workspace), "properties": _contract_properties(r)} for r in results]
    rules = (run.get("tool") or {}).get("driver", {}).get("rules") or []
    clean = {
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "bandit",
                        "rules": [{"id": r["id"]} for r in rules if isinstance(r.get("id"), str)],
                    }
                },
                "results": [
                    r
                    for r in cleaned
                    if not _assert_in_test(r) and not _reaches_a_link(r, workspace)
                ],
            }
        ],
    }
    return json.dumps(clean, separators=(",", ":")).encode()


def run(
    *,
    bandit: str = BANDIT,
    workspace: str = WORKSPACE,
    out_file: str = OUT_FILE,
    tmp_dir: str = TMP_DIR,
) -> int:
    env = {"PATH": os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin"), "HOME": tmp_dir}
    raw_file, ini = Path(tmp_dir, "bandit.sarif"), Path(tmp_dir, "bandit.ini")
    raw_file.unlink(missing_ok=True)
    ini.write_text("[bandit]\n")  # config vuota: ignora `.bandit` e `pyproject.toml` del repository
    try:
        done = subprocess.run(  # noqa: S603 - argv a lista, binario fissato, nessuna shell
            [bandit, "-r", workspace, "-f", "sarif", "-o", str(raw_file), "--skip", SKIP]
            + ["--ini", str(ini), "--ignore-nosec", "-q"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            cwd=tmp_dir,
            env=env,
            check=False,
        )
        if done.returncode not in (0, 1):  # 1 = trovati problemi
            return EXIT_TOOL
        raw = raw_file.read_bytes()
    except OSError:
        return EXIT_TOOL
    try:
        adapted = adapt(raw, workspace)
    except InvalidOutput:
        return EXIT_INVALID
    Path(out_file).write_bytes(adapted)
    return 0


if __name__ == "__main__":
    sys.exit(run())
