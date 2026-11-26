"""Adattatore del plugin hadolint (P-04). Python standard: non importa `ca_core` (ADR-0007, 0026).

Gira nell'immagine con il profilo `hardened-container` (ADR-0004): `/workspace` in sola lettura,
`/out` scrivibile, `/tmp` tmpfs, nessuna rete. hadolint analizza solo i file che gli si passano:
l'adattatore elenca i Dockerfile del workspace (solo file regolari, mai collegamenti simbolici,
con tetti) e li passa in un'unica esecuzione.

La configurazione del repository non si applica mai (V-04, S-03):
- `.hadolint.yaml` si legge dalla cartella di lavoro: hadolint gira in una cartella vuota nel
  tmpfs, con l'ambiente ripulito (nessuna `HADOLINT_*`, `HOME` e `XDG_CONFIG_HOME` nel tmpfs);
- i commenti `# hadolint ignore=` e `# hadolint global ignore=` sono ignorati da
  `--disable-ignore-pragma` (provato il 2026-11-17 con hadolint 2.15.1).
Il repository può solo spegnere regole: `/inputs/config.json` con `{"disable_rules": [...]}`
(ADR-0014), passate con `--ignore`.

Il JSON nativo si converte in SARIF 2.1.0: regola, severità del motore, file, riga e colonna. Gli
errori di sintassi di un Dockerfile sono finding `DL1000`. Uscite: 0 ok; 3 hadolint fallito o senza
output; 4 `config.json` non valido; 5 output non conforme.
"""

import json
import os
import re
import stat
import subprocess
import sys
from pathlib import Path
from typing import Any
from urllib.parse import quote

HADOLINT = "/usr/local/bin/hadolint"
WORKSPACE = "/workspace"
OUT_FILE = "/out/results.sarif"
CONFIG_FILE = "/inputs/config.json"
TMP_DIR = "/tmp"  # noqa: S108 - tmpfs del profilo
EXIT_TOOL, EXIT_CONFIG, EXIT_INVALID = 3, 4, 5

RULE_ID = re.compile(r"^[A-Za-z0-9@][A-Za-z0-9_./@-]{0,127}$")
MAX_DISABLED = 500
MAX_MESSAGE = 1000
SKIP_DIRS = frozenset(
    {".git", "node_modules", ".venv", "venv", "__pycache__", "dist", "build", ".terraform"}
)
DOCKERFILE = re.compile(
    r"^(?:(?:dockerfile|containerfile)(?:\..+)?|.+\.(?:dockerfile|containerfile))$", re.I
)
MAX_FILES = 2000
MAX_FILE_BYTES = 1024 * 1024
# Severità del motore (error, warning, info, style) verso `tool_severity` (ADR-0026).
SEVERITY = {"error": "high", "warning": "medium", "info": "low", "style": "low"}


class InvalidOutput(ValueError):
    """L'output di hadolint non è il JSON atteso o ha percorsi fuori dal workspace."""


class InvalidConfig(ValueError):
    """`config.json` malformato o con un identificativo di regola non ammesso."""


def _uri(path: str) -> str:
    """Percorso codificato per l'`uri` del SARIF (ADR-0004): l'host rifiuta `?` e `#`, scambia
    `a:` per uno schema e decodifica `%XX`. `fsencode` conserva anche i nomi non UTF-8."""
    return quote(os.fsencode(path), safe="/")


def load_disabled(path: str = CONFIG_FILE) -> list[str]:
    try:
        raw = Path(path).read_bytes()
    except FileNotFoundError:
        return []
    except OSError as exc:
        raise InvalidConfig("config.json illeggibile") from exc
    try:
        document = json.loads(raw)
    except (ValueError, RecursionError) as exc:
        raise InvalidConfig("config.json non è JSON") from exc
    if not isinstance(document, dict) or set(document) - {"disable_rules"}:
        raise InvalidConfig("config.json: chiavi non ammesse")
    rules = document.get("disable_rules")
    if rules is None:
        return []
    if (
        not isinstance(rules, list)
        or len(rules) > MAX_DISABLED
        or not all(isinstance(r, str) and RULE_ID.fullmatch(r) for r in rules)
    ):
        raise InvalidConfig("config.json: disable_rules non valido")
    return sorted(set(rules))


def find_dockerfiles(workspace: str) -> list[str]:
    """Percorsi assoluti dei Dockerfile: file regolari, senza collegamenti, con tetti."""
    found: list[str] = []
    for current, dirs, files in os.walk(workspace, followlinks=False):
        dirs[:] = sorted(d for d in dirs if d not in SKIP_DIRS)
        for name in sorted(files):
            if not DOCKERFILE.match(name):
                continue
            path = os.path.join(current, name)
            try:
                info = os.lstat(path)
            except OSError:
                continue
            if stat.S_ISREG(info.st_mode) and info.st_size <= MAX_FILE_BYTES:
                found.append(path)
    return found[:MAX_FILES]


def _relative(file_path: str, workspace: str) -> str:
    if not file_path.startswith(workspace + "/"):
        raise InvalidOutput("percorso fuori dal workspace")
    path = file_path[len(workspace) + 1 :]
    if any(p in ("", ".", "..") for p in path.split("/")) or "\x00" in path:
        raise InvalidOutput("percorso non valido")
    return path


def _int(value: Any) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) and value >= 1 else None


def adapt(raw: bytes, workspace: str = WORKSPACE) -> bytes:
    """JSON nativo di hadolint -> SARIF del contratto, o `InvalidOutput`."""
    try:
        document = json.loads(raw)
    except (ValueError, RecursionError) as exc:
        raise InvalidOutput("non è JSON") from exc
    if not isinstance(document, list):
        raise InvalidOutput("atteso un elenco")
    results: list[dict[str, Any]] = []
    for item in document:
        if not isinstance(item, dict):
            raise InvalidOutput("voce non valida")
        code, file_path = item.get("code"), item.get("file")
        if not isinstance(code, str) or not code or not isinstance(file_path, str):
            raise InvalidOutput("voce senza codice o file")
        text = item.get("message")
        text = text[:MAX_MESSAGE] if isinstance(text, str) and text else code
        region = {
            key: value
            for key, value in (
                ("startLine", _int(item.get("line"))),
                ("startColumn", _int(item.get("column"))),
            )
            if value is not None
        }
        physical: dict[str, Any] = {
            "artifactLocation": {"uri": _uri(_relative(file_path, workspace))}
        }
        if region:
            physical["region"] = region
        severity = SEVERITY.get(str(item.get("level")), "low")
        results.append(
            {
                "ruleId": code,
                "message": {"text": text},
                "locations": [{"physicalLocation": physical}],
                "properties": {"tool_severity": severity},
            }
        )
    results.sort(key=lambda r: json.dumps([r["locations"], r["ruleId"]]))
    rules = sorted({r["ruleId"] for r in results})
    clean = {
        "version": "2.1.0",
        "runs": [
            {
                "tool": {"driver": {"name": "hadolint", "rules": [{"id": r} for r in rules]}},
                "results": results,
            }
        ],
    }
    return json.dumps(clean, separators=(",", ":")).encode()


def command(hadolint: str, files: list[str], disabled: list[str]) -> list[str]:
    args = [hadolint, "--no-fail", "--disable-ignore-pragma", "--no-color", "-f", "json"]
    for rule in disabled:
        args += ["--ignore", rule]
    return [*args, *files]


def run(
    *,
    hadolint: str = HADOLINT,
    workspace: str = WORKSPACE,
    out_file: str = OUT_FILE,
    config_file: str = CONFIG_FILE,
    tmp_dir: str = TMP_DIR,
) -> int:
    try:
        disabled = load_disabled(config_file)
    except InvalidConfig:
        return EXIT_CONFIG
    files = find_dockerfiles(workspace)
    if not files:
        Path(out_file).write_bytes(adapt(b"[]", workspace))
        return 0
    # Ambiente ripulito: nessuna `HADOLINT_*`, nessuna configurazione dell'utente.
    env = {"PATH": "/usr/local/bin:/usr/bin:/bin", "HOME": tmp_dir, "XDG_CONFIG_HOME": tmp_dir}
    clean_dir = Path(tmp_dir, "hadolint-cwd")
    clean_dir.mkdir(exist_ok=True)
    try:
        done = subprocess.run(  # noqa: S603 - argv a lista, binario fissato, nessuna shell
            command(hadolint, files, disabled),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            cwd=clean_dir,  # `.hadolint.yaml` si legge da qui: cartella vuota
            env=env,
            check=False,
        )
    except OSError:
        return EXIT_TOOL
    if done.returncode != 0 or not done.stdout.strip():
        return EXIT_TOOL
    try:
        adapted = adapt(done.stdout, workspace)
    except InvalidOutput:
        return EXIT_INVALID
    Path(out_file).write_bytes(adapted)
    return 0


if __name__ == "__main__":
    sys.exit(run())
