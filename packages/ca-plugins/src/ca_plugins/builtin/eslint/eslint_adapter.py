"""Adattatore del plugin eslint (P-02). Python standard: non importa `ca_core` (ADR-0007, 0026).

Gira nell'immagine con il profilo `hardened-container` (ADR-0004): `/workspace` in sola lettura,
`/out` scrivibile, `/tmp` tmpfs, nessuna rete. Esegue eslint (Node) con la configurazione
dell'immagine e converte il suo JSON nativo in SARIF 2.1.0: il formattatore SARIF esterno non si
usa (V-08). Il JSON di eslint contiene il testo intero dei file con messaggi (`source`) e i
suggerimenti di correzione: l'adattatore tiene solo regola, severità, posizione e messaggio.

La configurazione del repository non si esegue né si legge: `--no-config-lookup -c <immagine>`
(`eslint.config.js` è codice). `--no-inline-config` ignora `/* eslint-disable */` (ADR-0012). I
plugin e il parser si risolvono dalla cartella dell'immagine, mai da `node_modules` del
workspace. Il repository può solo spegnere regole: `/inputs/config.json` con
`{"disable_rules": [...]}`, ricontrollato qui (ADR-0014); le regole spente si passano con
`--rule 'nome: off'`.

Uscite: 0 ok; 3 eslint fallito o senza output; 4 `config.json` non valido; 5 output non conforme.
"""

import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

NODE = "/usr/local/bin/node"
ESLINT = "/opt/ca-plugin/node_modules/eslint/bin/eslint.js"
ESLINT_CONFIG = "/opt/ca-plugin/eslint.config.mjs"
WORKSPACE = "/workspace"
OUT_FILE = "/out/results.sarif"
CONFIG_FILE = "/inputs/config.json"
TMP_DIR = "/tmp"  # noqa: S108 - tmpfs del profilo
EXIT_TOOL, EXIT_CONFIG, EXIT_INVALID = 3, 4, 5

RULE_ID = re.compile(r"^[A-Za-z0-9@][A-Za-z0-9_./@-]{0,127}$")
MAX_DISABLED = 500
MAX_MESSAGE = 1000
PARSE_ERROR = "parse-error"  # `ruleId` nullo in eslint: errore di sintassi del file

# Un'espressione per regola (V-03, ADR-0026): valore misurato e soglia superata.
METRICS = {
    "complexity": re.compile(r"^.+ has a complexity of (\d+)\. Maximum allowed is (\d+)\.$"),
    "max-depth": re.compile(
        r"^Blocks are nested too deeply \((\d+)\)\. Maximum allowed is (\d+)\.$"
    ),
    "max-lines-per-function": re.compile(
        r"^.+ has too many lines \((\d+)\)\. Maximum allowed is (\d+)\.$"
    ),
    "max-params": re.compile(
        r"^.+ has too many parameters \((\d+)\)\. Maximum allowed is (\d+)\.$"
    ),
}


class InvalidOutput(ValueError):
    """L'output di eslint non è il JSON atteso o ha percorsi fuori dal workspace."""


class InvalidConfig(ValueError):
    """`config.json` malformato o con un identificativo di regola non ammesso."""


def load_disabled(path: str = CONFIG_FILE) -> list[str]:
    """Regole da spegnere. File assente = nessuna; file presente ma non valido = errore."""
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


def _relative(file_path: str, workspace: str) -> str:
    if file_path == workspace or not file_path.startswith(workspace + "/"):
        raise InvalidOutput("percorso fuori dal workspace")
    return file_path[len(workspace) + 1 :]


def _int(value: Any) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) and value >= 1 else None


def _result(entry_uri: str, message: dict[str, Any]) -> dict[str, Any]:
    rule_id = message.get("ruleId")
    if rule_id is None:  # errore di sintassi (`fatal`)
        rule_id = PARSE_ERROR
    if not isinstance(rule_id, str) or not rule_id:
        raise InvalidOutput("messaggio senza regola")
    text = message.get("message")
    text = text[:MAX_MESSAGE] if isinstance(text, str) and text else rule_id
    fatal = message.get("fatal") is True
    # Severità scelta dalla nostra configurazione: 2 errore, 1 avviso (ADR-0026).
    severity = "high" if fatal else "medium" if message.get("severity") == 2 else "low"
    properties: dict[str, Any] = {"tool_severity": severity}
    pattern = METRICS.get(rule_id)
    match = pattern.fullmatch(text) if pattern else None
    if match:
        properties["metric"] = {"value": int(match[1]), "threshold": int(match[2])}
    region = {
        key: value
        for key, value in (
            ("startLine", _int(message.get("line"))),
            ("startColumn", _int(message.get("column"))),
            ("endLine", _int(message.get("endLine"))),
            ("endColumn", _int(message.get("endColumn"))),
        )
        if value is not None
    }
    physical: dict[str, Any] = {"artifactLocation": {"uri": entry_uri}}
    if region:
        physical["region"] = region
    return {
        "ruleId": rule_id,
        "message": {"text": text},
        "locations": [{"physicalLocation": physical}],
        "properties": properties,
    }


def adapt(raw: bytes, workspace: str = WORKSPACE) -> bytes:
    """JSON nativo di eslint -> SARIF del contratto, o `InvalidOutput`."""
    try:
        document = json.loads(raw)
    except (ValueError, RecursionError) as exc:
        raise InvalidOutput("non è JSON") from exc
    if not isinstance(document, list):
        raise InvalidOutput("atteso un elenco di file")
    results: list[dict[str, Any]] = []
    for entry in document:
        if not isinstance(entry, dict) or not isinstance(entry.get("filePath"), str):
            raise InvalidOutput("voce senza filePath")
        messages = entry.get("messages")
        if not isinstance(messages, list):
            raise InvalidOutput("voce senza messages")
        if not messages:
            continue
        uri = _relative(entry["filePath"], workspace)
        results += [_result(uri, m) for m in messages if isinstance(m, dict)]
    rules = sorted({r["ruleId"] for r in results})
    clean = {
        "version": "2.1.0",
        "runs": [
            {
                "tool": {"driver": {"name": "eslint", "rules": [{"id": r} for r in rules]}},
                "results": results,
            }
        ],
    }
    return json.dumps(clean, separators=(",", ":")).encode()


def command(node: str, eslint: str, config: str, disabled: list[str]) -> list[str]:
    args = [node, eslint, "--no-config-lookup", "-c", config, "--no-inline-config"]
    args += ["--no-warn-ignored", "-f", "json"]
    for rule in disabled:
        args += ["--rule", f"{rule}: off"]
    return [*args, "."]


def run(
    *,
    node: str = NODE,
    eslint: str = ESLINT,
    eslint_config: str = ESLINT_CONFIG,
    workspace: str = WORKSPACE,
    out_file: str = OUT_FILE,
    config_file: str = CONFIG_FILE,
    tmp_dir: str = TMP_DIR,
) -> int:
    try:
        disabled = load_disabled(config_file)
    except InvalidConfig:
        return EXIT_CONFIG
    env = {"PATH": os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin"), "HOME": tmp_dir}
    try:
        done = subprocess.run(  # noqa: S603 - argv a lista, binario fissato, nessuna shell
            command(node, eslint, eslint_config, disabled),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            cwd=workspace,  # i file si cercano rispetto alla cartella di lavoro (V-04)
            env=env,
            check=False,
        )
    except OSError:
        return EXIT_TOOL
    if done.returncode not in (0, 1) or not done.stdout:  # 1 = trovati problemi
        return EXIT_TOOL
    try:
        adapted = adapt(done.stdout, workspace)
    except InvalidOutput:
        return EXIT_INVALID
    Path(out_file).write_bytes(adapted)
    return 0


if __name__ == "__main__":
    sys.exit(run())
