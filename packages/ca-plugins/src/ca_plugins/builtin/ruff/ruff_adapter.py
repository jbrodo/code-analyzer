"""Adattatore del plugin ruff (P-01). Python standard: non importa `ca_core` (ADR-0007, 0026).

Gira nell'immagine con il profilo `hardened-container` (ADR-0004): `/workspace` in sola lettura,
`/out` scrivibile, `/tmp` tmpfs, nessuna rete. Esegue ruff con regole e soglie dell'immagine e
riscrive il SARIF nel contratto di ADR-0007: `uri` relativi alla radice del workspace senza
`uriBaseId`, nessun testo dei file (`fixes` si scarta), `properties` ridotte a `tool_severity`
da una tabella per regola (ruff dà `error` a tutto, V-03) e `metric` per le regole di complessità
e dimensione, estratta dal messaggio (ADR-0026).

La configurazione del repository non si legge mai: `--isolated` ignora `ruff.toml` e
`pyproject.toml`, `--no-respect-gitignore` impedisce di nascondere file, `--ignore-noqa` ignora
i commenti di soppressione, anche `# ruff: noqa` a livello di file (provato in S-03, ADR-0012).
Il repository può solo spegnere regole: `/inputs/config.json` con `{"disable_rules": [...]}`,
ricontrollato qui (ADR-0014). Nessuna scrittura nel workspace: `--no-cache`.

Uscite: 0 ok; 3 ruff fallito o senza output; 4 `config.json` non valido; 5 SARIF non conforme.
"""

import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

RUFF = "/opt/venv/bin/ruff"
WORKSPACE = "/workspace"
OUT_FILE = "/out/results.sarif"
CONFIG_FILE = "/inputs/config.json"
TMP_DIR = "/tmp"  # noqa: S108 - tmpfs del profilo
EXIT_TOOL, EXIT_CONFIG, EXIT_INVALID = 3, 4, 5

# Regole dell'immagine (ADR-0026): errori probabili e manutenibilità misurabile. Fuori stile,
# formattazione e le regole di sicurezza, che ripetono quelle di bandit.
SELECT = "F,B,C901,PLR0911,PLR0912,PLR0913,PLR0915"
# Soglie dell'immagine. Quando esisterà la configurazione di scoring (C-03) le passerà l'host in
# `config.json`; fino ad allora sono quelle predefinite di ruff, scritte qui per non dipendere da
# un cambio di valore del motore.
THRESHOLDS = (
    "lint.mccabe.max-complexity=10",
    "lint.pylint.max-returns=6",
    "lint.pylint.max-branches=12",
    "lint.pylint.max-args=5",
    "lint.pylint.max-statements=50",
)
RULE_ID = re.compile(r"^[A-Za-z0-9@][A-Za-z0-9_./@-]{0,127}$")
MAX_DISABLED = 500
MAX_MESSAGE = 1000

# Un'espressione per regola (V-03, ADR-0026): valore misurato e soglia superata.
METRICS = {
    "C901": re.compile(r"^`.+` is too complex \((\d+) > (\d+)\)$"),
    "PLR0911": re.compile(r"^Too many return statements \((\d+) > (\d+)\)$"),
    "PLR0912": re.compile(r"^Too many branches \((\d+) > (\d+)\)$"),
    "PLR0913": re.compile(r"^Too many arguments in function definition \((\d+) > (\d+)\)$"),
    "PLR0915": re.compile(r"^Too many statements \((\d+) > (\d+)\)$"),
}

# Severità per regola (ruff dà `error` a tutto). Prefissi, dal più specifico. Senza voce: `low`.
SEVERITY_EXACT = {
    "invalid-syntax": "high",
    "F821": "high",  # nome non definito
    "F822": "high",
    "F823": "high",
    "F811": "medium",  # ridefinizione non usata
    "F632": "medium",  # `is` con un letterale
    "F601": "medium",
    "F602": "medium",
}
SEVERITY_PREFIX = (
    ("PLR", "medium"),
    ("C901", "medium"),
    ("B0", "medium"),  # bugbear: errori probabili
    ("F5", "medium"),  # stringhe di formato
    ("F6", "medium"),
    ("F7", "medium"),
    ("F4", "low"),
    ("F8", "low"),
    ("F", "low"),
)


class InvalidOutput(ValueError):
    """L'output di ruff non è un SARIF 2.1.0 con percorsi relativi."""


class InvalidConfig(ValueError):
    """`config.json` malformato o con un identificativo di regola non ammesso."""


def severity_of(rule_id: str) -> str:
    if rule_id in SEVERITY_EXACT:
        return SEVERITY_EXACT[rule_id]
    return next((sev for prefix, sev in SEVERITY_PREFIX if rule_id.startswith(prefix)), "low")


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
    rules = document.get("disable_rules") if isinstance(document, dict) else None
    if not isinstance(document, dict) or set(document) - {"disable_rules"}:
        raise InvalidConfig("config.json: chiavi non ammesse")
    if rules is None:
        return []
    if (
        not isinstance(rules, list)
        or len(rules) > MAX_DISABLED
        or not all(isinstance(r, str) and RULE_ID.fullmatch(r) for r in rules)
    ):
        raise InvalidConfig("config.json: disable_rules non valido")
    return sorted(set(rules))


def _relative_uri(uri: str, workspace: str) -> str:
    path = uri.removeprefix("file://")
    if path == workspace:
        return "."
    if not path.startswith(workspace + "/"):
        raise InvalidOutput("uri fuori dal workspace")
    return path[len(workspace) + 1 :]


def _location(location: Any, workspace: str) -> dict[str, Any]:
    physical = (location or {}).get("physicalLocation") if isinstance(location, dict) else None
    if not isinstance(physical, dict):
        raise InvalidOutput("risultato senza posizione")
    artifact = physical.get("artifactLocation")
    uri = artifact.get("uri") if isinstance(artifact, dict) else None
    if not isinstance(uri, str):
        raise InvalidOutput("artifactLocation senza uri")
    region = physical.get("region") if isinstance(physical.get("region"), dict) else {}
    keep = {
        k: region[k]
        for k in ("startLine", "startColumn", "endLine", "endColumn")
        if isinstance(region.get(k), int) and not isinstance(region.get(k), bool)
    }
    out: dict[str, Any] = {"artifactLocation": {"uri": _relative_uri(uri, workspace)}}
    if keep:
        out["region"] = keep
    return {"physicalLocation": out}


def _result(raw: dict[str, Any], workspace: str) -> dict[str, Any]:
    rule_id = raw.get("ruleId")
    if not isinstance(rule_id, str) or not rule_id:
        raise InvalidOutput("risultato senza ruleId")
    text = (raw.get("message") or {}).get("text")
    text = text[:MAX_MESSAGE] if isinstance(text, str) and text else rule_id
    properties: dict[str, Any] = {"tool_severity": severity_of(rule_id)}
    pattern = METRICS.get(rule_id)
    match = pattern.fullmatch(text) if pattern else None
    if match:
        properties["metric"] = {"value": int(match[1]), "threshold": int(match[2])}
    locations = raw.get("locations")
    if not isinstance(locations, list) or not locations:
        raise InvalidOutput("risultato senza posizione")
    return {
        "ruleId": rule_id,
        "message": {"text": text},
        "locations": [_location(locations[0], workspace)],
        "properties": properties,
    }


def adapt(raw: bytes, workspace: str = WORKSPACE) -> bytes:
    """SARIF di ruff -> SARIF del contratto, o `InvalidOutput`."""
    try:
        document = json.loads(raw)
    except (ValueError, RecursionError) as exc:
        raise InvalidOutput("non è JSON") from exc
    if not isinstance(document, dict) or document.get("version") != "2.1.0":
        raise InvalidOutput("non è SARIF 2.1.0")
    runs = document.get("runs")
    if not isinstance(runs, list) or len(runs) != 1 or not isinstance(runs[0], dict):
        raise InvalidOutput("atteso un solo run")
    results = [_result(r, workspace) for r in runs[0].get("results") or [] if isinstance(r, dict)]
    rules = sorted({r["ruleId"] for r in results})
    clean = {
        "version": "2.1.0",
        "runs": [
            {
                "tool": {"driver": {"name": "ruff", "rules": [{"id": r} for r in rules]}},
                "results": results,
            }
        ],
    }
    return json.dumps(clean, separators=(",", ":")).encode()


def command(ruff: str, workspace: str, disabled: list[str]) -> list[str]:
    args = [ruff, "check", "--isolated", "--no-cache", "--no-respect-gitignore", "--ignore-noqa"]
    args += ["--select", SELECT, "--output-format", "sarif", "--exit-zero"]
    for threshold in THRESHOLDS:
        args += ["--config", threshold]
    if disabled:
        args += ["--ignore", ",".join(disabled)]
    return args + [workspace]


def run(
    *,
    ruff: str = RUFF,
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
            command(ruff, workspace, disabled),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            cwd=tmp_dir,  # fuori dal workspace: nessuna ricerca di configurazione
            env=env,
            check=False,
        )
    except OSError:
        return EXIT_TOOL
    if done.returncode != 0 or not done.stdout:  # con --exit-zero solo un errore vero è != 0
        return EXIT_TOOL
    try:
        adapted = adapt(done.stdout, workspace)
    except InvalidOutput:
        return EXIT_INVALID
    Path(out_file).write_bytes(adapted)
    return 0


if __name__ == "__main__":
    sys.exit(run())
