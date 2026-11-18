"""Adattatore del plugin semgrep (P-10). Python standard: non importa `ca_core` (ADR-0007).

Gira nell'immagine con il profilo `hardened-container` (ADR-0004): `/workspace` in sola lettura,
`/out` scrivibile, `/tmp` tmpfs, nessuna rete. Esegue semgrep con le sole regole in
`/opt/ca-plugin/rules` (ADR-0015) piu' quelle indicate in `plugins.semgrep.rules`, che l'host passa
in `/inputs/config.json` come `{"rules": ["percorso/relativo", ...]}` e che qui si ricontrollano per
contenimento nel workspace. Mai `--config auto` ne registry, mai metriche.

Le regole del repository girano in un'esecuzione separata: nella stessa, una regola con lo stesso
`id` sovrascriverebbe quella integrata (N-26). Un `id` uguale a uno integrato fa fallire il plugin.

Il repository e' un dato non fidato: `--no-git-ignore` evita che semgrep esegua `git` (una
`.git/config` ostile puo' lanciare un comando con `core.fsmonitor`), e
`--x-ignore-semgrepignore-files` ignora il `.semgrepignore` del repository e quello predefinito, che
esclude `tests/`. Il SARIF e' riscritto nel contratto di ADR-0007: `uri` relativi senza
`uriBaseId`, nessuno `snippet`, `ruleId` uguale all'`id` della regola (`--no-rewrite-rule-ids`) e
`message.text` preso dal testo della regola e non dal risultato, perche' una regola indicata dal
repository puo' interpolare metavariabili e quindi il codice trovato. `tool_severity` viene da
`defaultConfiguration.level` della regola.

Uscite: 0 ok; 3 semgrep fallito o senza output; 4 `config.json` o regola indicata non ammessi;
5 SARIF non conforme (non JSON, non 2.1.0, `uri` fuori dal workspace).
"""

import json
import math
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

SEMGREP = "/opt/venv/bin/semgrep"
RULES = "/opt/ca-plugin/rules"
WORKSPACE = "/workspace"
CONFIG_FILE = "/inputs/config.json"
OUT_FILE = "/out/results.sarif"
TMP_DIR = "/tmp"  # noqa: S108 - tmpfs del profilo
CGROUP_CPU_MAX = "/sys/fs/cgroup/cpu.max"
MAX_CONFIG_BYTES = 65536
MAX_USER_RULES = 50
EXIT_TOOL, EXIT_CONFIG, EXIT_INVALID = 3, 4, 5


class InvalidOutput(ValueError):
    """L'output di semgrep non e' un SARIF 2.1.0 con percorsi relativi."""


class InvalidConfig(ValueError):
    """`config.json` malformato o una regola indicata esce dal workspace."""


def user_rules(config_file: str, workspace: str) -> list[str]:
    """Percorsi assoluti delle regole del repository, o `InvalidConfig`. Assente = nessuna."""
    path = Path(config_file)
    if not path.exists():
        return []
    try:
        with path.open("rb") as handle:
            data = json.loads(handle.read(MAX_CONFIG_BYTES + 1)[:MAX_CONFIG_BYTES])
    except (OSError, ValueError, RecursionError) as exc:
        raise InvalidConfig("config.json illeggibile") from exc
    names = data.get("rules") if isinstance(data, dict) else None
    if not isinstance(names, list) or len(names) > MAX_USER_RULES:
        raise InvalidConfig("`rules` non e' un elenco ammesso")
    root = os.path.realpath(workspace)
    found: list[str] = []
    for name in names:
        if not isinstance(name, str) or not name or "\x00" in name or os.path.isabs(name):
            raise InvalidConfig("percorso di regola non ammesso")
        real = os.path.realpath(os.path.join(root, name))
        if os.path.commonpath([root, real]) != root or real == root or not os.path.exists(real):
            raise InvalidConfig("regola fuori dal workspace o inesistente")
        found.append(real)  # i symlink sono gia' risolti: il controllo vale per la destinazione
    return found


def jobs(cpu_max: str = CGROUP_CPU_MAX) -> int:
    """CPU concesse al container (`--cpus`): semgrep ne vedrebbe tutte quelle dell'host."""
    try:
        quota, period = Path(cpu_max).read_text().split()[:2]
        return max(1, math.ceil(int(quota) / int(period)))
    except (OSError, ValueError):
        return 1


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


def taint_rule_ids(rules_dir: str = RULES) -> frozenset[str]:
    """Identificativi delle regole `mode: taint` del prodotto, dai file che l'immagine porta.

    Solo le regole del prodotto: un risultato di una regola del repository analizzato non è mai
    «percorso confermato». Lettura per righe, senza un parser YAML (l'adattatore usa il Python
    dell'immagine): `- id: x` apre una regola, `mode: taint` la marca.
    """
    found: set[str] = set()
    for path in sorted(Path(rules_dir).glob("*.yaml")):
        current: str | None = None
        for line in path.read_text(encoding="utf-8").splitlines():
            stripped = line.strip()
            if stripped.startswith("- id:"):
                current = stripped.removeprefix("- id:").strip()
            elif stripped == "mode: taint" and current:
                found.add(current)
    return frozenset(found)


def _rule_text(rule: dict[str, Any]) -> str | None:
    text = (rule.get("fullDescription") or {}).get("text")
    return text if isinstance(text, str) and text else None


def adapt(raw: bytes, workspace: str = WORKSPACE, taint: frozenset[str] = frozenset()) -> bytes:
    """SARIF di semgrep -> SARIF del contratto, o `InvalidOutput`.

    `taint`: gli identificativi delle regole di flusso dei dati del prodotto; i loro risultati
    portano `properties.taint`."""
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
    rules = {
        r["id"]: r
        for r in (run.get("tool") or {}).get("driver", {}).get("rules") or []
        if isinstance(r, dict) and isinstance(r.get("id"), str)
    }
    results = []
    for result in run.get("results") or []:
        if not isinstance(result, dict):
            raise InvalidOutput("risultato non valido")
        rule = rules.get(result.get("ruleId"), {})
        clean = _clean(result, workspace)
        clean.pop("fingerprints", None)
        text = _rule_text(rule)
        clean["message"] = {"text": text or str(result.get("ruleId"))}
        level = (rule.get("defaultConfiguration") or {}).get("level")
        clean["properties"] = {"tool_severity": level} if isinstance(level, str) and level else {}
        if result.get("ruleId") in taint:
            clean["properties"]["taint"] = True
        results.append(clean)
    adapted = {
        "version": "2.1.0",
        "runs": [
            {
                "tool": {"driver": {"name": "semgrep", "rules": [{"id": i} for i in rules]}},
                "results": results,
            }
        ],
    }
    return json.dumps(adapted, separators=(",", ":")).encode()


def merge(builtin: bytes, repository: bytes) -> bytes:
    """Un solo run con i risultati delle due esecuzioni, o `InvalidConfig` se un `id` coincide."""
    base, extra = json.loads(builtin), json.loads(repository)
    base_run, extra_run = base["runs"][0], extra["runs"][0]
    base_rules, extra_rules = (
        base_run["tool"]["driver"]["rules"],
        extra_run["tool"]["driver"]["rules"],
    )
    if {r["id"] for r in base_rules} & {r["id"] for r in extra_rules}:
        raise InvalidConfig("una regola del repository ha lo stesso id di una integrata")
    base_rules.extend(extra_rules)
    base_run["results"].extend(extra_run["results"])
    return json.dumps(base, separators=(",", ":")).encode()


def command(semgrep: str, rules: list[str], workspace: str, raw_file: str, njobs: int) -> list[str]:
    configs = [arg for path in rules for arg in ("--config", path)]
    return [
        semgrep, "scan", *configs,
        "--metrics=off", "--disable-version-check", "--quiet",
        "--disable-nosem", "--max-target-bytes=0", "--timeout=0",
        "--no-git-ignore", "--x-ignore-semgrepignore-files", "--no-rewrite-rule-ids",
        "--sarif", f"--sarif-output={raw_file}", f"--jobs={njobs}",
        workspace,
    ]  # fmt: skip


def run(
    *,
    semgrep: str = SEMGREP,
    workspace: str = WORKSPACE,
    config_file: str = CONFIG_FILE,
    out_file: str = OUT_FILE,
    tmp_dir: str = TMP_DIR,
    njobs: int | None = None,
) -> int:
    try:
        rules = user_rules(config_file, workspace)
    except InvalidConfig:
        return EXIT_CONFIG
    env = {
        "PATH": os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin"),
        "HOME": tmp_dir,
        "SEMGREP_SEND_METRICS": "off",
        "SEMGREP_ENABLE_VERSION_CHECK": "0",
    }
    outputs = []
    for configs in ([RULES], rules) if rules else ([RULES],):
        raw_file = Path(tmp_dir, "semgrep.sarif")
        raw_file.unlink(missing_ok=True)
        try:
            done = subprocess.run(  # noqa: S603 - argv a lista, binario fissato, nessuna shell
                command(semgrep, configs, workspace, str(raw_file), njobs or jobs()),
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                cwd=tmp_dir,
                env=env,
                check=False,
            )
            if done.returncode != 0:
                return EXIT_TOOL
            outputs.append(raw_file.read_bytes())
        except OSError:
            return EXIT_TOOL
    try:
        adapted = adapt(outputs[0], workspace, taint_rule_ids())
        if rules:
            adapted = merge(adapted, adapt(outputs[1], workspace))
    except InvalidOutput:
        return EXIT_INVALID
    except InvalidConfig:
        return EXIT_CONFIG
    Path(out_file).write_bytes(adapted)
    return 0


if __name__ == "__main__":
    sys.exit(run())
