"""Adattatore del plugin checkov (P-03). Python standard: non importa `ca_core` (ADR-0007, 0026).

Gira nell'immagine con il profilo `hardened-container` (ADR-0004): `/workspace` in sola lettura,
`/out` scrivibile, `/tmp` tmpfs, nessuna rete. checkov legge `.checkov.yaml` del repository anche
con `--config-file` su un altro file (V-04), quindi non gira sul workspace: l'adattatore copia nel
tmpfs i soli file che interessano (Dockerfile, Terraform, YAML) senza i nomi dei file di
configurazione di checkov, e lo esegue sulla copia. La copia conserva la struttura, così i
riferimenti tra file Terraform si risolvono. Solo file regolari, mai collegamenti simbolici,
con tetti su numero e dimensione. Soppressioni in linea (`#checkov:skip`): i controlli saltati
tornano finding (ADR-0026). Frammenti di codice e nomi delle risorse non escono: dal JSON nativo
si tengono controllo, nome del controllo, file e intervallo di righe.

Nessuna chiamata di rete: `--skip-download`; i moduli remoti non si scaricano. Il repository può
solo spegnere controlli: `/inputs/config.json` con `{"disable_rules": [...]}` (ADR-0014).

Uscite: 0 ok; 3 checkov fallito o senza output; 4 `config.json` non valido; 5 output non conforme.
"""

import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

CHECKOV = "/opt/venv/bin/checkov"
WORKSPACE = "/workspace"
OUT_FILE = "/out/results.sarif"
CONFIG_FILE = "/inputs/config.json"
TMP_DIR = "/tmp"  # noqa: S108 - tmpfs del profilo
EXIT_TOOL, EXIT_CONFIG, EXIT_INVALID = 3, 4, 5

FRAMEWORKS = ("dockerfile", "kubernetes", "terraform")
RULE_ID = re.compile(r"^[A-Za-z0-9@][A-Za-z0-9_./@-]{0,127}$")
MAX_DISABLED = 500
MAX_MESSAGE = 1000

# Copia di lavoro: solo ciò che i tre framework leggono.
SKIP_DIRS = frozenset(
    {".git", "node_modules", ".venv", "venv", "__pycache__", "dist", "build", ".terraform"}
)
CONFIG_NAMES = frozenset(
    {".checkov.yaml", ".checkov.yml", ".checkov.baseline", ".checkov_config.yaml"}
)
CONFIG_DIRS = frozenset({".checkov"})
SUFFIXES = (".tf", ".tfvars", ".yaml", ".yml", ".dockerfile")
DOCKERFILE = re.compile(r"^(?:dockerfile|containerfile)(?:\..+)?$", re.IGNORECASE)
MAX_FILES = 5000
MAX_FILE_BYTES = 2 * 1024 * 1024
MAX_TOTAL_BYTES = 64 * 1024 * 1024

# Severità per controllo, dove la conosciamo: checkov non la dà senza la sua piattaforma (V-03).
# Senza voce il campo manca e vale il livello predefinito di `iac` (ADR-0009). Mai `error`.
SEVERITY = {
    "CKV_K8S_16": "high",  # container privilegiato
    "CKV_K8S_20": "high",  # escalation dei privilegi
    "CKV_K8S_23": "medium",
    "CKV_K8S_14": "medium",  # tag `latest`
    "CKV_DOCKER_3": "medium",  # nessun utente non root
    "CKV_DOCKER_7": "medium",  # immagine con tag `latest`
    "CKV2_DOCKER_1": "high",  # sudo
    "CKV_AWS_24": "high",  # SSH aperto a tutti
    "CKV_AWS_25": "high",  # RDP aperto a tutti
    "CKV_AWS_260": "high",
    "CKV2_AWS_6": "high",  # bucket senza blocco dell'accesso pubblico
    "CKV_AWS_18": "low",
    "CKV_AWS_21": "low",
}


class InvalidOutput(ValueError):
    """L'output di checkov non è il JSON atteso."""


class InvalidConfig(ValueError):
    """`config.json` malformato o con un identificativo di regola non ammesso."""


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


def wanted(name: str) -> bool:
    lowered = name.lower()
    if name in CONFIG_NAMES:
        return False
    return DOCKERFILE.match(name) is not None or lowered.endswith(SUFFIXES)


def stage(workspace: str, dest: str) -> tuple[int, int]:
    """Copia i file utili in `dest`. Restituisce (copiati, saltati per tetto)."""
    copied = skipped = total = 0
    root = Path(workspace)
    for current, dirs, files in os.walk(root, followlinks=False):
        dirs[:] = sorted(d for d in dirs if d not in SKIP_DIRS and d not in CONFIG_DIRS)
        for name in sorted(files):
            if not wanted(name):
                continue
            source = Path(current, name)
            try:
                info = source.lstat()
            except OSError:
                skipped += 1
                continue
            if not stat.S_ISREG(info.st_mode):  # collegamenti simbolici, FIFO, dispositivi
                skipped += 1
                continue
            if (
                info.st_size > MAX_FILE_BYTES
                or copied >= MAX_FILES
                or total + info.st_size > MAX_TOTAL_BYTES
            ):
                skipped += 1
                continue
            target = Path(dest, source.relative_to(root))
            try:
                fd = os.open(source, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            except OSError:
                skipped += 1
                continue
            with os.fdopen(fd, "rb") as handle:
                data = handle.read(MAX_FILE_BYTES + 1)
            if len(data) > MAX_FILE_BYTES:
                skipped += 1
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
            copied += 1
            total += len(data)
    return copied, skipped


def _reports(document: Any) -> list[dict[str, Any]]:
    items = document if isinstance(document, list) else [document]
    if not all(isinstance(i, dict) for i in items):
        raise InvalidOutput("report non valido")
    return items


def _relative(file_path: str) -> str:
    """`/k8s/pod.yaml` (radice della copia) -> `k8s/pod.yaml`; nulla che esca dalla radice."""
    path = file_path.removeprefix("/")
    parts = path.split("/")
    if (
        not file_path.startswith("/")
        or not path
        or "\x00" in path
        or any(p in ("", ".", "..") for p in parts)
    ):
        raise InvalidOutput("percorso non valido")
    return path


def _range(value: Any) -> dict[str, int]:
    if (
        isinstance(value, list)
        and len(value) == 2
        and all(isinstance(v, int) and not isinstance(v, bool) and v >= 1 for v in value)
    ):
        return {"startLine": value[0], "endLine": max(value)}
    return {}


def _result(check: Any) -> dict[str, Any]:
    if not isinstance(check, dict):
        raise InvalidOutput("controllo non valido")
    rule_id, file_path = check.get("check_id"), check.get("file_path")
    if not isinstance(rule_id, str) or not rule_id or not isinstance(file_path, str):
        raise InvalidOutput("controllo senza id o file")
    name = check.get("check_name")
    text = name[:MAX_MESSAGE] if isinstance(name, str) and name else rule_id
    physical: dict[str, Any] = {"artifactLocation": {"uri": _relative(file_path)}}
    if region := _range(check.get("file_line_range")):
        physical["region"] = region
    properties = {"tool_severity": SEVERITY[rule_id]} if rule_id in SEVERITY else {}
    return {
        "ruleId": rule_id,
        "message": {"text": text},
        "locations": [{"physicalLocation": physical}],
        "properties": properties,
    }


def adapt(raw: bytes) -> bytes:
    """JSON nativo di checkov -> SARIF del contratto, o `InvalidOutput`."""
    try:
        document = json.loads(raw)
    except (ValueError, RecursionError) as exc:
        raise InvalidOutput("non è JSON") from exc
    seen: set[tuple[str, str, str]] = set()
    results: list[dict[str, Any]] = []
    for report in _reports(document):
        checks = report.get("results")
        if not isinstance(checks, dict):
            raise InvalidOutput("report senza results")
        # I controlli saltati da un commento in linea tornano finding (ADR-0026).
        for key in ("failed_checks", "skipped_checks"):
            for check in checks.get(key) or []:
                result = _result(check)
                identity = (
                    result["ruleId"],
                    result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],
                    json.dumps(result["locations"][0]["physicalLocation"].get("region")),
                )
                if identity not in seen:
                    seen.add(identity)
                    results.append(result)
    results.sort(key=lambda r: json.dumps([r["locations"], r["ruleId"]]))
    rules = sorted({r["ruleId"] for r in results})
    clean = {
        "version": "2.1.0",
        "runs": [
            {
                "tool": {"driver": {"name": "checkov", "rules": [{"id": r} for r in rules]}},
                "results": results,
            }
        ],
    }
    return json.dumps(clean, separators=(",", ":")).encode()


def command(checkov: str, directory: str, disabled: list[str]) -> list[str]:
    args = [checkov, "-d", directory, "--framework", *FRAMEWORKS]
    # Senza `--quiet`: con quell'opzione il JSON omette i controlli saltati da un commento, che qui
    # tornano finding (ADR-0026). Il JSON porta anche i controlli superati e i blocchi di codice:
    # si scartano nell'adattatore, la memoria la limita il container.
    args += ["--skip-download", "--compact", "-o", "json"]
    if disabled:
        args += ["--skip-check", ",".join(disabled)]
    return args


def run(
    *,
    checkov: str = CHECKOV,
    workspace: str = WORKSPACE,
    out_file: str = OUT_FILE,
    config_file: str = CONFIG_FILE,
    tmp_dir: str = TMP_DIR,
) -> int:
    try:
        disabled = load_disabled(config_file)
    except InvalidConfig:
        return EXIT_CONFIG
    env = {
        "PATH": os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin"),
        "HOME": tmp_dir,
        "BC_SKIP_MAPPING": "TRUE",
        "CHECKOV_RUN_SCA_PACKAGE_SCAN_V2": "false",
        "PYTHONDONTWRITEBYTECODE": "1",
    }
    scratch = tempfile.mkdtemp(prefix="ckv-", dir=tmp_dir)
    try:
        directory = str(Path(scratch, "ws"))
        Path(directory).mkdir()
        try:
            stage(workspace, directory)
        except OSError:
            return EXIT_TOOL
        try:
            done = subprocess.run(  # noqa: S603 - argv a lista, binario fissato, nessuna shell
                command(checkov, directory, disabled),
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                cwd=scratch,
                env=env,
                check=False,
            )
        except OSError:
            return EXIT_TOOL
        if done.returncode not in (0, 1) or not done.stdout.strip():  # 1 = controlli falliti
            return EXIT_TOOL
        try:
            adapted = adapt(done.stdout)
        except InvalidOutput:
            return EXIT_INVALID
        Path(out_file).write_bytes(adapted)
        return 0
    finally:
        shutil.rmtree(scratch, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(run())
