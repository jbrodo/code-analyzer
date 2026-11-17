"""Adattatore del plugin coverage (P-05). Python standard: non importa `ca_core` (ADR-0007, 0026).

Legge i report di copertura che la CI ha prodotto prima della scansione, come file del workspace
indicati in `/inputs/config.json` (`{"reports": [{"path", "format", "base_dir"}]}`, dal blocco
`plugins.coverage` del repository, ricontrollato qui: ADR-0014). Un report è un input non fidato.

- Il file si apre senza seguire collegamenti simbolici e si controlla sul descrittore: regolare,
  dentro il workspace (anche per i percorsi intermedi), sotto un tetto di byte.
- XML con il parser `pyexpat` sui byte, non con una ricerca di testo: qualunque dichiarazione di
  entità fa rifiutare il report, qualunque sia la codifica (S-03, S3-A1). Una DTD esterna si
  ignora senza scaricare nulla. Tetti su elementi e profondità.
- I percorsi nel report sono relativi alla cartella in cui sono girati i test (`base_dir`): V-03.
  `<source>` di Cobertura è un percorso di un'altra macchina e si ignora. Una voce assoluta, che
  esce dal workspace o che non è un file regolare del workspace si scarta.
- Un file assente dal report non produce nulla: copertura ignota non è copertura zero. Più report
  sullo stesso file si uniscono riga per riga (coperta se lo è in almeno uno).
- Finding: uno per file con abbastanza righe misurabili e copertura di riga sotto la soglia
  (ADR-0026). Nessun frammento di codice: il plugin non legge mai i file sorgente.

Senza report configurati il SARIF è vuoto. Uscite: 0 ok; 4 `config.json` non valido; 6 report
rifiutato (forma, limiti, entità XML, collegamento simbolico); 3 errore di scrittura.
"""

import json
import os
import posixpath
import re
import stat
import sys
import xml.parsers.expat as expat
from pathlib import Path
from typing import Any

WORKSPACE = "/workspace"
OUT_FILE = "/out/results.sarif"
CONFIG_FILE = "/inputs/config.json"
EXIT_TOOL, EXIT_CONFIG, EXIT_REPORT = 3, 4, 6

# Soglie dell'immagine (ADR-0026): il 50% è il valore di §6.3. Le passerà l'host dalla
# configurazione di scoring quando esisterà (C-03).
THRESHOLD_PERCENT = 50
MIN_LINES = 20
RULE_ID = "ca.coverage.low-file-coverage"

MAX_REPORTS = 20
MAX_REPORT_BYTES = 32 * 1024 * 1024
MAX_LINE_LENGTH = 4096
MAX_ELEMENTS = 2_000_000
MAX_DEPTH = 100
MAX_COUNT = 10**9
FORMATS = ("lcov", "cobertura")
_UNSAFE = re.compile(r"^(?:[/\\]|[A-Za-z]:)|(?:^|[/\\])\.\.(?![^/\\])|[\x00-\x1f\x7f]")


class ConfigError(ValueError):
    """`config.json` malformato."""


class ReportRefused(ValueError):
    """Il report viola un limite, la forma attesa o dichiara entità."""


def _safe_relative(value: Any) -> bool:
    return isinstance(value, str) and bool(value) and _UNSAFE.search(value) is None


def load_reports(path: str = CONFIG_FILE) -> list[dict[str, Any]]:
    try:
        raw = Path(path).read_bytes()
    except FileNotFoundError:
        return []
    except OSError as exc:
        raise ConfigError("config.json illeggibile") from exc
    try:
        document = json.loads(raw)
    except (ValueError, RecursionError) as exc:
        raise ConfigError("config.json non è JSON") from exc
    if not isinstance(document, dict) or set(document) - {"reports"}:
        raise ConfigError("config.json: chiavi non ammesse")
    reports = document.get("reports") or []
    if not isinstance(reports, list) or len(reports) > MAX_REPORTS:
        raise ConfigError("config.json: reports non valido")
    out = []
    for item in reports:
        if not isinstance(item, dict) or set(item) - {"path", "format", "base_dir"}:
            raise ConfigError("config.json: voce non valida")
        base = item.get("base_dir")
        if (
            not _safe_relative(item.get("path"))
            or item.get("format") not in FORMATS
            or (base is not None and not _safe_relative(base))
        ):
            raise ConfigError("config.json: voce non valida")
        out.append({"path": item["path"], "format": item["format"], "base_dir": base})
    return out


# --- lettura del file ---------------------------------------------------------------------------


def read_report(workspace: str, relative: str) -> bytes | None:
    """Byte del report, `None` se il file non esiste. Rifiuta tutto ciò che non è sicuro."""
    root = os.path.realpath(workspace)
    resolved = os.path.realpath(os.path.join(root, relative))
    if resolved != root and not resolved.startswith(root + os.sep):
        raise ReportRefused("report fuori dal workspace")
    try:
        fd = os.open(resolved, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise ReportRefused("report non apribile") from exc
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_REPORT_BYTES:
            raise ReportRefused("report non regolare o troppo grande")
        with os.fdopen(fd, "rb", closefd=False) as handle:
            data = handle.read(MAX_REPORT_BYTES + 1)
    except OSError as exc:
        raise ReportRefused("report illeggibile") from exc
    finally:
        os.close(fd)
    if len(data) > MAX_REPORT_BYTES:
        raise ReportRefused("report troppo grande")
    return data


# --- parser ---------------------------------------------------------------------------------

Lines = dict[int, int]  # numero di riga -> esecuzioni
Entries = list[tuple[str, Lines]]


def _count(value: str) -> int:
    if not value.lstrip("-").isdigit() or abs(int(value)) > MAX_COUNT:
        raise ReportRefused("numero non valido")
    return int(value)


def parse_lcov(data: bytes) -> Entries:
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ReportRefused("LCOV non è UTF-8") from exc
    entries: Entries = []
    current: Lines | None = None
    for number, line in enumerate(text.splitlines(), 1):
        if len(line) > MAX_LINE_LENGTH:
            raise ReportRefused("riga LCOV troppo lunga")
        tag, _, value = line.partition(":")
        if tag == "SF":
            current = {}
            entries.append((value, current))
        elif tag == "DA":
            fields = value.split(",")
            if len(fields) < 2 or current is None:
                raise ReportRefused("DA non valido")
            hits = _count(fields[1])
            line_number = _count(fields[0])
            if line_number < 1:
                raise ReportRefused("DA non valido")
            current[line_number] = max(current.get(line_number, 0), hits)
        elif tag in ("LF", "LH"):
            if not value.isdigit() or int(value) > MAX_COUNT:
                raise ReportRefused(f"{tag} non valido")
        elif tag == "FN" and not re.fullmatch(r"\d+(?:,\d+)?,.+", value):
            raise ReportRefused("FN non valido")  # due dialetti: V-03
        elif tag == "end_of_record":
            current = None
        del number
    return entries


def parse_cobertura(data: bytes) -> Entries:
    entries: Entries = []
    state = {"elements": 0, "depth": 0}
    current: list[Lines | None] = [None]

    def refuse(*_: Any) -> None:
        raise ReportRefused("dichiarazione di entità")

    def start(name: str, attrs: dict[str, str]) -> None:
        state["elements"] += 1
        state["depth"] += 1
        if state["elements"] > MAX_ELEMENTS or state["depth"] > MAX_DEPTH:
            raise ReportRefused("troppi elementi o troppo annidati")
        if name == "class":
            lines: Lines = {}
            entries.append((attrs.get("filename", ""), lines))
            current[0] = lines
        elif name == "line" and current[0] is not None:
            number, hits = attrs.get("number", ""), attrs.get("hits", "")
            if not number.isdigit() or not hits.lstrip("-").isdigit():
                raise ReportRefused("line non valida")
            line_number = _count(number)
            if line_number >= 1:
                current[0][line_number] = max(current[0].get(line_number, 0), _count(hits))

    def end(name: str) -> None:
        state["depth"] -= 1
        if name == "class":
            current[0] = None

    parser = expat.ParserCreate()
    parser.SetParamEntityParsing(expat.XML_PARAM_ENTITY_PARSING_NEVER)
    parser.EntityDeclHandler = refuse
    parser.UnparsedEntityDeclHandler = refuse
    parser.StartElementHandler = start
    parser.EndElementHandler = end
    try:
        parser.Parse(data, True)
    except expat.ExpatError as exc:
        raise ReportRefused("XML non valido") from exc
    except RecursionError as exc:
        raise ReportRefused("XML troppo annidato") from exc
    return entries


def parse_report(data: bytes, fmt: str) -> Entries:
    return parse_lcov(data) if fmt == "lcov" else parse_cobertura(data)


# --- percorsi e conteggi -----------------------------------------------------------------------


def resolve(name: str, base_dir: str | None) -> str | None:
    """Percorso nel workspace di una voce del report, o `None` se si scarta."""
    if not name or _UNSAFE.search(name) or "\\" in name:
        return None
    joined = posixpath.normpath(posixpath.join(base_dir or "", name))
    if joined in (".", "") or joined.startswith(("/", "..")) or "/../" in f"/{joined}/":
        return None
    return joined


def is_workspace_file(workspace: str, relative: str) -> bool:
    """File regolare nel workspace, senza collegamenti simbolici su nessun componente."""
    root = os.path.realpath(workspace)
    path = os.path.join(root, relative)
    if os.path.realpath(path) != path:
        return False
    try:
        return stat.S_ISREG(os.lstat(path).st_mode)
    except OSError:
        return False


def merge(
    reports: list[dict[str, Any]], datas: list[bytes | None], workspace: str | None
) -> tuple[dict[str, Lines], int]:
    """Righe per percorso del workspace, unite tra i report; e quante voci si sono scartate."""
    files: dict[str, Lines] = {}
    discarded = 0
    for report, data in zip(reports, datas, strict=True):
        if data is None:
            continue
        for name, lines in parse_report(data, report["format"]):
            path = resolve(name, report["base_dir"])
            if path is None or (workspace is not None and not is_workspace_file(workspace, path)):
                discarded += 1
                continue
            target = files.setdefault(path, {})
            for number, hits in lines.items():
                target[number] = max(target.get(number, 0), hits)
    return files, discarded


def findings(files: dict[str, Lines]) -> list[dict[str, Any]]:
    results = []
    for path in sorted(files):
        lines = files[path]
        measurable = len(lines)
        covered = sum(1 for hits in lines.values() if hits > 0)
        if measurable < MIN_LINES or covered * 100 >= THRESHOLD_PERCENT * measurable:
            continue
        percent = covered * 100 // measurable
        text = (
            f"Copertura di riga {percent}% ({covered} su {measurable} righe), "
            f"soglia {THRESHOLD_PERCENT}%"
        )
        results.append(
            {
                "ruleId": RULE_ID,
                "message": {"text": text},
                "locations": [{"physicalLocation": {"artifactLocation": {"uri": path}}}],
                # `value` è la copertura misurata e `threshold` quella minima: qui il problema è
                # un valore sotto la soglia, non sopra (ADR-0026).
                "properties": {
                    "tool_severity": "medium",
                    "metric": {"value": percent, "threshold": THRESHOLD_PERCENT},
                },
            }
        )
    return results


def sarif(results: list[dict[str, Any]]) -> bytes:
    document = {
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "coverage",
                        "rules": [{"id": RULE_ID}] if results else [],
                    }
                },
                "results": results,
            }
        ],
    }
    return json.dumps(document, separators=(",", ":")).encode()


def run(
    *,
    workspace: str = WORKSPACE,
    out_file: str = OUT_FILE,
    config_file: str = CONFIG_FILE,
) -> int:
    try:
        reports = load_reports(config_file)
    except ConfigError:
        return EXIT_CONFIG
    try:
        datas = [read_report(workspace, r["path"]) for r in reports]
        files, _ = merge(reports, datas, workspace)
    except ReportRefused:
        return EXIT_REPORT
    try:
        Path(out_file).write_bytes(sarif(findings(files)))
    except OSError:
        return EXIT_TOOL
    return 0


if __name__ == "__main__":
    sys.exit(run())
