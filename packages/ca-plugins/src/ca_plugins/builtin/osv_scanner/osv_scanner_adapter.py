"""Adattatore del plugin osv-scanner (P-02, P-03). Python standard, senza `ca_core` (ADR-0007).

Due modi, nella stessa immagine firmata (ADR-0006):

- scansione (nessun argomento): `/workspace` in sola lettura, `/feeds` (snapshot) in sola lettura,
  nessuna rete. Esegue osv-scanner con `--offline-vulnerabilities --no-resolve`, legge il suo JSON
  nativo (vettore CVSS e alias non stanno nel SARIF) e scrive in `/out` un SARIF 2.1.0 con un solo
  run, `uri` relativi alla radice del workspace e solo le proprieta' del contratto ADR-0007.
- `sync <ecosistema>... [--base-url=URL]`: container con rete e senza workspace. Scarica gli
  `all.zip` degli ecosistemi indicati, da un elenco chiuso, in
  `/feeds/osv-scalibr/<ecosistema>/all.zip`. Non riceve ne' legge alcun dato del repository.

Il repository e l'output di osv-scanner sono dati non fidati: si leggono come JSON, non si
interpretano e non si riportano in stdout o stderr. Nessun `snippet` in uscita (ADR-0012).

Uscite: 0 ok; 3 osv-scanner fallito (exit inatteso, `could not load db` per un ecosistema in
elenco, `Error during extraction`, nessun output); 4 sync fallita; 5 output non conforme. Exit 1
(vulnerabilita' trovate) ed exit 128 con `No package sources found` (nessun pacchetto) non sono
fallimenti: nel secondo caso il SARIF ha zero risultati.

Ecosistema fuori elenco (D2-09, emendamento di ADR-0006): se manca il database di un ecosistema
che non sta in `ECOSYSTEMS` (ad esempio Maven per un `pom.xml`), il plugin non fallisce. La
scansione si ripete con un database vuoto per quell'ecosistema, cosi' il confronto degli altri
si completa, e una notifica `feeds-ecosystem-missing` in `invocations` nomina l'ecosistema e
quanti pacchetti restano senza controllo; il nucleo ne fa un avviso del report.
"""

import json
import math
import os
import re
import subprocess
import sys
import tempfile
import urllib.request
import zipfile
from pathlib import Path
from typing import Any
from urllib.parse import quote, urlsplit

SCANNER = "/usr/local/bin/osv-scanner"
SCANNER_VERSION = "2.7.0"
WORKSPACE = "/workspace"
FEEDS = "/feeds"
OUT_FILE = "/out/results.sarif"
TMP_FILE = "/tmp/osv.json"  # noqa: S108 - tmpfs del profilo, mai un percorso condiviso
BASE_URL = "https://osv-vulnerabilities.storage.googleapis.com"
ECOSYSTEMS = ("npm", "PyPI")  # elenco chiuso (ADR-0006): stessi valori di `feeds.ecosystems`
MAX_ZIP_BYTES = 1024**3  # npm 210 MB, PyPI 36 MB (V-05)
EXIT_SCANNER, EXIT_SYNC, EXIT_INVALID = 3, 4, 5
_LEVELS = {"CRITICAL": "error", "HIGH": "error", "MODERATE": "warning", "MEDIUM": "warning"}
_MAX_TEXT = 300
# `vulnmatch/osvlocal` e' il confronto con i feed: con uno snapshot vuoto e senza pacchetti non
# e' un fallimento (lo e' `could not load db` quando i pacchetti ci sono). Gli altri estrattori
# (lockfile) che falliscono si': un file corrotto non e' piu' usabile.
_EXTRACTION_ERROR = re.compile(rb"error during extraction: \(extracting as (?!vulnmatch/)")
_MISSING_DB = re.compile(rb"(?i)could not load db for ([^\n:]{1,80}?) ecosystem")
# Diventa anche il nome di una cartella nel tmpfs: niente separatori ne' `..`.
_ECOSYSTEM_NAME = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9 _-]|\.(?!\.)){0,39}")
MISSING_ID = "feeds-ecosystem-missing"  # il nucleo ne fa l'avviso `plugin-<id>` (K-19)


class InvalidOutput(ValueError):
    """L'output di osv-scanner non e' un JSON nativo utilizzabile."""


# --- CVSS 3.x: il JSON nativo porta il vettore, non il punteggio ---------------------------

_V3 = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
    "AC": {"L": 0.77, "H": 0.44},
    "UI": {"N": 0.85, "R": 0.62},
    "CIA": {"H": 0.56, "L": 0.22, "N": 0.0},
}


def _uri(path: str) -> str:
    """Percorso codificato per l'`uri` del SARIF (ADR-0004): l'host rifiuta `?` e `#`, scambia
    `a:` per uno schema e decodifica `%XX`. `fsencode` conserva anche i nomi non UTF-8."""
    return quote(os.fsencode(path), safe="/")


def _roundup(value: float) -> float:
    whole = round(value * 100000)
    return whole / 100000.0 if whole % 10000 == 0 else (math.floor(whole / 10000) + 1) / 10.0


def cvss3(vector: str) -> dict[str, Any] | None:
    """`{version, vector, score}` per un vettore CVSS 3.0/3.1 ben formato, altrimenti `None`."""
    match = re.fullmatch(r"CVSS:(3\.[01])/((?:[A-Z]+:[A-Z]/?)+)", vector)
    if not match:
        return None
    try:
        m = dict(part.split(":") for part in match.group(2).rstrip("/").split("/"))
        changed = m["S"] == "C"
        priv = {"N": 0.85, "L": 0.68 if changed else 0.62, "H": 0.5 if changed else 0.27}[m["PR"]]
        iss = 1 - math.prod(1 - _V3["CIA"][m[k]] for k in "CIA")
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15 if changed else 6.42 * iss
        exploit = 8.22 * _V3["AV"][m["AV"]] * _V3["AC"][m["AC"]] * priv * _V3["UI"][m["UI"]]
    except (KeyError, ValueError):
        return None
    raw = 0.0 if impact <= 0 else min((1.08 if changed else 1.0) * (impact + exploit), 10.0)
    return {"version": match.group(1), "vector": vector, "score": _roundup(raw)}


# --- JSON nativo -> SARIF -----------------------------------------------------------------


def _relative(path: str, workspace: str) -> str:
    if not path.startswith(workspace + "/"):
        raise InvalidOutput("percorso fuori dal workspace")
    relative = path[len(workspace) + 1 :]
    if ".." in relative.split("/"):
        raise InvalidOutput("percorso non confinato")
    return relative


def _purl(value: str) -> str:
    """Senza qualificatori (`?source=...`): lo stesso purl degli altri scanner (ADR-0008)."""
    purl = value.split("?", 1)[0].split("#", 1)[0]
    if not re.fullmatch(r"pkg:[a-z][a-z0-9.+-]*/\S+", purl):
        raise InvalidOutput("purl mancante o non valido")
    return purl


def _result(
    source: str, package: dict[str, Any], group: dict[str, Any], vulns: dict[str, Any]
) -> dict[str, Any]:
    ids = [i for i in group["ids"] if isinstance(i, str) and i]
    records = [vulns[i] for i in sorted(ids) if i in vulns]
    names = set(ids) | {a for a in group.get("aliases", []) if isinstance(a, str) and a}
    for record in records:
        names |= {a for a in record.get("aliases", []) if isinstance(a, str) and a}
    if not names:
        raise InvalidOutput("gruppo senza identificativo")
    cves = sorted(n for n in names if n.startswith("CVE-"))
    rule_id = cves[0] if cves else sorted(ids or names)[0]
    scores = [
        c
        for r in records
        for s in r.get("severity", [])
        if s.get("type") == "CVSS_V3" and (c := cvss3(str(s.get("score"))))
    ]
    severity = next(
        (
            s
            for r in records
            if isinstance(s := (r.get("database_specific") or {}).get("severity"), str) and s
        ),
        None,
    )
    summary = next((r["summary"] for r in records if isinstance(r.get("summary"), str)), "")
    name, version = str(package["package"]["name"]), str(package["package"]["version"])
    text = f"Package '{name}@{version}' is vulnerable to '{rule_id}'"
    if summary:
        text += ": " + " ".join(summary.split())
    properties: dict[str, Any] = {
        "category": "dependency",
        "purl": _purl(str(package["package"].get("purl"))),
    }
    if names - {rule_id}:
        properties["aliases"] = sorted(names - {rule_id})
    if scores:
        properties["cvss"] = max(scores, key=lambda c: c["score"])  # shortcut: solo 3.x, non 4.0
    if severity:
        properties["tool_severity"] = severity
    return {
        "ruleId": rule_id,
        "level": _LEVELS.get((severity or "").upper(), "note" if severity else "warning"),
        "message": {"text": text[:_MAX_TEXT]},
        "locations": [{"physicalLocation": {"artifactLocation": {"uri": _uri(source)}}}],
        "properties": properties,
    }


def _missing_notes(document: Any, missing: frozenset[str]) -> list[dict[str, Any]]:
    """Una notifica per ogni ecosistema senza database, col numero dei suoi pacchetti."""
    counts: dict[str, int] = {}
    names: dict[str, str] = {}
    for entry in document["results"]:
        for package in entry.get("packages", []):
            name = str(package["package"].get("ecosystem") or "")
            key = name.lower()
            if key in missing:
                counts[key] = counts.get(key, 0) + 1
                names.setdefault(key, name)
    notes = []
    for key in sorted(missing):
        name = names.get(key, key)
        shown = name if _ECOSYSTEM_NAME.fullmatch(name) else "unknown"
        text = (
            f"no vulnerability database for ecosystem {shown}: "
            f"{counts.get(key, 0)} packages were not checked"
        )
        notes.append(
            {"level": "warning", "descriptor": {"id": MISSING_ID}, "message": {"text": text}}
        )
    return notes


def adapt(raw: bytes, workspace: str = WORKSPACE, missing: frozenset[str] = frozenset()) -> bytes:
    """JSON nativo di osv-scanner -> SARIF 2.1.0 con percorsi relativi, o `InvalidOutput`.

    `missing`: ecosistemi fuori elenco senza database, in minuscolo (D2-09).
    """
    try:
        document = json.loads(raw)
        results: list[dict[str, Any]] = []
        seen: set[tuple[str, str, str]] = set()
        for entry in document["results"]:
            source = _relative(str(entry["source"]["path"]), workspace)
            for package in entry.get("packages", []):
                vulns = {v["id"]: v for v in package.get("vulnerabilities", [])}
                for group in package.get("groups", []):
                    result = _result(source, package, group, vulns)
                    key = (source, result["properties"]["purl"], result["ruleId"])
                    if key not in seen:
                        seen.add(key)
                        results.append(result)
        notes = _missing_notes(document, missing) if missing else []
    except (ValueError, KeyError, TypeError, AttributeError, RecursionError) as exc:
        raise InvalidOutput("JSON nativo non conforme") from exc
    run_: dict[str, Any] = {
        "tool": {"driver": {"name": "osv-scanner", "version": SCANNER_VERSION}},
        "results": results,
    }
    if notes:
        run_["invocations"] = [{"executionSuccessful": True, "toolExecutionNotifications": notes}]
    return json.dumps({"version": "2.1.0", "runs": [run_]}, separators=(",", ":")).encode()


# --- scansione ----------------------------------------------------------------------------


def _scan(scanner: str, workspace: str, cache: str, tmp_file: str) -> tuple[int, bytes] | None:
    """Esegue osv-scanner con i database in `cache`: `(exit, log)`, o `None` se non parte."""
    env = {
        "PATH": os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin"),
        "HOME": os.environ.get("HOME", "/tmp"),  # noqa: S108
        "OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY": cache,
    }
    Path(tmp_file).unlink(missing_ok=True)
    try:
        # `--config` su un file vuoto sovrascrive ogni `osv-scanner.toml` del repository, anche
        # quelli accanto ai lockfile nei sottoalberi (N-01); cwd vuota. `--no-ignore`: un
        # `.gitignore` del repository non nasconde i lockfile (N-06: exit 128, SARIF vuoto).
        with tempfile.TemporaryDirectory() as empty:
            config = Path(empty, "osv-scanner.toml")
            config.touch()
            argv = [scanner, "scan", "source", "--offline-vulnerabilities", "--no-resolve", "-r"]
            # `--all-packages`: anche i pacchetti senza vulnerabilita', per contare quelli di un
            # ecosistema senza database (D2-09). `adapt` ignora chi non ha `groups`.
            argv += [
                "--all-packages",
                "--no-ignore",
                "--config",
                str(config),
                "--format",
                "json",
                "--output-file",
                tmp_file,
            ]
            done = subprocess.run(  # noqa: S603 - argv a lista, binario fissato, nessuna shell
                [*argv, workspace],
                stdin=subprocess.DEVNULL,
                capture_output=True,
                cwd=empty,
                env=env,
                check=False,
            )
    except OSError:
        return None
    return done.returncode, done.stdout + done.stderr


def _shadow_cache(feeds: str, shadow: str, missing: list[str]) -> None:
    """Copia di `feeds` per collegamenti, con un database vuoto per ogni ecosistema in `missing`.

    Senza il database di un ecosistema osv-scanner interrompe il confronto e perde risultati
    anche degli altri (misurato: 6 su 25 per PyPI accanto a un `pom.xml`). Con un database vuoto
    il confronto si completa. `/feeds` e' in sola lettura: la copia sta nel tmpfs.
    """
    root = Path(shadow, "osv-scalibr")
    root.mkdir()
    source = Path(feeds, "osv-scalibr")
    for eco in ECOSYSTEMS:
        archive = source / eco / "all.zip"
        if archive.is_file():
            (root / eco).mkdir()
            (root / eco / "all.zip").symlink_to(archive)
    for eco in missing:
        (root / eco).mkdir()
        zipfile.ZipFile(root / eco / "all.zip", "w").close()


def run(
    *,
    scanner: str = SCANNER,
    workspace: str = WORKSPACE,
    feeds: str = FEEDS,
    out_file: str = OUT_FILE,
    tmp_file: str = TMP_FILE,
) -> int:
    first = _scan(scanner, workspace, feeds, tmp_file)
    if first is None:
        return EXIT_SCANNER
    code, log = first
    # `could not load db`: exit 1 o 127 con risultati parziali (V-05). Per un ecosistema in
    # elenco il plugin fallisce. Fuori elenco (D2-09) si ripete con un database vuoto per
    # quell'ecosistema: se il nome non e' riconoscibile o la seconda esecuzione segnala ancora
    # un database mancante, il plugin fallisce come prima.
    names = sorted({m.decode("ascii", "replace").strip() for m in _MISSING_DB.findall(log)})
    listed = {eco.lower() for eco in ECOSYSTEMS}
    if b"could not load db" in log.lower():
        if not names or any(n.lower() in listed or not _ECOSYSTEM_NAME.fullmatch(n) for n in names):
            return EXIT_SCANNER
        try:
            with tempfile.TemporaryDirectory() as shadow:
                _shadow_cache(feeds, shadow, names)
                second = _scan(scanner, workspace, shadow, tmp_file)
                if second is None:
                    return EXIT_SCANNER
                code, log = second
                if b"could not load db" in log.lower():
                    return EXIT_SCANNER
                return _finish(code, log, workspace, out_file, tmp_file, names)
        except OSError:
            return EXIT_SCANNER
    return _finish(code, log, workspace, out_file, tmp_file, [])


def _finish(
    code: int, log: bytes, workspace: str, out_file: str, tmp_file: str, missing: list[str]
) -> int:
    lowered = log.lower()
    if _EXTRACTION_ERROR.search(lowered):  # lockfile non estraibile: mai un esito vuoto (N-12)
        return EXIT_SCANNER
    if code == 128 and b"no package sources found" in lowered:
        raw = b'{"results":[]}'
    elif code in (0, 1):
        try:
            raw = Path(tmp_file).read_bytes()
        except OSError:
            return EXIT_SCANNER
    else:
        return EXIT_SCANNER
    try:
        adapted = adapt(raw, workspace, frozenset(n.lower() for n in missing))
    except InvalidOutput:
        return EXIT_INVALID
    Path(out_file).write_bytes(adapted)
    return 0


# --- sincronizzazione ---------------------------------------------------------------------


def sync(
    ecosystems: list[str], *, feeds: str = FEEDS, base_url: str = BASE_URL, timeout: float = 60.0
) -> int:
    """Scarica `<base_url>/<eco>/all.zip` in `<feeds>/osv-scalibr/<eco>/all.zip` (atomico)."""
    if not ecosystems or len(set(ecosystems)) != len(ecosystems):
        return EXIT_SYNC
    if any(eco not in ECOSYSTEMS for eco in ecosystems):  # l'URL non si compone da dati liberi
        return EXIT_SYNC
    for eco in ecosystems:
        target = Path(feeds) / "osv-scalibr" / eco / "all.zip"
        part = target.with_name("all.zip.part")
        try:
            target.parent.mkdir(parents=True, exist_ok=True)
            with urllib.request.urlopen(f"{base_url}/{eco}/all.zip", timeout=timeout) as src:  # noqa: S310
                with part.open("wb") as dst:
                    while chunk := src.read(1 << 20):
                        dst.write(chunk)
                        if dst.tell() > MAX_ZIP_BYTES:
                            raise OSError("archivio oltre il limite")
            with zipfile.ZipFile(part) as archive:
                if not archive.namelist():
                    raise OSError("archivio vuoto")
            os.replace(part, target)
        except (OSError, ValueError, zipfile.BadZipFile):  # URLError e' un OSError
            part.unlink(missing_ok=True)
            return EXIT_SYNC
    return 0


def _sync_command(argv: list[str]) -> int:
    """`<ecosistema>... [--base-url=URL]`: l'URL, se c'e', lo passa la CLI per un'origine scelta
    da chi lancia la scansione (E-04). Si ricontrolla qui: https, un host, nessuna credenziale."""
    ecosystems = [a for a in argv if not a.startswith("--")]
    options = [a for a in argv if a.startswith("--")]
    if not options:
        return sync(ecosystems)
    name, _, url = options[0].partition("=")
    try:
        parts = urlsplit(url)
        valid = parts.scheme == "https" and bool(parts.hostname)
        valid = valid and not (parts.username or parts.password or parts.query or parts.fragment)
    except ValueError:
        valid = False
    if len(options) != 1 or name != "--base-url" or not valid:
        return EXIT_SYNC
    return sync(ecosystems, base_url=url.rstrip("/"))


def main(argv: list[str]) -> int:
    if argv[:1] == ["sync"]:
        return _sync_command(argv[1:])
    return run() if not argv else EXIT_SCANNER


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
