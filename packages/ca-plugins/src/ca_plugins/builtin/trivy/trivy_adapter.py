"""Adattatore del plugin trivy (P-04, P-05). Python standard: non importa `ca_core` (ADR-0007).

Due modi, nella stessa immagine firmata (ADR-0006):

- scansione (nessun argomento): `/workspace` in sola lettura, `/feeds` (snapshot) in sola lettura,
  nessuna rete. Solo il workspace (dipendenze e configurazioni IaC), mai immagini container:
  `trivy fs --scanners vuln,misconfig` (senza `secret` e `license`). Legge il JSON nativo e scrive
  in `/out` un SARIF 2.1.0 con un solo run, `uri` relativi alla radice del workspace senza
  `uriBaseId`, `category` e `purl` per ogni risultato.
- `sync`: container con rete e senza workspace. Scarica il database (`fs --download-db-only`) e il
  bundle delle regole di configurazione (`config` su una directory vuota) in `/feeds/trivy`.

Alias: il JSON nativo li da' in `VendorIDs` (per esempio il GHSA di una CVE); il SARIF di trivy no.
Il repository e l'output di trivy sono dati non fidati: si leggono come JSON e non si riportano in
stdout o stderr. Nel SARIF non entrano `Message`, `Description` ne' `Code` dei risultati di
configurazione (possono riportare valori del repository, ADR-0012) e nessun `snippet`.

Uscite: 0 ok; 3 trivy fallito o senza output; 4 sync fallita; 5 output non conforme.
"""

import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

TRIVY = "/usr/local/bin/trivy"
TRIVY_VERSION = "0.76.2"
WORKSPACE = "/workspace"
CACHE_DIR = "/feeds/trivy"
OUT_FILE = "/out/results.sarif"
TMP_FILE = "/tmp/trivy.json"  # noqa: S108 - tmpfs del profilo, mai un percorso condiviso
EXIT_TRIVY, EXIT_SYNC, EXIT_INVALID = 3, 4, 5
_LEVELS = {"CRITICAL": "error", "HIGH": "error", "MEDIUM": "warning", "LOW": "note"}
_COMMON = ["--skip-version-check", "--disable-telemetry", "--quiet"]
_MAX_TEXT = 300
_SOURCE_ORDER = ("nvd", "ghsa", "redhat")  # dopo `SeveritySource`, poi gli altri in ordine


class InvalidOutput(ValueError):
    """L'output di trivy non e' un JSON nativo utilizzabile."""


def _relative(target: str, workspace: str) -> str:
    path = target[len(workspace) + 1 :] if target.startswith(workspace + "/") else target
    segments = path.replace("\\", "/").split("/")
    if (
        not path
        or path.startswith(("/", "\\"))
        or ".." in segments
        or re.match(r"[A-Za-z][\w+.-]*:", path)
    ):
        raise InvalidOutput("percorso non relativo")
    return path


def _cvss(record: dict[str, Any]) -> dict[str, Any] | None:
    """Primo CVSS 3.x o 4.0 con vettore e punteggio, scegliendo la fonte nell'ordine di trivy."""
    sources = record.get("CVSS") or {}
    first = record.get("SeveritySource")
    order = [s for s in (first, *_SOURCE_ORDER) if s in sources]
    order += sorted(s for s in sources if s not in order)
    for key, score_key in (("V3Vector", "V3Score"), ("V40Vector", "V40Score")):
        for source in order:
            vector, score = sources[source].get(key), sources[source].get(score_key)
            match = re.match(r"CVSS:(3\.[01]|4\.0)/", vector) if isinstance(vector, str) else None
            if match and isinstance(score, (int, float)) and 0 <= score <= 10:
                return {"version": match.group(1), "vector": vector, "score": float(score)}
    return None


def _purl(record: dict[str, Any]) -> str:
    purl = ((record.get("PkgIdentifier") or {}).get("PURL")) or ""
    purl = str(purl).split("?", 1)[0].split("#", 1)[0]
    if not re.fullmatch(r"pkg:[a-z][a-z0-9.+-]*/\S+", purl):
        raise InvalidOutput("purl mancante o non valido")
    return purl


def _vulnerability(target: str | None, record: dict[str, Any]) -> dict[str, Any]:
    rule_id = str(record["VulnerabilityID"])
    severity = str(record.get("Severity") or "")
    text = (
        f"Package '{record['PkgName']}@{record['InstalledVersion']}' is vulnerable to '{rule_id}'"
    )
    if isinstance(record.get("Title"), str) and record["Title"]:
        text += ": " + " ".join(record["Title"].split())
    aliases = sorted({str(a) for a in record.get("VendorIDs") or () if a} - {rule_id})
    properties: dict[str, Any] = {"category": "dependency", "purl": _purl(record)}
    if aliases:
        properties["aliases"] = aliases
    if (cvss := _cvss(record)) is not None:
        properties["cvss"] = cvss
    if severity:
        properties["tool_severity"] = severity
    result: dict[str, Any] = {
        "ruleId": rule_id,
        "level": _LEVELS.get(severity, "note"),
        "message": {"text": text[:_MAX_TEXT]},
        "properties": properties,
    }
    if target is not None:
        result["locations"] = [{"physicalLocation": {"artifactLocation": {"uri": target}}}]
    return result


def _misconfiguration(target: str, record: dict[str, Any]) -> dict[str, Any]:
    severity = str(record.get("Severity") or "")
    physical: dict[str, Any] = {"artifactLocation": {"uri": target}}
    cause = record.get("CauseMetadata") or {}
    start, end = cause.get("StartLine"), cause.get("EndLine")
    if isinstance(start, int) and start >= 1:
        physical["region"] = {"startLine": start}
        if isinstance(end, int) and end >= start:
            physical["region"]["endLine"] = end
    properties: dict[str, Any] = {"category": "iac"}
    if severity:
        properties["tool_severity"] = severity
    title = " ".join(str(record.get("Title") or record["ID"]).split())
    return {
        "ruleId": str(record["ID"]),
        "level": _LEVELS.get(severity, "note"),
        "message": {"text": title[:_MAX_TEXT]},
        "locations": [{"physicalLocation": physical}],
        "properties": properties,
    }


def adapt(raw: bytes, workspace: str = WORKSPACE) -> bytes:
    """JSON nativo di trivy -> SARIF 2.1.0 con percorsi relativi, o `InvalidOutput`."""
    try:
        document = json.loads(raw)
        results: list[dict[str, Any]] = []
        seen: set[tuple[str, str, str]] = set()
        for entry in document.get("Results") or ():
            is_os = entry.get("Class") == "os-pkgs"  # Target e' una descrizione, non un percorso
            target = None if is_os else _relative(str(entry["Target"]), workspace)
            for record in entry.get("Vulnerabilities") or ():
                result = _vulnerability(target, record)
                key = (target or "", result["properties"]["purl"], result["ruleId"])
                if key not in seen:
                    seen.add(key)
                    results.append(result)
            for record in entry.get("Misconfigurations") or ():
                if record.get("Status") == "FAIL" and target is not None:
                    results.append(_misconfiguration(target, record))
    except (ValueError, KeyError, TypeError, AttributeError, RecursionError) as exc:
        raise InvalidOutput("JSON nativo non conforme") from exc
    sarif = {
        "version": "2.1.0",
        "runs": [
            {
                "tool": {"driver": {"name": "trivy", "version": TRIVY_VERSION}},
                "results": results,
            }
        ],
    }
    return json.dumps(sarif, separators=(",", ":")).encode()


def _env() -> dict[str, str]:
    return {
        "PATH": os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin"),
        "HOME": os.environ.get("HOME", "/tmp"),  # noqa: S108
    }


def _call(argv: list[str]) -> int:
    try:
        return subprocess.run(  # noqa: S603 - argv a lista, binario fissato, nessuna shell
            argv,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            env=_env(),
            check=False,
        ).returncode
    except OSError:
        return -1


def run(
    *,
    trivy: str = TRIVY,
    workspace: str = WORKSPACE,
    cache_dir: str = CACHE_DIR,
    out_file: str = OUT_FILE,
    tmp_file: str = TMP_FILE,
) -> int:
    Path(tmp_file).unlink(missing_ok=True)
    argv = [trivy, "fs", "--scanners", "vuln,misconfig"]
    argv += ["--offline-scan", "--skip-db-update", "--skip-check-update", *_COMMON]
    argv += ["--cache-dir", cache_dir, "--format", "json", "--output", tmp_file, workspace]
    if _call(argv) != 0:
        return EXIT_TRIVY
    try:
        raw = Path(tmp_file).read_bytes()
    except OSError:
        return EXIT_TRIVY
    try:
        adapted = adapt(raw, workspace)
    except InvalidOutput:
        return EXIT_INVALID
    Path(out_file).write_bytes(adapted)
    return 0


def sync(*, trivy: str = TRIVY, cache_dir: str = CACHE_DIR) -> int:
    """Database (V-05: `fs --download-db-only`) e regole (`config` su una directory vuota)."""
    if _call([trivy, "fs", "--download-db-only", "--cache-dir", cache_dir, *_COMMON]) != 0:
        return EXIT_SYNC
    with tempfile.TemporaryDirectory() as empty:
        return (
            0
            if _call([trivy, "config", "--cache-dir", cache_dir, *_COMMON, empty]) == 0
            else EXIT_SYNC
        )


def main(argv: list[str]) -> int:
    if argv == ["sync"]:
        return sync()
    return run() if not argv else EXIT_TRIVY


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
