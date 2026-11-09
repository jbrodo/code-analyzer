"""Confronto tra gli attesi di una fixture (F-01) e i finding di un report. Non e' un test.

Regola di G1.c: nessun atteso mancante. Un finding in piu' non e' un errore (bandit emette B403 e
B404 non elencati). Un atteso e' soddisfatto da un finding che ha:
- la stessa `category`;
- `rule_id` uguale, oppure, per `cve`, il CVE tra i `cve` del finding o come suo `rule_id`;
- lo stesso `path` (la radice della fixture e' la radice della scansione);
- se l'atteso ha righe, un intervallo che si sovrappone a `[start_line, end_line]`;
- almeno uno dei `tools` dell'atteso tra i `tools` del finding.

Posizione: vale quella principale del finding oppure una di `evidence.occurrences`, dove ADR-0008
mette "l'unione delle posizioni di tutti i finding del gruppo" (stesso segreto in piu' commit: la
posizione principale e' quella del commit piu' vecchio, la riga in HEAD e' nelle occorrenze).

Il confronto non usa il fingerprint (F-01) e non e' piu' largo di quanto dice lo schema: nessuna
tolleranza sui percorsi, nessuna sulle righe oltre la sovrapposizione.
"""

from pathlib import Path
from typing import Any

import yaml

Expected = dict[str, Any]
Finding = dict[str, Any]


def load_expected(path: Path) -> list[Expected]:
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    entries: list[Expected] = data["expected"]
    return entries


def describe(entry: Expected) -> str:
    what = entry.get("rule_id") or entry["cve"]
    where = entry["path"]
    if "start_line" in entry:
        end = entry.get("end_line", entry["start_line"])
        where += f":{entry['start_line']}" + (f"-{end}" if end != entry["start_line"] else "")
    return f"{entry['category']}/{what}@{where}"


def _lines_overlap(entry: Expected, location: dict[str, Any]) -> bool:
    start = location.get("start_line")
    if start is None:
        return False
    end = location.get("end_line") or start
    wanted_end = entry.get("end_line", entry["start_line"])
    return bool(start <= wanted_end and end >= entry["start_line"])


def _locations(finding: Finding) -> list[dict[str, Any]]:
    occurrences = finding.get("evidence", {}).get("occurrences", [])
    return [finding["location"], *[o for o in occurrences if isinstance(o, dict)]]


def satisfies(entry: Expected, finding: Finding, *, ignore_lines: bool = False) -> bool:
    if finding["category"] != entry["category"]:
        return False
    if "rule_id" in entry:
        if finding["rule_id"] != entry["rule_id"]:
            return False
    elif entry["cve"] != finding["rule_id"] and entry["cve"] not in finding.get("cve", []):
        return False
    if not set(entry["tools"]) & set(finding["tools"]):
        return False
    for location in _locations(finding):
        if location.get("path") != entry["path"]:
            continue
        if ignore_lines or "start_line" not in entry or _lines_overlap(entry, location):
            return True
    return False


def matching(
    entry: Expected, findings: list[Finding], *, ignore_lines: bool = False
) -> list[Finding]:
    return [f for f in findings if satisfies(entry, f, ignore_lines=ignore_lines)]


def missing(entries: list[Expected], findings: list[Finding]) -> list[Expected]:
    return [e for e in entries if not matching(e, findings)]


def near_misses(entry: Expected, findings: list[Finding], limit: int = 5) -> list[str]:
    """Finding della stessa regola o dello stesso CVE: aiutano a capire perche' manca un atteso."""
    key = entry.get("rule_id") or entry["cve"]
    out = []
    for f in findings:
        if key == f["rule_id"] or key in f.get("cve", []):
            loc = f["location"]
            out.append(
                f"{f['category']}/{f['rule_id']}@{loc.get('path')}:{loc.get('start_line')}"
                f" tools={f['tools']}"
            )
    return out[:limit]
