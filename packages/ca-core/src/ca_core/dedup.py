"""Deduplicazione dei finding per fingerprint (K-07, ADR-0008 "Precisazioni per K-04" §7).

Proprietà: `deduplicate(deduplicate(xs)) == deduplicate(xs)` e il risultato non dipende
dall'ordine di `xs`. Si raggruppa per `fingerprint`; il risultato è ordinato per fingerprint.
Un gruppo di uno ritorna invariato: dopo la fusione i fingerprint sono unici, quindi basta.

SAST di scanner diversi non si fondono perché il fingerprint contiene il nome dello scanner
(ADR-0008): qui non c'è nessuna regola in più.

Precondizioni da K-05: `tools = [tool]`, `evidence` con chiave `<tool>` (più `occurrences`,
riservata), `level`, `score` e `impact` nulli (i livelli si calcolano dopo, K-11).
"""

import json
from collections import defaultdict
from collections.abc import Mapping, Sequence
from typing import Any

from ca_core.models.finding import Finding

OCCURRENCES = "occurrences"  # chiave riservata di `evidence`: nessun plugin può chiamarsi così
_LOCATION_KEYS = ("path", "start_line", "end_line", "purl")


def _canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def _key(finding: Finding) -> str:
    return _canonical(finding.model_dump(mode="json"))


def _occurrences(group: Sequence[Finding]) -> list[dict[str, Any]]:
    found: dict[str, dict[str, Any]] = {}
    for finding in group:
        previous = finding.evidence.get(OCCURRENCES, [])
        if not isinstance(previous, list) or not all(isinstance(p, Mapping) for p in previous):
            raise ValueError("evidence.occurrences riservata e deve essere un elenco di posizioni")
        location = finding.location.model_dump(mode="json")
        for position in [*previous, {k: location[k] for k in _LOCATION_KEYS}]:
            found[_canonical(position)] = dict(position)
    return [found[k] for k in sorted(found)]


def _merge(group: Sequence[Finding]) -> Finding:
    ranked = sorted(group, key=_key)
    representative = ranked[0]
    tools = sorted({t for f in group for t in f.tools})
    evidence: dict[str, Any] = {}
    for tool in tools:
        # il primo, nell'ordine canonico, tra i finding di quel tool che ne portano l'evidenza
        for finding in ranked:
            if tool in finding.tools and tool in finding.evidence:
                evidence[tool] = finding.evidence[tool]
                break
    evidence[OCCURRENCES] = _occurrences(group)
    data = representative.model_dump()
    data.update(
        tool=tools[0],
        tools=tools,
        cve=sorted({c for f in group for c in f.cve}),
        cwe=sorted({c for f in group for c in f.cwe}),
        evidence=evidence,
        first_seen=min(f.first_seen for f in group),
        last_seen=max(f.last_seen for f in group),
    )
    return Finding.model_validate(data)


def deduplicate(findings: Sequence[Finding]) -> list[Finding]:
    """Fonde i finding con lo stesso fingerprint; risultato ordinato per fingerprint."""
    groups: dict[str, list[Finding]] = defaultdict(list)
    for finding in findings:
        groups[finding.fingerprint].append(finding)
    return [
        group[0] if len(group) == 1 else _merge(group)
        for _, group in sorted(groups.items(), key=lambda item: item[0])
    ]
