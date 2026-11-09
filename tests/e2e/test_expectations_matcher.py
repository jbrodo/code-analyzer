"""Il confronto degli attesi e' esso stesso codice: se fosse troppo largo nasconderebbe attesi
mancanti (G1.c). Senza Docker."""

import copy
from typing import Any

import pytest

from .expectations import describe, matching, missing, satisfies

ENTRY: dict[str, Any] = {
    "category": "sast",
    "rule_id": "B602",
    "path": "app/handlers.py",
    "start_line": 12,
    "end_line": 14,
    "tools": ["bandit"],
}
FINDING: dict[str, Any] = {
    "category": "sast",
    "rule_id": "B602",
    "tools": ["bandit"],
    "cve": [],
    "location": {"path": "app/handlers.py", "start_line": 13, "end_line": 13},
}


def changed(base: dict[str, Any], **top: Any) -> dict[str, Any]:
    out = copy.deepcopy(base)
    for key, value in top.items():
        if key.startswith("loc_"):
            out["location"][key[4:]] = value
        else:
            out[key] = value
    return out


def test_satisfied_by_a_finding_inside_the_range() -> None:
    assert satisfies(ENTRY, FINDING)


@pytest.mark.parametrize(
    "finding",
    [
        changed(FINDING, category="secret"),
        changed(FINDING, rule_id="B603"),
        changed(FINDING, loc_path="app/db.py"),
        changed(FINDING, loc_path="./app/handlers.py"),
        changed(FINDING, loc_start_line=15, loc_end_line=15),
        changed(FINDING, loc_start_line=10, loc_end_line=11),
        changed(FINDING, loc_start_line=None, loc_end_line=None),
        changed(FINDING, tools=["semgrep"]),
    ],
    ids=["category", "rule", "path", "path-prefix", "after", "before", "no-line", "tool"],
)
def test_a_single_difference_is_enough_to_not_match(finding: dict[str, Any]) -> None:
    assert not satisfies(ENTRY, finding)


def test_range_overlap_at_the_edges_counts() -> None:
    assert satisfies(ENTRY, changed(FINDING, loc_start_line=14, loc_end_line=20))
    assert satisfies(ENTRY, changed(FINDING, loc_start_line=5, loc_end_line=12))


def test_entry_without_lines_ignores_the_finding_lines() -> None:
    entry = {k: v for k, v in ENTRY.items() if k not in ("start_line", "end_line")}
    assert satisfies(entry, changed(FINDING, loc_start_line=None, loc_end_line=None))


def test_cve_matches_the_cve_list_or_the_rule_id_and_not_other_cves() -> None:
    entry = {"category": "dependency", "cve": "CVE-2020-1", "path": "p.lock", "tools": ["trivy"]}
    base = {
        "category": "dependency",
        "rule_id": "GHSA-x",
        "tools": ["osv-scanner", "trivy"],
        "cve": ["CVE-2020-1"],
        "location": {"path": "p.lock"},
    }
    assert satisfies(entry, base)
    assert satisfies(entry, changed(base, cve=[], rule_id="CVE-2020-1"))
    assert not satisfies(entry, changed(base, cve=["CVE-2020-2"]))


def test_missing_lists_only_unsatisfied_entries_and_extra_findings_are_fine() -> None:
    other = {**ENTRY, "rule_id": "B999"}
    extra = changed(FINDING, rule_id="B404")
    assert missing([ENTRY, other], [FINDING, extra]) == [other]
    assert matching(ENTRY, [FINDING, extra]) == [FINDING]


def test_describe_is_readable() -> None:
    assert describe(ENTRY) == "sast/B602@app/handlers.py:12-14"


def test_a_position_in_evidence_occurrences_counts_but_only_with_the_same_path() -> None:
    """ADR-0008: stesso segreto in piu' commit = un finding; la riga in HEAD e' un'occorrenza."""
    primary = changed(FINDING, loc_start_line=3, loc_end_line=3)
    assert not satisfies(ENTRY, primary)
    here = {"path": "app/handlers.py", "start_line": 12, "end_line": 12}
    other = {"path": "app/db.py", "start_line": 12, "end_line": 12}
    assert satisfies(ENTRY, {**primary, "evidence": {"occurrences": [other, here]}})
    assert not satisfies(ENTRY, {**primary, "evidence": {"occurrences": [other]}})


def test_ignore_lines_relaxes_only_the_lines() -> None:
    no_line = changed(FINDING, loc_start_line=None, loc_end_line=None)
    assert not satisfies(ENTRY, no_line)
    assert satisfies(ENTRY, no_line, ignore_lines=True)
    assert not satisfies(ENTRY, changed(no_line, loc_path="app/db.py"), ignore_lines=True)
    assert not satisfies(ENTRY, changed(no_line, rule_id="B1"), ignore_lines=True)
