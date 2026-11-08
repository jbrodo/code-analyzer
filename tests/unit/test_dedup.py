from datetime import UTC, datetime
from typing import Any

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from ca_core.dedup import deduplicate
from ca_core.fingerprint import fingerprint_code, fingerprint_dependency
from ca_core.models.finding import Category, Finding, Location

T0 = datetime(2026, 1, 1, tzinfo=UTC)
T1 = datetime(2026, 1, 2, tzinfo=UTC)
SOURCE = "a\nsubprocess.run(x, shell=True)\nb"


def finding(
    tool: str = "bandit",
    fp: str = "sha256:" + "a" * 64,
    *,
    category: Category = Category.SAST,
    path: str = "app/run.py",
    line: int = 2,
    title: str = "t",
    cve: tuple[str, ...] = (),
    seen: datetime = T0,
    evidence: Any = 1,
) -> Finding:
    return Finding(
        id=fp,
        fingerprint=fp,
        category=category,
        rule_id="r",
        tool=tool,
        tools=[tool],
        title=title,
        message="m",
        location=Location(repository="repo", path=path, start_line=line, end_line=line),
        cve=list(cve),
        evidence={tool: {"e": evidence}},
        first_seen=seen,
        last_seen=seen,
    )


def test_unique_fingerprints_are_returned_ordered_and_unchanged() -> None:
    a, b = finding(fp="sha256:" + "b" * 64), finding(fp="sha256:" + "a" * 64)

    assert deduplicate([a, b]) == [b, a]
    assert deduplicate([]) == []


def test_same_fingerprint_fuses_tools_evidence_and_occurrences() -> None:
    fp = fingerprint_dependency(vuln_ids=["CVE-2024-1"], purl="pkg:pypi/x@1")
    osv = finding("osv-scanner", fp, category=Category.DEPENDENCY, path="a/lock", line=1)
    trivy = finding(
        "trivy", fp, category=Category.DEPENDENCY, path="b/lock", line=1, cve=("CVE-2024-1",)
    )
    other = finding(
        "trivy", fp, category=Category.DEPENDENCY, path="a/lock", line=1, seen=T1, evidence=2
    )

    (merged,) = deduplicate([trivy, other, osv])

    assert merged.tools == ["osv-scanner", "trivy"] and merged.tool == "osv-scanner"
    assert merged.cve == ["CVE-2024-1"]
    assert set(merged.evidence) == {"osv-scanner", "trivy", "occurrences"}
    assert merged.evidence["trivy"] == {"e": 1}  # rappresentante canonico minimo del tool
    paths = [o["path"] for o in merged.evidence["occurrences"]]
    assert paths == ["a/lock", "b/lock"]  # senza duplicati
    assert (merged.first_seen, merged.last_seen) == (T0, T1)
    assert merged.id == merged.fingerprint == fp


def test_sast_of_different_scanners_on_the_same_line_do_not_fuse() -> None:
    def code_fp(tool: str) -> str:
        return fingerprint_code(
            rule_id="B602", tool=tool, path="app/run.py", source=SOURCE, start_line=2
        )

    both = [finding("bandit", code_fp("bandit")), finding("semgrep", code_fp("semgrep"))]

    assert len(deduplicate(both)) == 2


def test_reserved_occurrences_key_must_be_a_list_of_positions() -> None:
    bad = finding()
    bad.evidence["occurrences"] = "x"

    with pytest.raises(ValueError, match="occurrences"):
        deduplicate([bad, finding(tool="semgrep")])


FPS = ["sha256:" + c * 64 for c in "abc"]
dates = st.sampled_from([T0, T1, datetime(2026, 3, 1, tzinfo=UTC)])
findings = st.builds(
    finding,
    tool=st.sampled_from(["bandit", "semgrep", "trivy"]),
    fp=st.sampled_from(FPS),
    category=st.sampled_from([Category.SAST, Category.DEPENDENCY]),
    path=st.sampled_from(["a.py", "b.py"]),
    line=st.integers(1, 3),
    title=st.sampled_from(["x", "y"]),
    cve=st.lists(st.sampled_from(["CVE-1", "CVE-2"]), max_size=2).map(tuple),
    seen=dates,
    evidence=st.integers(0, 2),
)


@settings(max_examples=200, deadline=None)
@given(xs=st.lists(findings, max_size=8))
def test_idempotent_with_unique_sorted_fingerprints(xs: list[Finding]) -> None:
    once = deduplicate(xs)

    assert deduplicate(once) == once
    fingerprints = [f.fingerprint for f in once]
    assert fingerprints == sorted(set(f.fingerprint for f in xs))
    for merged in once:
        group = [f for f in xs if f.fingerprint == merged.fingerprint]
        assert set(merged.tools) == {f.tool for f in group}
        assert merged.first_seen == min(f.first_seen for f in group)
        assert merged.last_seen == max(f.last_seen for f in group)


@settings(max_examples=200, deadline=None)
@given(xs=st.lists(findings, max_size=8), data=st.data())
def test_independent_of_input_order(xs: list[Finding], data: st.DataObject) -> None:
    shuffled = data.draw(st.permutations(xs))

    assert deduplicate(shuffled) == deduplicate(xs)
