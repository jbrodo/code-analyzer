"""K-11: livelli provvisori (IPOTESI D-0009-A) e ordinamento."""

from typing import Any

import pytest
from builders import finding

from ca_core.models.finding import Category, Level, LevelSource
from ca_core.scoring.levels import DEFAULT_LEVEL_TABLE, LevelTable, assign_levels, sort_findings


def dep(score: float | None, version: str = "3.1", tool: str = "osv-scanner") -> Any:
    evidence = (
        {} if score is None else {"cvss": {"version": version, "vector": "v", "score": score}}
    )
    return finding("d", category=Category.DEPENDENCY, tool=tool, path=None, evidence=evidence)


@pytest.mark.parametrize(
    ("score", "level"),
    [
        (10.0, Level.CRITICAL),
        (9.0, Level.CRITICAL),
        (8.9, Level.HIGH),
        (7.0, Level.HIGH),
        (6.9, Level.MEDIUM),
        (4.0, Level.MEDIUM),
        (3.9, Level.LOW),
        (0.0, Level.LOW),
    ],
)
def test_cvss_bands_are_half_open(score: float, level: Level) -> None:
    [out] = assign_levels([dep(score)])

    assert (out.level, out.level_source) == (level, LevelSource.TOOL_SEVERITY)
    assert out.impact is None and out.score is None


def test_dependency_without_cvss_is_high_by_default() -> None:
    [out] = assign_levels([dep(None)])

    assert (out.level, out.level_source) == (Level.HIGH, LevelSource.DEFAULT)


def test_malformed_cvss_counts_as_missing() -> None:
    bad = finding(
        "d", category=Category.DEPENDENCY, evidence={"cvss": {"score": "9", "version": "3.1"}}
    )

    assert assign_levels([bad])[0].level_source is LevelSource.DEFAULT


def test_most_recent_cvss_version_wins_over_higher_score() -> None:
    f = finding(
        "d",
        category=Category.DEPENDENCY,
        tool="a",
        evidence={"cvss": {"version": "2.0", "score": 9.8}},
    )
    data = f.model_dump()
    data.update(
        tools=["a", "b"], evidence={**f.evidence, "b": {"cvss": {"version": "3.1", "score": 5.0}}}
    )

    out = assign_levels([type(f).model_validate(data)])[0]

    assert out.level is Level.MEDIUM


@pytest.mark.parametrize(
    ("evidence", "level", "source"),
    [
        ({"tool_severity": "CRITICAL"}, Level.CRITICAL, LevelSource.TOOL_SEVERITY),
        ({"tool_severity": "high"}, Level.HIGH, LevelSource.TOOL_SEVERITY),
        ({"tool_severity": "medium"}, Level.MEDIUM, LevelSource.TOOL_SEVERITY),
        ({"tool_severity": "low"}, Level.LOW, LevelSource.TOOL_SEVERITY),
        ({"sarif_level": "error"}, Level.HIGH, LevelSource.TOOL_SEVERITY),
        ({"sarif_level": "warning"}, Level.MEDIUM, LevelSource.TOOL_SEVERITY),
        ({"sarif_level": "note"}, Level.LOW, LevelSource.TOOL_SEVERITY),
        ({"tool_severity": "low", "sarif_level": "error"}, Level.LOW, LevelSource.TOOL_SEVERITY),
        ({"tool_severity": "weird", "sarif_level": "note"}, Level.LOW, LevelSource.TOOL_SEVERITY),
        ({}, Level.MEDIUM, LevelSource.DEFAULT),
        ({"tool_severity": "weird"}, Level.MEDIUM, LevelSource.DEFAULT),
    ],
)
@pytest.mark.parametrize("category", [Category.SAST, Category.IAC])
def test_code_severity_table(
    category: Category, evidence: dict[str, str], level: Level, source: LevelSource
) -> None:
    [out] = assign_levels([finding("s", category=category, evidence=evidence)])

    assert (out.level, out.level_source) == (level, source)


def test_secret_is_high_and_health_medium_by_policy() -> None:
    secret = finding("s", category=Category.SECRET, tool="gitleaks")
    health = finding("h", category=Category.HEALTH, path=None)

    a, b = assign_levels([secret, health])

    assert (a.level, a.level_source) == (Level.HIGH, LevelSource.POLICY)
    assert (b.level, b.level_source) == (Level.MEDIUM, LevelSource.POLICY)


def test_existing_level_is_kept_and_assignment_is_idempotent() -> None:
    kept = finding("l", category=Category.LICENSE, level=Level.CRITICAL)
    once = assign_levels([kept, dep(8.0)])

    assert once[0].level is Level.CRITICAL and once[0].level_source is None
    assert assign_levels(once) == once


def test_table_is_data_not_logic() -> None:
    table = LevelTable(
        dependency_without_cvss=Level.LOW, cvss_bands=((5.0, Level.CRITICAL), (0.0, Level.LOW))
    )

    assert assign_levels([dep(None)], table)[0].level is Level.LOW
    assert assign_levels([dep(5.0)], table)[0].level is Level.CRITICAL
    assert DEFAULT_LEVEL_TABLE.dependency_without_cvss is Level.HIGH


def test_sort_by_level_category_fingerprint_independent_of_input_order() -> None:
    items = assign_levels(
        [
            finding("1", category=Category.SAST, evidence={"tool_severity": "low"}),
            finding("2", category=Category.SECRET, tool="gitleaks"),
            finding("3", category=Category.SAST, evidence={"tool_severity": "critical"}),
            finding("4", category=Category.DEPENDENCY, path=None),
            finding("5", category=Category.HEALTH, path=None),
        ]
    )
    expected = sort_findings(items)

    assert [f.level for f in expected] == [
        Level.CRITICAL,
        Level.HIGH,
        Level.HIGH,
        Level.MEDIUM,
        Level.LOW,
    ]
    assert [f.category for f in expected[1:3]] == [Category.DEPENDENCY, Category.SECRET]
    assert sort_findings(reversed(items)) == expected
    assert sort_findings(sort_findings(items)) == expected


@pytest.mark.parametrize(
    ("severity", "level"),
    [
        ("critical", Level.MEDIUM),
        ("high", Level.MEDIUM),
        ("medium", Level.MEDIUM),
        ("low", Level.LOW),
    ],
)
def test_quality_findings_never_exceed_medium(severity: str, level: Level) -> None:
    """ADR-0026: i problemi di qualità non bloccano il gate prima del Gate 2."""
    item = finding(
        "q", category=Category.QUALITY, tool="ruff", evidence={"tool_severity": severity}
    )
    [out] = assign_levels([item])
    assert (out.level, out.level_source) == (level, LevelSource.TOOL_SEVERITY)


def test_quality_without_severity_is_medium_by_default() -> None:
    [out] = assign_levels([finding("q", category=Category.QUALITY, tool="ruff")])
    assert (out.level, out.level_source) == (Level.MEDIUM, LevelSource.DEFAULT)


def test_sast_is_not_capped() -> None:
    item = finding("s", category=Category.SAST, tool="x", evidence={"tool_severity": "high"})
    assert assign_levels([item])[0].level is Level.HIGH


def test_architecture_findings_are_low_with_the_default_source() -> None:
    """ADR-0020: nessuno smell deve bloccare una CI prima del Gate 2."""
    item = finding("g", category=Category.ARCHITECTURE, tool="ca-graph", path="shop/a.py")
    [out] = assign_levels([item])
    assert (out.level, out.level_source) == (Level.LOW, LevelSource.DEFAULT)
