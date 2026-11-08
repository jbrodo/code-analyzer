"""K-08 (filtro `paths.exclude`) e K-09 (eccezioni)."""

from datetime import UTC, date, datetime

import pytest
from builders import finding

from ca_core.fakes import FixedClock
from ca_core.models.config import ConfigException
from ca_core.models.finding import Category, Status
from ca_core.pipeline.exceptions import apply_exceptions
from ca_core.pipeline.exclusions import (
    DEFAULT_EXCLUDES,
    apply_exclusions,
    effective_exclusions,
    is_excluded,
)


@pytest.mark.parametrize(
    ("path", "pattern", "expected"),
    [
        ("node_modules/a/b.js", "**/node_modules", True),
        ("web/node_modules/a.js", "**/node_modules", True),
        ("src/node_modules_x/a.js", "**/node_modules", False),
        ("tests/fixtures/x.py", "tests/fixtures/", True),
        ("tests/fixtures", "tests/fixtures/", True),
        ("tests/other.py", "tests/fixtures/", False),
        ("a/b/c.py", "a/**/c.py", True),
        ("a/c.py", "a/**/c.py", True),
        ("a/b.py", "a/*.py", True),
        ("a/x/b.py", "a/*.py", False),
        ("a/b.py", "a/?.py", True),
        ("A/b.py", "a/b.py", False),
        ("a.b", "a.b", True),
        ("axb", "a.b", False),
    ],
)
def test_glob_semantics(path: str, pattern: str, expected: bool) -> None:
    assert is_excluded(path, [pattern]) is expected


def test_defaults_cover_adr_0014_and_output_artifacts() -> None:
    for path in (
        "node_modules/x.js",
        ".venv/lib/x.py",
        "dist/x.js",
        ".git/config",
        "code-analyzer.report.json",
        "out/code-analyzer.sarif",
    ):
        assert is_excluded(path, DEFAULT_EXCLUDES), path


def test_filter_excludes_defaults_and_user_patterns_but_keeps_pathless() -> None:
    findings = [
        finding("a", path="node_modules/x.js"),
        finding("b", path="tests/fixtures/v.py"),
        finding("c", path="src/ok.py"),
        finding("d", path=None, category=Category.DEPENDENCY),
    ]

    kept = apply_exclusions(findings, ["tests/fixtures/"])

    assert [f.rule_id for f in kept] == ["r-c", "r-d"]


def test_git_exclusion_does_not_apply_to_gitleaks_but_user_patterns_do() -> None:
    secret = finding("s", category=Category.SECRET, tool="gitleaks", path=".git/x")
    other = finding("o", path=".git/x")

    assert apply_exclusions([secret, other], []) == [secret]
    assert apply_exclusions([secret], [".git"]) == []


def test_effective_exclusions_are_reported_without_duplicates() -> None:
    assert effective_exclusions(["x/", "**/dist"]) == [*DEFAULT_EXCLUDES, "x/"]


# --- K-09 ------------------------------------------------------------------------------------


def exception(fp: str, expires: date, reason: str = "r") -> ConfigException:
    return ConfigException(fingerprint=fp, reason=reason, expires=expires, approved_by="@sec")


def clock(day: int, hour: int = 12) -> FixedClock:
    return FixedClock(datetime(2026, 6, day, hour, tzinfo=UTC))


def test_active_exception_accepts_the_finding_and_is_reported() -> None:
    f = finding("a")

    result = apply_exceptions([f], [exception(f.fingerprint, date(2026, 12, 31))], clock(1))

    assert result.findings[0].status is Status.ACCEPTED
    assert [e.fingerprint for e in result.applied] == [f.fingerprint]
    assert result.warnings == []


def test_boundary_expiry_day_is_still_valid_and_next_day_is_not() -> None:
    f = finding("a")
    exc = exception(f.fingerprint, date(2026, 6, 10))

    on_day = apply_exceptions([f], [exc], clock(10, hour=23))
    after = apply_exceptions([f], [exc], clock(11, hour=0))

    assert on_day.findings[0].status is Status.ACCEPTED
    assert after.findings[0].status is Status.OPEN and after.applied == []
    assert [w.code for w in after.warnings] == ["exception-expired"]
    assert after.warnings[0].subject == f.fingerprint


def test_clock_is_read_in_utc() -> None:
    f = finding("a")
    tz_clock = FixedClock(datetime.fromisoformat("2026-06-10T23:30:00-05:00"))  # 11 giugno UTC

    result = apply_exceptions([f], [exception(f.fingerprint, date(2026, 6, 10))], tz_clock)

    assert result.findings[0].status is Status.OPEN


def test_unmatched_exception_is_not_applied_and_expired_one_still_warns() -> None:
    f = finding("a")
    other = finding("b")

    result = apply_exceptions(
        [f],
        [
            exception(other.fingerprint, date(2026, 12, 1)),
            exception(other.fingerprint, date(2026, 1, 1)),
        ],
        clock(1),
    )

    assert result.findings == [f] and result.applied == []
    assert [w.code for w in result.warnings] == ["exception-expired"]


def test_earliest_valid_exception_wins_and_input_is_not_mutated() -> None:
    f = finding("a")
    late = exception(f.fingerprint, date(2026, 12, 1), "late")
    early = exception(f.fingerprint, date(2026, 7, 1), "early")

    result = apply_exceptions([f], [late, early], clock(1))

    assert [e.reason for e in result.applied] == ["early"]
    assert f.status is Status.OPEN
    assert apply_exceptions([f], [early, late], clock(1)) == result
