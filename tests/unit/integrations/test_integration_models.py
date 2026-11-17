"""C-09: i modelli di commento, check run e codequality fanno rispettare i limiti del provider."""

from typing import Any

import pytest
from pydantic import ValidationError

from ca_integrations import limits
from ca_integrations.models import (
    Annotation,
    CheckRun,
    CheckRunOutput,
    CodeQualityIssue,
    PullRequestComment,
)

MARKER = "<!-- code-analyzer:42 -->"


def comment(**changes: Any) -> dict[str, Any]:
    base = {
        "marker": MARKER,
        "body": f"{MARKER}\n# Code Analyzer\n",
        "findings_shown": 1,
        "findings_hidden": 0,
    }
    return {**base, **changes}


def annotation(**changes: Any) -> dict[str, Any]:
    base = {
        "path": "app/a.py",
        "start_line": 3,
        "end_line": 4,
        "level": "warning",
        "title": "t",
        "message": "m",
    }
    return {**base, **changes}


def test_valid_comment_and_check_run() -> None:
    PullRequestComment(**comment())
    run = CheckRun(
        conclusion="failure",
        output=CheckRunOutput(title="Code Analyzer", summary="2 nuovi", annotations=[annotation()]),
    )
    assert run.output.annotations[0].level.value == "warning"


@pytest.mark.parametrize(
    "changes",
    [
        {"body": "senza marcatore"},
        {"body": f"{MARKER}\n{MARKER}\n"},  # il marcatore compare una volta sola
        {"body": f"{MARKER}\n" + "x" * limits.GITHUB_COMMENT_MAX_CHARS},
        {"marker": "<!-- altro -->"},
        {"findings_shown": -1},
    ],
    ids=["no-marker", "twice", "too-long", "bad-marker", "negative"],
)
def test_invalid_comments_are_rejected(changes: dict[str, Any]) -> None:
    with pytest.raises(ValidationError):
        PullRequestComment(**comment(**changes))


def test_a_finding_text_cannot_forge_the_marker() -> None:
    forged = f"{MARKER}\n- titolo con <!-- code-analyzer:7 --> dentro\n"
    with pytest.raises(ValidationError):
        PullRequestComment(**comment(body=forged))


@pytest.mark.parametrize(
    "changes",
    [
        {"end_line": 2},
        {"start_line": 0},
        {"level": "error"},
        {"path": "a\n::error::b"},
        {"path": ""},
        {"title": "x" * (limits.GITHUB_ANNOTATION_TITLE_MAX + 1)},
        {"message": ""},
        {"message": "é" * (limits.GITHUB_ANNOTATION_MESSAGE_MAX_BYTES // 2 + 1)},
        {"extra": 1},
    ],
)
def test_invalid_annotations_are_rejected(changes: dict[str, Any]) -> None:
    with pytest.raises(ValidationError):
        Annotation(**annotation(**changes))


def test_check_run_limits() -> None:
    too_many = [annotation() for _ in range(limits.GITHUB_ANNOTATIONS_PER_REQUEST + 1)]
    with pytest.raises(ValidationError):
        CheckRunOutput(title="t", summary="s", annotations=too_many)
    with pytest.raises(ValidationError):
        CheckRunOutput(title="t", summary="x" * (limits.GITHUB_CHECK_SUMMARY_MAX_CHARS + 1))
    with pytest.raises(ValidationError):
        CheckRunOutput(title="", summary="s")
    with pytest.raises(ValidationError):
        CheckRun(conclusion="cancelled", output=CheckRunOutput(title="t", summary="s"))


def issue(**changes: Any) -> dict[str, Any]:
    base = {
        "description": "Cyclic dependency",
        "check_name": "ca.arch.cyclic-dependency",
        "fingerprint": "a" * 32,
        "severity": "major",
        "location": {"path": "app/a.py", "lines": {"begin": 1}},
    }
    return {**base, **changes}


def test_codequality_issue() -> None:
    CodeQualityIssue(**issue())
    for severity in limits.CODEQUALITY_SEVERITIES:
        CodeQualityIssue(**issue(severity=severity))
    for bad in ({"severity": "high"}, {"fingerprint": "xyz"}, {"description": ""}):
        with pytest.raises(ValidationError):
            CodeQualityIssue(**issue(**bad))
