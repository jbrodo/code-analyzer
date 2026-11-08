import pytest
from conftest import Json, Mutation, errors_of, make_validator, mutated

FP = "sha256:" + "a" * 64
NOW = "2026-01-01T00:00:00Z"
VALIDATOR = make_validator("finding")

MINIMAL: Json = {
    "id": "f1",
    "fingerprint": FP,
    "category": "sast",
    "rule_id": "B602",
    "tool": "bandit",
    "tools": ["bandit"],
    "title": "t",
    "message": "m",
    "location": {"repository": "repo"},
    "first_seen": NOW,
    "last_seen": NOW,
}
FULL: Json = mutated(
    MINIMAL,
    lambda i: i.update(
        cwe=["CWE-78"],
        cve=["CVE-2024-0001"],
        level="alto",
        level_source="tool_severity",
        score=87.5,
        impact={"g": 0, "p": 0.5, "e": 1, "c": 0.25, "variant": "A", "evidence": {"x": 1}},
        status="in_corso",
        owner="team-a",
        due_date=NOW,
        license_spdx="MIT",
        evidence={"anything": ["goes"]},
        location={
            "repository": "repo",
            "path": "a.py",
            "start_line": 1,
            "end_line": 3,
            "commit": "abc",
            "purl": "pkg:pypi/x@1",
            "dependency_path": ["a", "b"],
        },
    ),
)


def _pop(key: str) -> Mutation:
    return lambda i: i.pop(key)


def _set(key: str, value: object) -> Mutation:
    return lambda i: i.__setitem__(key, value)


VALID = {
    "minimal": MINIMAL,
    "full": FULL,
    "score-lower-bound": mutated(MINIMAL, _set("score", 0)),
    "score-upper-bound": mutated(MINIMAL, _set("score", 100)),
    "null-optionals": mutated(
        MINIMAL, _set("level", None), _set("score", None), _set("impact", None)
    ),
    **{
        f"category-{c}": mutated(MINIMAL, _set("category", c))
        for c in (
            "quality",
            "architecture",
            "test",
            "sast",
            "dependency",
            "license",
            "secret",
            "iac",
            "health",
        )
    },
    **{
        f"level-{lv}": mutated(MINIMAL, _set("level", lv))
        for lv in ("critico", "alto", "medio", "basso")
    },
}
INVALID = {
    **{
        f"missing-{k}": mutated(MINIMAL, _pop(k))
        for k in (
            "id",
            "fingerprint",
            "category",
            "rule_id",
            "tool",
            "tools",
            "title",
            "message",
            "location",
            "first_seen",
            "last_seen",
        )
    },
    "unknown-top-level-key": mutated(MINIMAL, _set("extra", 1)),
    "fingerprint-no-prefix": mutated(MINIMAL, _set("fingerprint", "a" * 64)),
    "fingerprint-uppercase": mutated(MINIMAL, _set("fingerprint", "sha256:" + "A" * 64)),
    "fingerprint-short": mutated(MINIMAL, _set("fingerprint", "sha256:" + "a" * 63)),
    "category-unknown": mutated(MINIMAL, _set("category", "other")),
    "level-unknown": mutated(MINIMAL, _set("level", "urgent")),
    "level-source-unknown": mutated(MINIMAL, _set("level_source", "magic")),
    "status-unknown": mutated(MINIMAL, _set("status", "closed")),
    "tools-empty": mutated(MINIMAL, _set("tools", [])),
    "tools-duplicates": mutated(MINIMAL, _set("tools", ["bandit", "bandit"])),
    "score-below-0": mutated(MINIMAL, _set("score", -0.1)),
    "score-above-100": mutated(MINIMAL, _set("score", 100.1)),
    "location-without-repository": mutated(MINIMAL, _set("location", {"path": "a"})),
    "location-unknown-key": mutated(MINIMAL, _set("location", {"repository": "r", "x": 1})),
    "location-start-line-zero": mutated(
        MINIMAL, _set("location", {"repository": "r", "start_line": 0})
    ),
    "location-end-line-zero": mutated(
        MINIMAL, _set("location", {"repository": "r", "end_line": 0})
    ),
    "impact-factor-above-1": mutated(
        MINIMAL, _set("impact", {"g": 1.01, "p": 0, "e": 0, "c": 0, "variant": "A"})
    ),
    "impact-factor-below-0": mutated(
        MINIMAL, _set("impact", {"g": 0, "p": -0.01, "e": 0, "c": 0, "variant": "A"})
    ),
    "impact-variant-C": mutated(
        MINIMAL, _set("impact", {"g": 0, "p": 0, "e": 0, "c": 0, "variant": "C"})
    ),
    "impact-missing-factor": mutated(
        MINIMAL, _set("impact", {"g": 0, "p": 0, "e": 0, "variant": "A"})
    ),
    "impact-unknown-key": mutated(
        MINIMAL, _set("impact", {"g": 0, "p": 0, "e": 0, "c": 0, "variant": "A", "z": 1})
    ),
    "cwe-not-array": mutated(MINIMAL, _set("cwe", "CWE-78")),
    "tools-item-not-string": mutated(MINIMAL, _set("tools", [1])),
}


@pytest.mark.parametrize("instance", VALID.values(), ids=VALID.keys())
def test_valid_finding_is_accepted(instance: Json) -> None:
    assert errors_of(VALIDATOR, instance) == []


@pytest.mark.parametrize("instance", INVALID.values(), ids=INVALID.keys())
def test_invalid_finding_is_rejected(instance: Json) -> None:
    assert errors_of(VALIDATOR, instance) != []


def test_non_object_is_rejected() -> None:
    assert errors_of(VALIDATOR, [MINIMAL]) != []
