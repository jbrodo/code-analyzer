"""F-01: lo schema degli attesi accetta istanze valide e rifiuta quelle non valide."""

import json
from pathlib import Path
from typing import Any

import pytest

jsonschema = pytest.importorskip("jsonschema")  # dipendenza di sviluppo da aggiungere

SCHEMA_PATH = Path(__file__).parents[1] / "fixtures" / "expected-findings.schema.json"

VALID: dict[str, Any] = {
    "version": 1,
    "expected": [
        {
            "category": "sast",
            "rule_id": "B602",
            "path": "app/run.py",
            "start_line": 10,
            "end_line": 12,
            "tools": ["bandit", "semgrep"],
        },
        {
            "category": "dependency",
            "cve": "CVE-2021-44228",
            "path": "requirements.txt",
            "tools": ["osv-scanner", "trivy"],
        },
    ],
}


def _validator() -> Any:
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    jsonschema.Draft202012Validator.check_schema(schema)
    return jsonschema.Draft202012Validator(schema)


def _with(**changes: Any) -> dict[str, Any]:
    item = {**VALID["expected"][0], **changes}
    return {"version": 1, "expected": [item]}


def test_valid_example_is_accepted() -> None:
    _validator().validate(VALID)


@pytest.mark.parametrize(
    "instance",
    [
        _with(fingerprint="sha256:" + "a" * 64),  # il fingerprint non e una chiave
        _with(tools=[]),
        _with(tools=["bandit", "bandit"]),
        _with(path="/etc/passwd"),
        _with(path="../outside.py"),
        _with(start_line=0),
        _with(category="unknown"),
        _with(correlation="Dockerfile Latest"),  # solo minuscole, cifre, punti e trattini
        {"version": 1, "expected": [{"category": "sast", "path": "a.py", "tools": ["bandit"]}]},
        {"version": 1, "expected": [{**VALID["expected"][1], "cve": "GHSA-xxxx-xxxx-xxxx"}]},
    ],
    ids=[
        "fingerprint",
        "no-tools",
        "duplicate-tools",
        "absolute-path",
        "dotdot-path",
        "line-zero",
        "bad-category",
        "bad-correlation",
        "no-rule-or-cve",
        "not-a-cve",
    ],
)
def test_invalid_examples_are_rejected(instance: dict[str, Any]) -> None:
    assert not _validator().is_valid(instance)


def test_correlation_label_is_accepted() -> None:
    _validator().validate(_with(correlation="dockerfile.latest-tag"))


def test_end_line_requires_start_line() -> None:
    item = {k: v for k, v in VALID["expected"][0].items() if k != "start_line"}
    assert not _validator().is_valid({"version": 1, "expected": [item]})
