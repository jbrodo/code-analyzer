"""Controlli strutturali sugli attesi delle fixture (F-02, F-03).

Non eseguono scanner: verificano che `expected-findings.yaml` sia valido contro lo schema di F-01
e coerente con i file della fixture. Che ogni atteso sia davvero rilevato lo provano gli scanner
reali (task P e T-05).
"""

from pathlib import Path
from typing import Any

import pytest
import yaml
from jsonschema import Draft202012Validator

REPOS = Path(__file__).resolve().parent
SCHEMA = REPOS.parent / "expected-findings.schema.json"
RULES = REPOS.parents[2] / "packages/ca-plugins/src/ca_plugins/builtin/semgrep/rules"
FIXTURES = ("python-app", "js-ts-app")
DISABLED_BANDIT_RULES = {"B105", "B106", "B107"}  # ADR-0012


def load(fixture: str) -> dict[str, Any]:
    return yaml.safe_load((REPOS / fixture / "expected-findings.yaml").read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def validator() -> Draft202012Validator:
    import json

    return Draft202012Validator(json.loads(SCHEMA.read_text(encoding="utf-8")))


@pytest.mark.parametrize("fixture", FIXTURES)
def test_expected_findings_match_the_schema(fixture: str, validator: Draft202012Validator) -> None:
    errors = [e.message for e in validator.iter_errors(load(fixture))]
    assert errors == []


@pytest.mark.parametrize("fixture", FIXTURES)
def test_expected_paths_exist_and_line_ranges_fit_the_file(fixture: str) -> None:
    for entry in load(fixture)["expected"]:
        target = REPOS / fixture / entry["path"]
        assert target.is_file(), f"{fixture}: {entry['path']} non esiste"
        if "start_line" in entry:
            total = len(target.read_text(encoding="utf-8").splitlines())
            start = entry["start_line"]
            end = entry.get("end_line", start)
            assert 1 <= start <= end <= total, f"{fixture}: intervallo fuori da {entry['path']}"


@pytest.mark.parametrize("fixture", FIXTURES)
def test_no_expectation_on_disabled_bandit_rules(fixture: str) -> None:
    rules = {e.get("rule_id") for e in load(fixture)["expected"]}
    assert rules.isdisjoint(DISABLED_BANDIT_RULES)


@pytest.mark.parametrize("fixture", FIXTURES)
def test_expected_entries_are_unique(fixture: str) -> None:
    keys = [
        (e.get("rule_id") or e["cve"], e["path"], e.get("start_line"), e["category"])
        for e in load(fixture)["expected"]
    ]
    assert len(keys) == len(set(keys))


@pytest.mark.parametrize("fixture", FIXTURES)
def test_semgrep_expectations_use_project_rules_only(fixture: str) -> None:
    """P-09: ogni atteso di semgrep ha il `rule_id` di una regola del progetto (ADR-0015)."""
    rules = set()
    for rule_file in RULES.glob("*.yaml"):
        rules |= {r["id"] for r in yaml.safe_load(rule_file.read_text(encoding="utf-8"))["rules"]}
    semgrep = [e for e in load(fixture)["expected"] if "semgrep" in e["tools"]]
    assert semgrep and {e["rule_id"] for e in semgrep} <= rules
    assert all(e["category"] == "sast" and e["tools"] == ["semgrep"] for e in semgrep)


@pytest.mark.parametrize("fixture", FIXTURES)
def test_every_known_category_group_is_present(fixture: str) -> None:
    categories = {e["category"] for e in load(fixture)["expected"]}
    assert {"dependency", "iac", "license"} <= categories
    if fixture == "python-app":
        assert "sast" in categories


def test_license_policy_is_outside_the_scanned_trees() -> None:
    """Dentro una fixture, scancode rileverebbe gli SPDX della policy come licenze del progetto."""
    assert (REPOS / "license-policy.yml").is_file()
    for fixture in FIXTURES:
        assert not (REPOS / fixture / ".code-analyzer.yml").exists()
