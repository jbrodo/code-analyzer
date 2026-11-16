"""Controlli strutturali sugli attesi delle fixture (F-02, F-03; F-02 della Fase 2).

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
# Fase 2 (F-02): qualita' e IaC. Fuori da FIXTURES finche' i plugin non esistono, perche' gli E2E
# della Fase 1 pretendono che ogni atteso sia rilevato; li collega T-03.
PHASE2_FIXTURES = ("quality-python", "quality-js-ts", "iac-app")
ALL_FIXTURES = FIXTURES + PHASE2_FIXTURES
PHASE2_TOOLS = {
    "quality-python": {"ruff"},
    "quality-js-ts": {"eslint"},
    "iac-app": {"checkov", "hadolint", "trivy"},
}
DISABLED_BANDIT_RULES = {"B105", "B106", "B107"}  # ADR-0012


def load(fixture: str) -> dict[str, Any]:
    return yaml.safe_load((REPOS / fixture / "expected-findings.yaml").read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def validator() -> Draft202012Validator:
    import json

    return Draft202012Validator(json.loads(SCHEMA.read_text(encoding="utf-8")))


@pytest.mark.parametrize("fixture", ALL_FIXTURES)
def test_expected_findings_match_the_schema(fixture: str, validator: Draft202012Validator) -> None:
    errors = [e.message for e in validator.iter_errors(load(fixture))]
    assert errors == []


@pytest.mark.parametrize("fixture", ALL_FIXTURES)
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


@pytest.mark.parametrize("fixture", ALL_FIXTURES)
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
    for fixture in ALL_FIXTURES:
        assert not (REPOS / fixture / ".code-analyzer.yml").exists()


@pytest.mark.parametrize("fixture", PHASE2_FIXTURES)
def test_phase2_fixture_covers_its_tools_with_one_tool_per_entry(fixture: str) -> None:
    """Ogni voce nomina un solo strumento: la stessa regola non esiste in due motori diversi."""
    entries = load(fixture)["expected"]
    assert all(len(e["tools"]) == 1 for e in entries)
    assert {e["tools"][0] for e in entries} == PHASE2_TOOLS[fixture]


@pytest.mark.parametrize("fixture", ["quality-python", "quality-js-ts"])
def test_quality_fixture_has_a_clean_file_and_metric_rules(fixture: str) -> None:
    entries = load(fixture)["expected"]
    assert {e["category"] for e in entries} == {"quality"}
    clean = [p for p in (REPOS / fixture).rglob("clean.*") if p.is_file()]
    assert clean and not {e["path"] for e in entries} & {
        p.relative_to(REPOS / fixture).as_posix() for p in clean
    }
    metric_rules = {"C901", "PLR0913", "complexity", "max-params", "max-depth"}
    assert {e["rule_id"] for e in entries} & metric_rules


def test_iac_fixture_covers_the_three_formats() -> None:
    paths = {e["path"] for e in load("iac-app")["expected"]}
    assert paths == {"Dockerfile", "k8s/pod.yaml", "terraform/main.tf"}


def test_correlation_groups_join_different_tools_on_the_same_file() -> None:
    """F-02: almeno un problema rilevato sia da trivy sia da checkov, per la correlazione."""
    groups: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for entry in load("iac-app")["expected"]:
        if "correlation" in entry:
            groups.setdefault((entry["correlation"], entry["path"]), []).append(entry)
    assert groups
    for (label, path), members in groups.items():
        tools = [m["tools"][0] for m in members]
        assert len(tools) == len(set(tools)) >= 2, f"{label} su {path}: {tools}"
        assert len({m["rule_id"] for m in members}) == len(members)
    by_tools = {frozenset(m["tools"][0] for m in members) for members in groups.values()}
    assert any({"trivy", "checkov"} <= tools for tools in by_tools)
    assert any({"trivy", "checkov", "hadolint"} == tools for tools in by_tools)


def test_correlation_is_used_only_where_a_group_is_expected() -> None:
    for fixture in ALL_FIXTURES:
        if fixture != "iac-app":
            assert not any("correlation" in e for e in load(fixture)["expected"])
