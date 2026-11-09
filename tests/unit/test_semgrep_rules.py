"""P-09: controlli statici sulle regole Semgrep del progetto (nessuno scanner, ADR-0015)."""

from pathlib import Path
from typing import Any

import pytest
import yaml

SEMGREP = Path(__file__).resolve().parents[2] / "packages/ca-plugins/src/ca_plugins/builtin/semgrep"
CASES = Path(__file__).resolve().parents[1] / "integration/semgrep_rule_cases"
RULE_FILES = sorted((SEMGREP / "rules").glob("*.yaml"))
SEVERITIES = {"INFO", "WARNING", "ERROR"}


def all_rules() -> list[dict[str, Any]]:
    return [r for f in RULE_FILES for r in yaml.safe_load(f.read_text(encoding="utf-8"))["rules"]]


def test_rule_files_exist() -> None:
    assert {f.name for f in RULE_FILES} == {"javascript.yaml", "python.yaml"}


def test_ids_are_unique_and_prefixed() -> None:
    ids = [r["id"] for r in all_rules()]
    assert len(ids) == len(set(ids)) and all(i.startswith("ca-") for i in ids)


@pytest.mark.parametrize("rule", all_rules(), ids=lambda r: r["id"])
def test_rule_shape(rule: dict[str, Any]) -> None:
    assert rule["severity"] in SEVERITIES and rule["languages"]
    assert "$" not in rule["message"]  # nessuna metavariabile interpolata (niente snippet)
    assert rule["metadata"]["category"] == "sast" and rule["metadata"]["cwe"].startswith("CWE-")
    assert "fix" not in rule  # il rilevamento non modifica il codice


@pytest.mark.parametrize("rule", all_rules(), ids=lambda r: r["id"])
def test_every_rule_has_a_positive_and_a_negative_case(rule: dict[str, Any]) -> None:
    cases = "".join(p.read_text(encoding="utf-8") for p in (CASES).iterdir())
    assert f"ruleid: {rule['id']}" in cases and f"ok: {rule['id']}" in cases


def test_no_registry_and_no_copied_license_markers() -> None:
    for path in [*RULE_FILES, *(CASES).iterdir()]:
        text = path.read_text(encoding="utf-8").lower()
        assert "semgrep.dev" not in text and "config auto" not in text, path.name
        assert "license" not in text and "spdx" not in text, path.name  # nessuna licenza dichiarata
