"""C-09: i formati GitLab fissati (tag v15.2.5) e i limiti che `ca_integrations` dichiara.

Gli schemi si leggono da `schemas/vendor/` con `jsonschema`, senza importare `ca_core`: se i limiti
di `ca_integrations.limits` divergono dallo schema, il test fallisce.
"""

import hashlib
import json

import pytest
from conftest import SCHEMAS_DIR, Json, mutated
from jsonschema import Draft7Validator

from ca_integrations import limits

VENDOR = SCHEMAS_DIR / "vendor"
SCHEMAS = {
    "sast": VENDOR / "gitlab-sast-15.2.5.schema.json",
    "dependency_scanning": VENDOR / "gitlab-dependency-scanning-15.2.5.schema.json",
}
SCAN: Json = {
    "analyzer": {
        "id": "code-analyzer",
        "name": "Code Analyzer",
        "version": "0.0.0",
        "vendor": {"name": "x"},
    },
    "scanner": {"id": "bandit", "name": "bandit", "version": "1.9.4", "vendor": {"name": "x"}},
    "type": "sast",
    "start_time": "2026-11-17T10:00:00",
    "end_time": "2026-11-17T10:01:00",
    "status": "success",
}
IDENT: Json = {"type": "bandit_rule_id", "name": "B602", "value": "B602"}


def sast_report(**vulnerability: object) -> Json:
    vuln = {
        "id": "sha256-aaaa",
        "name": "subprocess con shell=True",
        "severity": "High",
        "identifiers": [IDENT],
        "location": {"file": "app/handlers.py", "start_line": 12, "end_line": 12},
        **vulnerability,
    }
    return {"version": limits.GITLAB_SCHEMA_VERSION, "scan": SCAN, "vulnerabilities": [vuln]}


def dependency_report(**vulnerability: object) -> Json:
    vuln = {
        "id": "sha256-bbbb",
        "name": "CVE-2018-18074",
        "severity": "Medium",
        "identifiers": [{"type": "cve", "name": "CVE-2018-18074", "value": "CVE-2018-18074"}],
        "location": {
            "file": "poetry.lock",
            "dependency": {"package": {"name": "requests"}, "version": "2.19.1"},
        },
        **vulnerability,
    }
    scan = {**SCAN, "type": "dependency_scanning"}
    return {"version": limits.GITLAB_SCHEMA_VERSION, "scan": scan, "vulnerabilities": [vuln]}


def errors(kind: str, document: Json) -> list[str]:
    schema = json.loads(SCHEMAS[kind].read_text())
    return [e.message for e in Draft7Validator(schema).iter_errors(document)]


def test_pinned_schemas_are_the_ones_the_manifest_lists_and_declare_the_pinned_version() -> None:
    manifest = {e["file"]: e for e in json.loads((VENDOR / "SOURCES.json").read_text())["files"]}
    for path in SCHEMAS.values():
        assert hashlib.sha256(path.read_bytes()).hexdigest() == manifest[path.name]["sha256"]
        assert json.loads(path.read_text())["self"] == {"version": limits.GITLAB_SCHEMA_VERSION}
        assert "v15.2.5" in manifest[path.name]["origin"]


def test_minimal_reports_are_valid() -> None:
    assert errors("sast", sast_report()) == []
    assert errors("dependency_scanning", dependency_report()) == []


@pytest.mark.parametrize("severity", limits.GITLAB_SEVERITIES)
def test_every_declared_severity_is_accepted(severity: str) -> None:
    assert errors("sast", sast_report(severity=severity)) == []


def test_the_declared_limits_match_the_schema() -> None:
    props = json.loads(SCHEMAS["sast"].read_text())["properties"]["vulnerabilities"]["items"][
        "properties"
    ]
    assert props["name"]["maxLength"] == limits.GITLAB_NAME_MAX
    assert props["description"]["maxLength"] == limits.GITLAB_DESCRIPTION_MAX
    assert props["solution"]["maxLength"] == limits.GITLAB_SOLUTION_MAX
    assert tuple(props["severity"]["enum"]) == limits.GITLAB_SEVERITIES


@pytest.mark.parametrize(
    "changes",
    [
        {"name": "x" * (limits.GITLAB_NAME_MAX + 1)},
        {"solution": "x" * (limits.GITLAB_SOLUTION_MAX + 1)},
        {"severity": "Urgent"},
        {"identifiers": []},
    ],
    ids=["name-too-long", "solution-too-long", "severity", "no-identifiers"],
)
def test_values_over_the_limits_are_rejected(changes: Json) -> None:
    assert errors("sast", sast_report(**changes)) != []


def test_reports_without_required_parts_are_rejected() -> None:
    for kind, report in (("sast", sast_report()), ("dependency_scanning", dependency_report())):
        for key in ("version", "scan", "vulnerabilities"):
            assert errors(kind, {k: v for k, v in report.items() if k != key}) != []
        assert errors(kind, mutated(report, lambda r: r["scan"].pop("status"))) != []


def test_dependency_location_needs_package_and_version() -> None:
    bad = dependency_report(location={"file": "poetry.lock", "dependency": {"version": "1"}})
    assert errors("dependency_scanning", bad) != []
