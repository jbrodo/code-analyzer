"""K-14: layout del SARIF aggregato (ADR-0011), contratto pubblico verso `upload-sarif`.

Il documento si valida con lo schema SARIF 2.1.0 fissato in `schemas/vendor/`, senza rete.
"""

import json
from copy import deepcopy
from pathlib import Path
from typing import Any

import pytest

from ca_core.models.scan_report import ScanReport
from ca_core.sarif import SarifError, SarifErrorCode, aggregate_sarif
from ca_core.schema_validation import SchemaStore

ROOT = Path(__file__).resolve().parents[2]
NOW = "2026-06-01T12:00:00Z"
FP = ["sha256:" + c * 64 for c in "abcdef"]


@pytest.fixture(scope="module")
def store() -> SchemaStore:
    return SchemaStore(ROOT / "schemas" / "vendor")


def finding(i: int, **kv: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "id": FP[i],
        "fingerprint": FP[i],
        "category": "sast",
        "rule_id": f"rule-{i}",
        "tool": "bandit",
        "tools": ["bandit"],
        "title": "t",
        "message": f"message {i}",
        "location": {"repository": "repo", "path": "src/a b.py", "start_line": 3, "end_line": 4},
        "evidence": {"bandit": {"secret_like": "NEVER-IN-OUTPUT"}},
        "level": "alto",
        "level_source": "tool_severity",
        "status": "aperto",
        "first_seen": NOW,
        "last_seen": NOW,
    }
    return {**base, **kv}


def report_dict(findings: list[dict[str, Any]], **kv: Any) -> dict[str, Any]:
    plugin = {
        "name": "bandit",
        "version": "1.8.0",
        "digest": "sha256:" + "9" * 64,
        "signature": "verified",
        "isolation": "gvisor",
        "duration_seconds": 1.0,
        "outcome": "ok",
    }
    return {
        "version": 1,
        "status": "complete",
        "started_at": NOW,
        "duration_seconds": 2.0,
        "repository": {"name": "repo", "history": "full"},
        "gate": {"mode": "all", "effective_mode": "all"},
        "plugins": [plugin, {**plugin, "name": "osv-scanner", "version": "2.0.0"}],
        "findings": findings,
        **kv,
    }


def build(store: SchemaStore, findings: list[dict[str, Any]], **kv: Any) -> dict[str, Any]:
    report = ScanReport.model_validate(report_dict(findings, **kv))
    return json.loads(aggregate_sarif(report, store))


def test_single_run_with_code_analyzer_driver_and_scanner_extensions(store: SchemaStore) -> None:
    sarif = build(store, [finding(0)])

    assert sarif["version"] == "2.1.0" and len(sarif["runs"]) == 1
    tool = sarif["runs"][0]["tool"]
    assert tool["driver"]["name"] == "code-analyzer"
    assert tool["extensions"] == [
        {"name": "bandit", "version": "1.8.0"},
        {"name": "osv-scanner", "version": "2.0.0"},
    ]


def test_result_layout(store: SchemaStore) -> None:
    [result] = build(store, [finding(0)])["runs"][0]["results"]

    assert result["ruleId"] == "rule-0" and result["level"] == "error"
    assert result["message"] == {"text": "message 0"}
    assert result["partialFingerprints"] == {"codeAnalyzer/v1": FP[0]}
    assert result["properties"] == {
        "level": "alto",
        "level_source": "tool_severity",
        "category": "sast",
        "tools": ["bandit"],
        "status": "aperto",
    }
    location = result["locations"][0]["physicalLocation"]
    assert location["artifactLocation"] == {"uri": "src/a%20b.py"}  # relativo, senza uriBaseId
    assert location["region"] == {"startLine": 3, "endLine": 4}


@pytest.mark.parametrize(
    ("level", "sarif"),
    [("critico", "error"), ("alto", "error"), ("medio", "warning"), ("basso", "note")],
)
def test_level_mapping(store: SchemaStore, level: str, sarif: str) -> None:
    [result] = build(store, [finding(0, level=level)])["runs"][0]["results"]

    assert result["level"] == sarif and result["properties"]["level"] == level


def test_security_severity_only_with_cvss(store: SchemaStore) -> None:
    cvss = {"osv-scanner": {"cvss": {"version": "3.1", "vector": "v", "score": 7.5}}}
    with_cvss = finding(
        0,
        category="dependency",
        tool="osv-scanner",
        tools=["osv-scanner"],
        evidence=cvss,
        location={"repository": "repo", "path": "package-lock.json", "purl": "pkg:npm/x@1"},
    )
    without = finding(1)

    first, second = build(store, [with_cvss, without])["runs"][0]["results"]

    assert first["properties"]["security-severity"] == "7.5"
    assert first["properties"]["purl"] == "pkg:npm/x@1"
    assert "security-severity" not in second["properties"]


def test_findings_without_position_go_to_notifications_not_results(store: SchemaStore) -> None:
    health = finding(
        1,
        category="health",
        rule_id="ca.scanner-not-run",
        level="medio",
        location={"repository": "repo"},
    )
    run = build(store, [finding(0), health])["runs"][0]

    assert [r["ruleId"] for r in run["results"]] == ["rule-0"]
    [notification] = run["invocations"][0]["toolExecutionNotifications"]
    assert notification["descriptor"] == {"id": "ca.scanner-not-run"}
    assert notification["level"] == "warning"
    assert notification["properties"]["fingerprint"] == FP[1]


def test_report_warnings_are_notifications_and_failure_marks_invocation(
    store: SchemaStore,
) -> None:
    failed = {
        "name": "trivy",
        "version": "1",
        "digest": "sha256:" + "8" * 64,
        "signature": "verified",
        "isolation": "gvisor",
        "duration_seconds": 0.0,
        "outcome": "failed",
        "failure": "timeout",
    }
    run = build(
        store,
        [],
        status="partial",
        plugins=[failed],
        warnings=[{"code": "exception-expired", "message": "scaduta", "subject": FP[0]}],
    )["runs"][0]

    invocation = run["invocations"][0]
    assert invocation["executionSuccessful"] is False
    assert invocation["startTimeUtc"] == NOW
    assert [n["descriptor"]["id"] for n in invocation["toolExecutionNotifications"]] == [
        "exception-expired"
    ]


def test_active_exception_becomes_external_suppression(store: SchemaStore) -> None:
    exception = {
        "fingerprint": FP[0],
        "reason": "falso positivo",
        "expires": "2027-01-01",
        "approved_by": "@sec",
    }
    accepted, other = build(
        store, [finding(0, status="accettato"), finding(1)], exceptions=[exception]
    )["runs"][0]["results"]

    assert accepted["suppressions"] == [
        {"kind": "external", "status": "accepted", "justification": "falso positivo"}
    ]
    assert "suppressions" not in other


def test_no_snippet_and_no_evidence_leak_into_the_document(store: SchemaStore) -> None:
    secret = finding(
        0, category="secret", tool="gitleaks", tools=["gitleaks"], message="Segreto rilevato"
    )
    text = aggregate_sarif(ScanReport.model_validate(report_dict([secret])), store).decode()

    assert "snippet" not in text and "NEVER-IN-OUTPUT" not in text


def test_two_runs_produce_identical_bytes_regardless_of_dict_order(store: SchemaStore) -> None:
    data = report_dict([finding(0), finding(1, rule_id="a-rule")])
    shuffled = deepcopy(data)
    shuffled["plugins"].reverse()
    shuffled["findings"][0] = dict(reversed(list(shuffled["findings"][0].items())))

    one = aggregate_sarif(ScanReport.model_validate(data), store)

    assert one == aggregate_sarif(ScanReport.model_validate(data), store)
    assert one == aggregate_sarif(ScanReport.model_validate(shuffled), store)


def test_invalid_document_is_refused_before_returning_bytes(store: SchemaStore) -> None:
    bad = finding(0, location={"repository": "repo", "path": "a.py", "start_line": 1})
    report = ScanReport.model_validate(report_dict([bad]))

    class Rejecting(SchemaStore):
        def __init__(self) -> None:  # riusa lo store reale, rifiuta ogni documento
            pass

        def validate_sarif(self, instance: Any) -> list[str]:
            return ["/runs/0: rifiutato"]

    with pytest.raises(SarifError) as info:
        aggregate_sarif(report, Rejecting())

    assert info.value.code is SarifErrorCode.SCHEMA
