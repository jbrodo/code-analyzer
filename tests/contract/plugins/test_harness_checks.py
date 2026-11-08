"""T-04: l'harness deve rifiutare cio' che il contratto vieta (casi negativi con nome).

Ogni caso parte da un documento conforme e introduce un solo difetto: il gruppo di controlli che
scatta deve essere quello atteso, e nessun altro.
"""

import copy
from collections.abc import Callable
from typing import Any

import pytest
from plugin_output_harness import (
    gitleaks_problems,
    properties_problems,
    sarif_problems,
    snippet_problems,
    uri_problems,
)

SHA = "a" * 64


def base(rule_id: str = "R1", uri: str = "src/a.py", properties: dict[str, Any] | None = None):
    result: dict[str, Any] = {
        "ruleId": rule_id,
        "message": {"text": "problema"},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": uri},
                    "region": {"startLine": 3, "endLine": 3},
                }
            }
        ],
    }
    if properties is not None:
        result["properties"] = properties
    return {
        "version": "2.1.0",
        "runs": [{"tool": {"driver": {"name": "t"}}, "results": [result]}],
    }


def gitleaks_doc() -> dict[str, Any]:
    doc = base(
        "github-pat",
        "conf.py",
        {"category": "secret", "secret_sha256": SHA},
    )
    result = doc["runs"][0]["results"][0]
    result["message"] = {"text": "github-pat has detected secret for file conf.py."}
    result["partialFingerprints"] = {"commitSha": "ab394a3", "date": "2026-11-08T00:00:00Z"}
    return doc


def result_of(doc: dict[str, Any]) -> dict[str, Any]:
    return doc["runs"][0]["results"][0]


def region_of(doc: dict[str, Any]) -> dict[str, Any]:
    return result_of(doc)["locations"][0]["physicalLocation"]["region"]


def artifact_of(doc: dict[str, Any]) -> dict[str, Any]:
    return result_of(doc)["locations"][0]["physicalLocation"]["artifactLocation"]


Mutation = Callable[[dict[str, Any]], None]

# nome -> (mutazione del documento conforme, gruppo che deve scattare)
CASES: dict[str, tuple[str, Mutation]] = {
    "snippet-in-region": ("snippet", lambda d: region_of(d).update(snippet={"text": "x"})),
    "snippet-case-insensitive": (
        "snippet",
        lambda d: region_of(d).update(properties={"Snippet": "x"}),
    ),
    "snippet-deep-in-lists": (
        "snippet",
        lambda d: region_of(d).update(properties={"a": [{"b": [{"snippet": "x"}]}]}),
    ),
    "snippet-in-run-properties": (
        "snippet",
        lambda d: d["runs"][0].update(properties={"a": [{"b": {"snippet": "x"}}]}),
    ),
    "uri-absolute": ("uri", lambda d: artifact_of(d).update(uri="/workspace/src/a.py")),
    "uri-file-scheme": ("uri", lambda d: artifact_of(d).update(uri="file:///workspace/a.py")),
    "uri-parent": ("uri", lambda d: artifact_of(d).update(uri="../outside.py")),
    "uri-embedded-parent": ("uri", lambda d: artifact_of(d).update(uri="a/../../b.py")),
    "uri-windows-drive": ("uri", lambda d: artifact_of(d).update(uri="C:\\work\\a.py")),
    "uri-base-id": ("uri", lambda d: artifact_of(d).update(uriBaseId="%SRCROOT%")),
    "properties-unknown-key": (
        "properties",
        lambda d: result_of(d).update(properties={"issue_severity": "HIGH"}),
    ),
    "properties-misspelled-aliases": (
        "properties",
        lambda d: result_of(d).update(properties={"alias": ["CVE-2024-1"]}),
    ),
    "properties-cvss-score-out-of-range": (
        "properties",
        lambda d: result_of(d).update(
            properties={"cvss": {"version": "3.1", "vector": "CVSS:3.1/AV:N", "score": 11}}
        ),
    ),
    "properties-secret-without-hash": (
        "properties",
        lambda d: result_of(d).update(properties={"category": "secret"}),
    ),
    "properties-dependency-without-purl": (
        "properties",
        lambda d: result_of(d).update(properties={"category": "dependency"}),
    ),
    "properties-bad-secret-hash": (
        "properties",
        lambda d: result_of(d).update(properties={"category": "secret", "secret_sha256": "xyz"}),
    ),
}


@pytest.mark.parametrize("group,mutate", CASES.values(), ids=list(CASES))
def test_a_single_defect_trips_only_its_group(group: str, mutate: Mutation) -> None:
    doc = base(properties={})
    result_of(doc).pop("properties")
    mutate(doc)
    assert set(sarif_problems(doc, "any-plugin")) == {group}


def test_conforming_document_has_no_problems() -> None:
    assert sarif_problems(base(), "any-plugin") == {}
    assert sarif_problems(gitleaks_doc(), "gitleaks") == {}


def test_dependency_with_purl_and_aliases_is_conforming() -> None:
    props = {"category": "dependency", "purl": "pkg:pypi/requests", "aliases": ["CVE-2024-1"]}
    assert sarif_problems(base("CVE-2024-1", "poetry.lock", props), "osv-scanner") == {}


def test_schema_violation_stops_further_checks() -> None:
    doc = base()
    doc["version"] = "2.0.0"
    assert set(sarif_problems(doc, "any-plugin")) == {"schema"}


def test_not_json_sarif_is_a_schema_problem() -> None:
    assert set(sarif_problems({"runs": "x", "version": "2.1.0"}, "any-plugin")) == {"schema"}


def test_two_runs_are_rejected() -> None:
    doc = base()
    doc["runs"].append(copy.deepcopy(doc["runs"][0]))
    assert set(sarif_problems(doc, "any-plugin")) == {"schema"}


@pytest.mark.parametrize(
    "text",
    [
        "github-pat has detected secret for file conf.py at commit ab394a3f04.",
        "github-pat has detected secret for file conf.py.",
    ],
    ids=["with-commit", "without-commit"],
)
def test_gitleaks_redacted_message_models_are_accepted(text: str) -> None:
    doc = gitleaks_doc()
    result_of(doc)["message"]["text"] = text
    assert gitleaks_problems(doc) == []


@pytest.mark.parametrize(
    "text",
    [
        "github-pat has detected secret FAKE-VALUE-123 for file conf.py.",
        "github-pat has detected secret for file conf.py at commit not-a-commit.",
        "github-pat has detected secret for file other.py.",
        "other-rule has detected secret for file conf.py.",
        "github-pat has detected secret for file conf.py. FAKE-VALUE-123",
        "",
    ],
    ids=["value-inside", "bad-commit", "other-file", "other-rule", "trailing-value", "empty"],
)
def test_gitleaks_other_messages_are_rejected(text: str) -> None:
    doc = gitleaks_doc()
    result_of(doc)["message"]["text"] = text
    assert gitleaks_problems(doc)


def test_gitleaks_message_with_extra_keys_is_rejected() -> None:
    doc = gitleaks_doc()
    result_of(doc)["message"]["markdown"] = "x"
    assert gitleaks_problems(doc)


@pytest.mark.parametrize("key", ["email", "author", "commitMessage"])
def test_gitleaks_personal_fingerprint_keys_are_rejected(key: str) -> None:
    doc = gitleaks_doc()
    result_of(doc)["partialFingerprints"][key] = "x"
    assert gitleaks_problems(doc) == [f"/runs/0/results/0/partialFingerprints/{key}"]


def test_gitleaks_checks_apply_only_to_gitleaks() -> None:
    doc = gitleaks_doc()
    result_of(doc)["partialFingerprints"]["email"] = "x"
    assert "gitleaks" in sarif_problems(doc, "gitleaks")
    assert "gitleaks" not in sarif_problems(doc, "bandit")


def test_problem_lists_are_bounded() -> None:
    doc = base()
    doc["runs"][0]["results"] = [copy.deepcopy(result_of(doc)) for _ in range(100)]
    for r in doc["runs"][0]["results"]:
        r["locations"][0]["physicalLocation"]["region"]["snippet"] = {"text": "x"}
        r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] = "/abs"
    assert len(snippet_problems(doc)) == 20
    assert len(uri_problems(doc)) == 20


def test_properties_absent_are_conforming() -> None:
    assert properties_problems(base()) == []
