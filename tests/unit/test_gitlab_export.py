"""N-06: i report nativi di GitLab, validati contro gli schemi fissati (C-09)."""

import json
from pathlib import Path

import pytest
from builders import finding, report

from ca_core.models.finding import Category, Level, Location, Remediation, RemediationSource
from ca_core.schema_validation import SchemaStore
from ca_integrations.gitlab import ExportError, build_reports, to_cyclonedx_16

SAST_SCHEMA = "gitlab-sast-15.2.5.schema.json"
DEPENDENCY_SCHEMA = "gitlab-dependency-scanning-15.2.5.schema.json"
FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "plugin-output"
STORE = SchemaStore.packaged()


def dependency(n: str, purl: str | None = "pkg:pypi/django@3.2.1", **kv: object):
    where = Location(
        repository="repo", path="requirements.txt", purl=purl, dependency_path=["django"]
    )
    return finding(n, category=Category.DEPENDENCY, tool="osv-scanner", **kv).model_copy(
        update={"location": where, "cve": ["CVE-2024-1234"], "cwe": ["CWE-79"]}
    )


def built(*findings, **kv):
    return build_reports(report(list(findings), **kv), version="1.2.3")


def test_every_report_is_valid_against_its_pinned_schema() -> None:
    out = built(
        finding("s", level=Level.HIGH, cwe=["CWE-78"]),
        dependency("d", level=Level.CRITICAL),
        finding("q", category=Category.QUALITY, tool="ruff", level=Level.LOW),
    )
    assert STORE.validate_pinned(SAST_SCHEMA, out.sast) == []
    assert STORE.validate_pinned(DEPENDENCY_SCHEMA, out.dependency_scanning) == []
    assert len(out.sast["vulnerabilities"]) == 1
    assert len(out.dependency_scanning["vulnerabilities"]) == 1
    assert len(out.codequality) == 1


def test_empty_reports_are_still_valid() -> None:
    out = built()
    assert STORE.validate_pinned(SAST_SCHEMA, out.sast) == []
    assert STORE.validate_pinned(DEPENDENCY_SCHEMA, out.dependency_scanning) == []
    assert out.codequality == []


def test_sast_mapping() -> None:
    f = finding("s", level=Level.HIGH, cwe=["CWE-78"]).model_copy(
        update={
            "remediation": Remediation(
                text="Usa subprocess senza shell.",
                references=["https://example.org/doc"],
                source=RemediationSource.RULE,
            )
        }
    )
    item = built(f).sast["vulnerabilities"][0]
    assert item["severity"] == "High"
    assert item["location"] == {"file": "app/run.py", "start_line": 3, "end_line": 3}
    assert item["identifiers"][0] == {
        "type": "bandit_rule_id", "name": "r-s", "value": "r-s",
    }  # fmt: skip
    cwe = {
        "type": "cwe",
        "name": "CWE-78",
        "value": "78",
        "url": "https://cwe.mitre.org/data/definitions/78.html",
    }
    assert cwe in item["identifiers"]
    assert item["solution"] == "Usa subprocess senza shell."
    assert item["links"] == [{"url": "https://example.org/doc"}]


def test_ids_are_stable_and_distinct() -> None:
    a1 = built(finding("a")).sast["vulnerabilities"][0]["id"]
    a2 = built(finding("a")).sast["vulnerabilities"][0]["id"]
    b = built(finding("b")).sast["vulnerabilities"][0]["id"]
    assert a1 == a2 and a1 != b


def test_level_without_a_value_is_unknown() -> None:
    assert built(finding("a")).sast["vulnerabilities"][0]["severity"] == "Unknown"


def test_dependency_mapping() -> None:
    item = built(dependency("d", level=Level.MEDIUM)).dependency_scanning["vulnerabilities"][0]
    assert item["location"] == {
        "file": "requirements.txt",
        "dependency": {"package": {"name": "django"}, "version": "3.2.1", "direct": True},
    }
    assert item["identifiers"][0]["type"] == "cve"
    assert item["identifiers"][0]["url"] == "https://nvd.nist.gov/vuln/detail/CVE-2024-1234"


def test_scoped_npm_package_is_decoded() -> None:
    item = built(dependency("d", purl="pkg:npm/%40scope/pkg@1.0.0")).dependency_scanning[
        "vulnerabilities"
    ][0]
    assert item["location"]["dependency"]["package"]["name"] == "@scope/pkg"


def test_dependency_without_a_version_or_path_is_counted_not_invented() -> None:
    out = built(dependency("a", purl="pkg:pypi/django"), dependency("b", purl=None))
    assert out.dependency_scanning["vulnerabilities"] == []
    assert out.skipped == {"dependency_scanning": 2}


def test_findings_without_a_path_or_line_are_counted() -> None:
    out = built(
        finding("s", path=None),
        finding("q", category=Category.QUALITY, tool="ruff", path=None),
        finding("q2", category=Category.QUALITY, tool="ruff").model_copy(
            update={"location": Location(repository="repo", path="a.py")}
        ),
    )
    assert out.skipped == {"sast": 1, "codequality": 2}


def test_categories_without_a_format_are_counted() -> None:
    out = built(
        finding("a", category=Category.SECRET, tool="gitleaks"),
        finding("b", category=Category.LICENSE, tool="scancode"),
        finding("c", category=Category.IAC, tool="checkov"),
        finding("d", category=Category.ARCHITECTURE, tool="ca-graph"),
    )
    assert out.not_exported == {"secret": 1, "license": 1, "iac": 1, "architecture": 1}
    assert out.sast["vulnerabilities"] == [] and out.codequality == []


@pytest.mark.parametrize(
    ("level", "expected"),
    [
        (Level.CRITICAL, "critical"),
        (Level.HIGH, "major"),
        (Level.MEDIUM, "minor"),
        (Level.LOW, "info"),
        (None, "info"),
    ],
)
def test_codequality_severity(level: Level | None, expected: str) -> None:
    item = built(finding("q", category=Category.QUALITY, tool="ruff", level=level)).codequality[0]
    assert item["severity"] == expected
    assert item["location"] == {"path": "app/run.py", "lines": {"begin": 3}}
    assert len(item["fingerprint"]) == 64


def test_hostile_text_loses_control_characters_and_is_capped() -> None:
    f = finding("s").model_copy(update={"title": "a\x00b\x1b[31m" + "x" * 1000, "message": "m\x07"})
    item = built(f).sast["vulnerabilities"][0]
    assert "\x00" not in item["name"] and "\x1b" not in item["name"]
    assert len(item["name"]) <= 255
    assert item["description"] == "m"
    assert STORE.validate_pinned(SAST_SCHEMA, built(f).sast) == []


def test_partial_scan_is_reported_as_failure_with_a_message() -> None:
    out = built(finding("s"), status="partial")
    scan = out.sast["scan"]
    assert scan["status"] == "failure" and scan["messages"][0]["level"] == "warn"
    assert STORE.validate_pinned(SAST_SCHEMA, out.sast) == []


def test_scan_times_and_scanner_are_set() -> None:
    scan = built(finding("s")).sast["scan"]
    assert scan["start_time"] == "2026-06-01T12:00:00" and scan["type"] == "sast"
    assert scan["scanner"]["version"] == "1.2.3"


# --- CycloneDX ---------------------------------------------------------------------------------


@pytest.mark.parametrize("name", ["syft", "trivy"])
def test_product_sbom_converts_to_a_valid_cyclonedx_16(name: str) -> None:
    document = json.loads((FIXTURES / f"{name}.cdx.json").read_text())
    converted = to_cyclonedx_16(document)
    assert converted["specVersion"] == "1.6"
    assert converted["$schema"].endswith("bom-1.6.schema.json")
    assert STORE.validate_cyclonedx_export(converted, "1.6") == []
    assert document["specVersion"] == "1.7"  # l'originale non cambia


def test_a_document_that_is_not_1_7_is_refused() -> None:
    with pytest.raises(ExportError, match="sbom-not-1.7"):
        to_cyclonedx_16({"specVersion": "1.6"})
    with pytest.raises(ExportError):
        to_cyclonedx_16([])


def test_a_1_7_only_feature_makes_the_converted_document_invalid() -> None:
    """Se il documento usa qualcosa di esclusivo della 1.7, la validazione 1.6 lo rifiuta."""
    document = json.loads((FIXTURES / "syft.cdx.json").read_text())
    document["citations"] = [{"timestamp": "2026-01-01T00:00:00Z"}]  # solo 1.7
    assert STORE.validate_cyclonedx_export(to_cyclonedx_16(document), "1.6") != []


def test_export_versions_are_not_admitted_as_input() -> None:
    from ca_core.formats import ADMITTED_CYCLONEDX_VERSIONS

    assert "1.6" not in ADMITTED_CYCLONEDX_VERSIONS
