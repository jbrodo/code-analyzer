from copy import deepcopy
from typing import Any

import pytest
from pydantic import ValidationError

from ca_core.models import CodeAnalyzerConfig, Finding

FP = "sha256:" + "a" * 64

FINDING: dict[str, Any] = {
    "id": FP,
    "fingerprint": FP,
    "category": "sast",
    "rule_id": "r1",
    "tool": "gitleaks",
    "tools": ["semgrep", "gitleaks"],
    "title": "t",
    "message": "m",
    "location": {"repository": "r"},
    "first_seen": "2026-11-08T10:00:00Z",
    "last_seen": "2026-11-08T10:00:00Z",
}


def finding(**changes: Any) -> Finding:
    return Finding.model_validate({**deepcopy(FINDING), **changes})


def test_finding_minimal_phase1_defaults() -> None:
    f = finding()
    assert f.impact is None and f.score is None and f.level is None
    assert f.location.commit is None


def test_finding_tool_must_be_lexicographic_first() -> None:
    with pytest.raises(ValidationError, match="lessicografico"):
        finding(tool="semgrep")


def test_finding_tools_rejects_duplicates_and_empty() -> None:
    with pytest.raises(ValidationError):
        finding(tool="a", tools=["a", "a"])
    with pytest.raises(ValidationError):
        finding(tools=[])


@pytest.mark.parametrize("bad", ["abc", "sha256:ZZ", "sha256:" + "a" * 63])
def test_finding_fingerprint_format(bad: str) -> None:
    with pytest.raises(ValidationError):
        finding(fingerprint=bad)


def test_finding_rejects_naive_dates_and_unknown_keys() -> None:
    with pytest.raises(ValidationError):
        finding(first_seen="2026-11-08T10:00:00")
    with pytest.raises(ValidationError):
        finding(unknown=1)


def test_finding_level_source_and_line_order() -> None:
    assert finding(level="alto", level_source="tool_severity").level_source
    for source in ("score", "override"):  # Fase 2 (C-01): aggiunte compatibili
        assert finding(level_source=source).level_source.value == source
    with pytest.raises(ValidationError):
        finding(level_source="bogus")
    with pytest.raises(ValidationError):
        finding(location={"repository": "r", "start_line": 5, "end_line": 4})


def config(**changes: Any) -> CodeAnalyzerConfig:
    return CodeAnalyzerConfig.model_validate({"version": 1, **changes})


SPEC_8: dict[str, Any] = {
    "version": 1,
    "languages": ["python", "typescript"],
    "paths": {"exclude": ["tests/fixtures/**"]},
    "service": {"catalog_id": "payments-api", "tier": 1, "internet_facing": True},
    "scoring": {"variant": "A"},
    "gate": {"mode": "new-findings-only", "block_on": ["critico", "alto"], "warn_on": ["medio"]},
    "licenses": {
        "forbidden": ["AGPL-3.0-only"],
        "require_approval": ["GPL-3.0-only"],
        "distributed_product": True,
    },
    "plugins": {"disable": [], "semgrep": {"rules": ["rules/semgrep/"]}},
    "exceptions": [
        {"fingerprint": FP, "reason": "fp", "expires": "2027-03-31", "approved_by": "@sec"}
    ],
    "agents": {"enabled": True, "max_phase": 5, "llm_provider": "self-hosted"},
}


def test_config_accepts_full_spec_example() -> None:
    assert CodeAnalyzerConfig.model_validate(SPEC_8).gate.block_on


def test_config_defaults_leave_gate_decisions_open() -> None:
    c = config()
    assert c.gate.mode == "all" and c.gate.block_on is None
    assert c.paths.exclude == []


def test_config_version_must_be_1() -> None:
    for v in (2, "1", None):
        with pytest.raises(ValidationError):
            CodeAnalyzerConfig.model_validate({"version": v})
    with pytest.raises(ValidationError):
        CodeAnalyzerConfig.model_validate({})


FORBIDDEN = [
    "image", "digest", "signature", "verify_signature", "isolation",
    "network", "mounts", "command", "feeds", "feed_url",
]  # fmt: skip


@pytest.mark.parametrize("key", FORBIDDEN)
def test_config_rejects_trust_boundary_keys_everywhere(key: str) -> None:
    for payload in (
        {key: "x"},
        {"plugins": {key: "x"}},
        {"plugins": {"semgrep": {key: "x"}}},
        {"plugins": {"trivy": {key: "x"}}},
        {"gate": {key: "x"}},
    ):
        with pytest.raises(ValidationError):
            config(**payload)


@pytest.mark.parametrize("bad", ["/etc", "../x", "a/../../b", "C:\\x", "", "a\\..\\b"])
def test_config_paths_must_be_relative(bad: str) -> None:
    with pytest.raises(ValidationError):
        config(paths={"exclude": [bad]})
    with pytest.raises(ValidationError):
        config(plugins={"semgrep": {"rules": [bad]}})


def test_config_exception_requires_all_fields_and_valid_values() -> None:
    ok = {"fingerprint": FP, "reason": "r", "expires": "2027-01-01", "approved_by": "@a"}
    config(exceptions=[ok])
    for drop in ok:
        with pytest.raises(ValidationError):
            config(exceptions=[{k: v for k, v in ok.items() if k != drop}])
    with pytest.raises(ValidationError):
        config(exceptions=[{**ok, "expires": "2027-13-01"}])
    with pytest.raises(ValidationError):
        config(exceptions=[{**ok, "fingerprint": "sha256:…"}])


def test_config_rejects_level_in_block_and_warn_and_bad_values() -> None:
    with pytest.raises(ValidationError):
        config(gate={"block_on": ["alto"], "warn_on": ["alto"]})
    with pytest.raises(ValidationError):
        config(gate={"mode": "pr"})
    with pytest.raises(ValidationError):
        config(gate={"block_on": ["high"]})
    with pytest.raises(ValidationError):
        config(scoring={"variant": "C"})
