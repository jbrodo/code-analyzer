from copy import deepcopy
from typing import Any

import pytest
from pydantic import ValidationError

from ca_core.models import ScanReport

PLUGIN: dict[str, Any] = {
    "name": "semgrep",
    "version": "1.184.0",
    "digest": "sha256:" + "a" * 64,
    "signature": "verified",
    "isolation": "hardened-container",
    "duration_seconds": 12.5,
    "outcome": "ok",
}
REPORT: dict[str, Any] = {
    "version": 1,
    "status": "complete",
    "started_at": "2026-11-08T10:00:00Z",
    "duration_seconds": 30,
    "repository": {"name": "r", "commit": "a" * 40, "history": "full"},
    "gate": {"mode": "new-findings-only", "effective_mode": "all"},
    "plugins": [PLUGIN],
    "findings": [],
}


def report(**changes: Any) -> ScanReport:
    return ScanReport.model_validate({**deepcopy(REPORT), **changes})


def test_minimal_report_and_defaults() -> None:
    parsed = report()
    assert parsed.exceptions == [] and parsed.warnings == [] and parsed.gate.block_on is None


def test_failed_plugin_requires_partial_and_a_failure() -> None:
    failed = {**PLUGIN, "outcome": "failed", "failure": "timeout"}
    with pytest.raises(ValidationError, match="partial"):
        report(plugins=[failed])
    assert report(plugins=[failed], status="partial").status == "partial"
    with pytest.raises(ValidationError, match="failure"):
        report(plugins=[{**PLUGIN, "failure": "x"}])
    with pytest.raises(ValidationError, match="failure"):
        report(plugins=[{**PLUGIN, "outcome": "failed"}], status="partial")


def test_plugins_are_unique_and_not_both_disabled() -> None:
    with pytest.raises(ValidationError, match="duplicati"):
        report(plugins=[PLUGIN, PLUGIN])
    with pytest.raises(ValidationError, match="disattivato"):
        report(disabled_plugins=["semgrep"])


@pytest.mark.parametrize("key", ["image", "registry", "key", "signer"])
def test_no_registry_or_key_in_plugin(key: str) -> None:
    with pytest.raises(ValidationError):
        report(plugins=[{**PLUGIN, key: "x"}])
