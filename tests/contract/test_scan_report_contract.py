"""`scan-report`: contratto del report. Copre `partial` e `failed` per quanto lo schema li esprime.

Lo schema NON lega `status` agli esiti dei plugin (vedi `test_status_is_not_tied_to_*`):
quel vincolo vive solo nel modello Pydantic.
"""

import pytest
from conftest import Json, errors_of, load_schema, make_validator, mutated

VALIDATOR = make_validator("scan-report")
FP = "sha256:" + "c" * 64
NOW = "2026-01-01T00:00:00Z"

FINDING: Json = {
    "id": "f1",
    "fingerprint": FP,
    "category": "secret",
    "rule_id": "r",
    "tool": "gitleaks",
    "tools": ["gitleaks"],
    "title": "t",
    "message": "m",
    "location": {"repository": "repo"},
    "first_seen": NOW,
    "last_seen": NOW,
}
PLUGIN_OK: Json = {
    "name": "bandit",
    "version": "1.8.0",
    "digest": FP,
    "signature": "verified",
    "isolation": "gvisor",
    "duration_seconds": 1.5,
    "outcome": "ok",
}
PLUGIN_FAILED: Json = {**PLUGIN_OK, "name": "trivy", "outcome": "failed", "failure": "timeout"}
MINIMAL: Json = {
    "version": 1,
    "status": "complete",
    "started_at": NOW,
    "duration_seconds": 0,
    "repository": {"name": "repo", "history": "full"},
    "gate": {"mode": "all", "effective_mode": "all"},
    "plugins": [PLUGIN_OK],
    "findings": [],
}


def _set(**kv: object):
    return lambda i: i.update(kv)


def _drop(key: str):
    return lambda i: i.pop(key)


def _plugin(**kv: object):
    return lambda i: i["plugins"][0].update(kv)


PARTIAL = mutated(MINIMAL, _set(status="partial", plugins=[PLUGIN_OK, PLUGIN_FAILED]))

VALID = {
    "minimal": MINIMAL,
    "with-finding": mutated(MINIMAL, _set(findings=[FINDING])),
    "partial-with-failed-plugin": PARTIAL,
    "partial-with-feed-snapshot-failed": mutated(
        PARTIAL,
        lambda i: i["plugins"][0].update(
            feed={"origin": "mirror", "synced_at": NOW, "sync_failed": True}
        ),
    ),
    "no-plugins": mutated(MINIMAL, _set(plugins=[])),
    "history-shallow": mutated(MINIMAL, _set(repository={"name": "r", "history": "shallow"})),
    "history-absent-with-commit": mutated(
        MINIMAL, _set(repository={"name": "r", "history": "absent", "commit": "a" * 40})
    ),
    "commit-sha256-length": mutated(
        MINIMAL, _set(repository={"name": "r", "history": "full", "commit": "a" * 64})
    ),
    "signature-skipped": mutated(MINIMAL, _plugin(signature="skipped")),
    "isolation-hardened": mutated(MINIMAL, _plugin(isolation="hardened-container")),
    "gate-with-levels": mutated(
        MINIMAL,
        _set(
            gate={
                "mode": "new-findings-only",
                "effective_mode": "all",
                "block_on": ["critico"],
                "warn_on": None,
            }
        ),
    ),
    "optional-sections": mutated(
        MINIMAL,
        _set(
            warnings=[{"code": "exception-expired", "message": "m", "subject": "s"}],
            exceptions=[
                {"fingerprint": FP, "reason": "r", "expires": "2027-01-01", "approved_by": "a"}
            ],
            exclusions=["vendor/**"],
            disabled_plugins=["scancode"],
            inert_sections=["service", "scoring", "agents"],
        ),
    ),
}
INVALID = {
    **{
        f"missing-{k}": mutated(MINIMAL, _drop(k))
        for k in (
            "version",
            "status",
            "started_at",
            "duration_seconds",
            "repository",
            "gate",
            "plugins",
            "findings",
        )
    },
    "unknown-top-level": mutated(MINIMAL, _set(extra=1)),
    "version-2": mutated(MINIMAL, _set(version=2)),
    # `failed` non è un esito del report: un report fallito non viene emesso (exit 2).
    "status-failed": mutated(MINIMAL, _set(status="failed")),
    "status-unknown": mutated(MINIMAL, _set(status="running")),
    "duration-negative": mutated(MINIMAL, _set(duration_seconds=-1)),
    "repository-missing-history": mutated(MINIMAL, _set(repository={"name": "r"})),
    "repository-empty-name": mutated(MINIMAL, _set(repository={"name": "", "history": "full"})),
    "repository-history-unknown": mutated(MINIMAL, _set(repository={"name": "r", "history": "x"})),
    "repository-commit-short": mutated(
        MINIMAL, _set(repository={"name": "r", "history": "full", "commit": "abc"})
    ),
    "repository-commit-uppercase": mutated(
        MINIMAL, _set(repository={"name": "r", "history": "full", "commit": "A" * 40})
    ),
    "gate-missing-effective-mode": mutated(MINIMAL, _set(gate={"mode": "all"})),
    "gate-bad-mode": mutated(MINIMAL, _set(gate={"mode": "x", "effective_mode": "all"})),
    "gate-bad-level": mutated(
        MINIMAL, _set(gate={"mode": "all", "effective_mode": "all", "block_on": ["x"]})
    ),
    "plugin-signature-failed": mutated(MINIMAL, _plugin(signature="failed")),
    "plugin-signature-missing": mutated(MINIMAL, _plugin(signature=None)),
    "plugin-isolation-none": mutated(MINIMAL, _plugin(isolation="none")),
    "plugin-outcome-timeout": mutated(MINIMAL, _plugin(outcome="timeout")),
    "plugin-digest-not-sha256": mutated(MINIMAL, _plugin(digest="sha1:" + "a" * 40)),
    "plugin-digest-short": mutated(MINIMAL, _plugin(digest="sha256:abc")),
    "plugin-name-uppercase": mutated(MINIMAL, _plugin(name="Bandit")),
    "plugin-empty-version": mutated(MINIMAL, _plugin(version="")),
    "plugin-failure-empty": mutated(MINIMAL, _plugin(failure="")),
    "plugin-failure-too-long": mutated(MINIMAL, _plugin(failure="x" * 501)),
    "plugin-duration-negative": mutated(MINIMAL, _plugin(duration_seconds=-0.1)),
    "plugin-unknown-key": mutated(MINIMAL, _plugin(image="x:1")),
    "plugin-missing-outcome": mutated(MINIMAL, lambda i: i["plugins"][0].pop("outcome")),
    "feed-missing-origin": mutated(MINIMAL, _plugin(feed={"synced_at": NOW})),
    "feed-empty-origin": mutated(MINIMAL, _plugin(feed={"origin": "", "synced_at": NOW})),
    "feed-unknown-key": mutated(
        MINIMAL, _plugin(feed={"origin": "o", "synced_at": NOW, "url": "u"})
    ),
    "finding-invalid-embedded": mutated(MINIMAL, _set(findings=[{**FINDING, "fingerprint": "x"}])),
    "finding-unknown-key-embedded": mutated(MINIMAL, _set(findings=[{**FINDING, "x": 1}])),
    "warning-bad-code": mutated(MINIMAL, _set(warnings=[{"code": "Bad Code", "message": "m"}])),
    "warning-empty-message": mutated(MINIMAL, _set(warnings=[{"code": "c", "message": ""}])),
    "inert-section-unknown": mutated(MINIMAL, _set(inert_sections=["gate"])),
    "exception-bad-fingerprint": mutated(
        MINIMAL,
        _set(
            exceptions=[
                {"fingerprint": "f", "reason": "r", "expires": "2027-01-01", "approved_by": "a"}
            ]
        ),
    ),
}


@pytest.mark.parametrize("instance", VALID.values(), ids=VALID.keys())
def test_valid_report_is_accepted(instance: Json) -> None:
    assert errors_of(VALIDATOR, instance) == []


@pytest.mark.parametrize("instance", INVALID.values(), ids=INVALID.keys())
def test_invalid_report_is_rejected(instance: Json) -> None:
    assert errors_of(VALIDATOR, instance) != []


def test_status_only_admits_complete_and_partial() -> None:
    assert load_schema("scan-report")["$defs"]["ReportStatus"]["enum"] == ["complete", "partial"]


def test_plugin_outcome_only_admits_ok_and_failed() -> None:
    assert load_schema("scan-report")["$defs"]["Outcome"]["enum"] == ["ok", "failed"]


def test_status_is_not_tied_to_plugin_outcome() -> None:
    """Limite del contratto, documentato: lo schema non lega `status` agli esiti dei plugin.

    Se un giorno lo schema esprimerà il vincolo, questi casi diventeranno non validi e il test
    andrà aggiornato insieme a `architect`, non indebolito.
    """
    complete_with_failure = mutated(MINIMAL, _set(plugins=[PLUGIN_FAILED]))
    partial_all_ok = mutated(MINIMAL, _set(status="partial"))
    failed_without_reason = mutated(MINIMAL, _plugin(outcome="failed"))
    assert errors_of(VALIDATOR, complete_with_failure) == []
    assert errors_of(VALIDATOR, partial_all_ok) == []
    assert errors_of(VALIDATOR, failed_without_reason) == []
