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
    "partial-without-failed-plugin": mutated(MINIMAL, _set(status="partial")),
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
    "complete-with-failed-plugin": mutated(MINIMAL, _set(plugins=[PLUGIN_OK, PLUGIN_FAILED])),
    "failed-without-failure": mutated(PARTIAL, lambda i: i["plugins"][1].pop("failure")),
    "failed-with-null-failure": mutated(PARTIAL, lambda i: i["plugins"][1].update(failure=None)),
    "ok-with-failure": mutated(MINIMAL, _plugin(failure="boom")),
    "finding-embedded-tools-duplicates": mutated(
        MINIMAL, _set(findings=[{**FINDING, "tools": ["gitleaks", "gitleaks"]}])
    ),
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


# --- Fase 2 (C-04): tipo di scansione, baseline, configurazione effettiva, scoring ---------------

BASE = "a" * 40
HEAD = "b" * 40
PR_SCAN: Json = {"kind": "pr", "base_commit": BASE, "pull_request": 12}
BASELINE_OK: Json = {
    "status": "valid",
    "commit": BASE,
    "source": "ci-artifact",
    "new": 1,
    "existing": 1,
    "resolved": [{"fingerprint": FP, "rule_id": "B602", "title": "t", "path": "a.py"}],
}  # noqa: E501
NEW = {**FINDING, "baseline_state": "new"}
OLD = {**FINDING, "fingerprint": "sha256:" + "d" * 64, "id": "f2", "baseline_state": "existing"}
PR_REPORT: Json = mutated(MINIMAL, _set(scan=PR_SCAN, baseline=BASELINE_OK, findings=[NEW, OLD]))
CONFIG: Json = {
    "version": 1,
    "gate": {"mode": "new-findings-only", "block_on": ["critico"]},
    "paths": {"exclude": ["dist"]},
    "licenses": {"forbidden": ["X"]},
}  # noqa: E501
SNAPSHOT: Json = {
    "feed": "epss",
    "origin": "cache",
    "downloaded_at": NOW,
    "sha256": "e" * 64,
    "content": {"score_date": "2026-11-13"},
}  # noqa: E501

VALID.update(
    {
        "full-scan-explicit": mutated(MINIMAL, _set(scan={"kind": "full"})),
        "pr-scan-with-baseline": PR_REPORT,
        "pr-scan-without-pull-request-number": mutated(
            MINIMAL, _set(scan={"kind": "pr", "base_commit": BASE})
        ),
        "baseline-missing": mutated(
            MINIMAL, _set(scan={"kind": "pr", "base_commit": BASE}, baseline={"status": "missing"})
        ),
        "baseline-rejected": mutated(
            MINIMAL,
            _set(
                scan={"kind": "pr", "base_commit": BASE},
                baseline={
                    "status": "rejected",
                    "commit": HEAD,
                    "reason": "baseline-commit-mismatch",
                },
            ),
        ),
        "baseline-not-evaluated": mutated(
            PR_REPORT, lambda i: i["baseline"].update(not_evaluated=3)
        ),
        "effective-config": mutated(MINIMAL, _set(effective_config=CONFIG)),
        "scoring": mutated(
            MINIMAL,
            _set(scoring={"active_variant": "B", "config_version": "2026-11-17", "shadow": False}),
        ),
        "service-context": mutated(
            MINIMAL,
            _set(
                service_context={
                    "tier": {"value": 1, "source": "catalog"},
                    "internet_facing": {"value": True, "source": "default"},
                    "catalog_id": "payments-api",
                }
            ),
        ),
        "service-context-unknown-values": mutated(
            MINIMAL,
            _set(
                service_context={
                    "tier": {"source": "default"},
                    "internet_facing": {"value": None, "source": "repository"},
                }
            ),
        ),
        "enrichment-both-feeds": mutated(
            MINIMAL,
            _set(
                enrichment=[
                    SNAPSHOT,
                    {**SNAPSHOT, "feed": "kev", "content": {"catalogVersion": "1"}},
                ]
            ),
        ),
        "correlation-version": mutated(MINIMAL, _set(correlation_version="1")),
    }
)
INVALID.update(
    {
        "scan-kind-unknown": mutated(MINIMAL, _set(scan={"kind": "nightly"})),
        "scan-base-commit-short": mutated(MINIMAL, _set(scan={"kind": "pr", "base_commit": "abc"})),
        "scan-pull-request-zero": mutated(
            MINIMAL, _set(scan={"kind": "pr", "base_commit": BASE, "pull_request": 0})
        ),
        "scan-unknown-key": mutated(MINIMAL, _set(scan={"kind": "full", "branch": "main"})),
        "baseline-status-unknown": mutated(MINIMAL, _set(baseline={"status": "stale"})),
        "baseline-source-unknown": mutated(
            PR_REPORT, lambda i: i["baseline"].update(source="email")
        ),
        "baseline-negative-count": mutated(PR_REPORT, lambda i: i["baseline"].update(new=-1)),
        "baseline-reason-not-a-code": mutated(
            MINIMAL,
            _set(baseline={"status": "rejected", "reason": "Commit diverso!"}),
        ),
        "baseline-resolved-bad-fingerprint": mutated(
            PR_REPORT, lambda i: i["baseline"]["resolved"][0].update(fingerprint="abc")
        ),
        "baseline-unknown-key": mutated(PR_REPORT, lambda i: i["baseline"].update(extra=1)),
        "effective-config-unknown-key": mutated(
            MINIMAL, _set(effective_config={"version": 1, "image": "x"})
        ),
        "effective-config-bad-version": mutated(MINIMAL, _set(effective_config={"version": 2})),
        "scoring-variant-c": mutated(
            MINIMAL, _set(scoring={"active_variant": "C", "config_version": "1"})
        ),
        "scoring-without-version": mutated(MINIMAL, _set(scoring={"active_variant": "A"})),
        "service-tier-4": mutated(
            MINIMAL,
            _set(
                service_context={
                    "tier": {"value": 4, "source": "catalog"},
                    "internet_facing": {"source": "default"},
                }
            ),
        ),
        "service-source-unknown": mutated(
            MINIMAL,
            _set(
                service_context={
                    "tier": {"value": 1, "source": "guess"},
                    "internet_facing": {"source": "default"},
                }
            ),
        ),
        "enrichment-three": mutated(MINIMAL, _set(enrichment=[SNAPSHOT, SNAPSHOT, SNAPSHOT])),
        "enrichment-origin-is-a-url": mutated(
            MINIMAL, _set(enrichment=[{**SNAPSHOT, "origin": "https://evil.example"}])
        ),
        "enrichment-bad-sha": mutated(MINIMAL, _set(enrichment=[{**SNAPSHOT, "sha256": "xyz"}])),
        "enrichment-unknown-feed": mutated(MINIMAL, _set(enrichment=[{**SNAPSHOT, "feed": "osv"}])),
        "correlation-version-not-a-number": mutated(MINIMAL, _set(correlation_version="v1")),
    }
)


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


def test_complete_with_failed_plugin_is_rejected() -> None:
    assert errors_of(VALIDATOR, mutated(MINIMAL, _set(plugins=[PLUGIN_FAILED]))) != []


def test_partial_without_failed_plugin_stays_valid() -> None:
    """Un solo verso: `failed` implica `partial`, non il contrario."""
    assert errors_of(VALIDATOR, mutated(MINIMAL, _set(status="partial"))) == []
