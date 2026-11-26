"""Equivalenza tra `ScanReport` e `schemas/scan-report.schema.json`.

ECCEZIONE VOLUTA alla regola di C-07 (i test di contratto non importano `ca_core.models`):
vedi `test_finding_model_equivalence.py`. Ogni differenza non elencata in `MODEL_ONLY` fa fallire.
"""

import pytest
from conftest import Json, case_params, errors_of, make_validator, mutated
from pydantic import ValidationError
from test_scan_report_contract import (
    BASE,
    FINDING,
    FP,
    INVALID,
    MINIMAL,
    NEW,
    OLD,
    PLUGIN_OK,
    PR_REPORT,
    PR_SCAN,
    SNAPSHOT,
    VALID,
)

from ca_core.models import ScanReport

VALIDATOR = make_validator("scan-report")

# Rifiutati solo dal modello (ADR-0003, "Dove vive un'invariante"): lo schema li accetta.
MODEL_ONLY: dict[str, Json] = {
    "plugin-names-not-unique": mutated(MINIMAL, lambda i: i.update(plugins=[PLUGIN_OK, PLUGIN_OK])),
    "disabled-plugin-also-run": mutated(MINIMAL, lambda i: i.update(disabled_plugins=["bandit"])),
    # C-04: invarianti tra sezioni, che lo schema non esprime
    "pr-scan-without-base-commit": mutated(MINIMAL, lambda i: i.update(scan={"kind": "pr"})),
    "full-scan-with-base-commit": mutated(
        MINIMAL, lambda i: i.update(scan={"kind": "full", "base_commit": BASE})
    ),
    "baseline-valid-without-commit": mutated(PR_REPORT, lambda i: i["baseline"].pop("commit")),
    "baseline-missing-with-counts": mutated(
        MINIMAL,
        lambda i: i.update(scan=PR_SCAN, baseline={"status": "missing", "new": 2}),
    ),
    "baseline-rejected-without-reason": mutated(
        MINIMAL, lambda i: i.update(scan=PR_SCAN, baseline={"status": "rejected"})
    ),
    "baseline-valid-with-reason": mutated(
        PR_REPORT, lambda i: i["baseline"].update(reason="baseline-partial")
    ),
    "baseline-on-a-full-scan": mutated(PR_REPORT, lambda i: i.update(scan={"kind": "full"})),
    "baseline-count-of-new-wrong": mutated(PR_REPORT, lambda i: i["baseline"].update(new=5)),
    "baseline-count-of-existing-wrong": mutated(
        PR_REPORT, lambda i: i["baseline"].update(existing=0)
    ),
    "finding-with-state-but-no-baseline": mutated(MINIMAL, lambda i: i.update(findings=[NEW])),
    "finding-without-state-with-valid-baseline": mutated(
        PR_REPORT, lambda i: i.update(findings=[NEW, {**OLD, "baseline_state": None}])
    ),
    "new-findings-only-effective-without-baseline": mutated(
        MINIMAL, lambda i: i["gate"].update(effective_mode="new-findings-only")
    ),
    "new-findings-only-effective-with-missing-baseline": mutated(
        MINIMAL,
        lambda i: (
            i["gate"].update(effective_mode="new-findings-only"),
            i.update(scan=PR_SCAN, baseline={"status": "missing"}),
        ),
    ),
    "baseline-updated-not-existing": mutated(
        PR_REPORT, lambda i: i["baseline"].update(updated=[NEW["fingerprint"]])
    ),
    "baseline-updated-duplicate": mutated(
        PR_REPORT,
        lambda i: i["baseline"].update(updated=[OLD["fingerprint"], OLD["fingerprint"]]),
    ),
    "baseline-missing-with-updated": mutated(
        MINIMAL,
        lambda i: i.update(scan=PR_SCAN, baseline={"status": "missing", "updated": [FP]}),
    ),
    "enrichment-same-feed-twice": mutated(
        MINIMAL, lambda i: i.update(enrichment=[SNAPSHOT, SNAPSHOT])
    ),
    "embedded-finding-tool-not-first": mutated(
        MINIMAL,
        lambda i: i.update(findings=[{**FINDING, "tool": "z", "tools": ["a", "z"]}]),
    ),
    "embedded-finding-end-line-before-start-line": mutated(
        MINIMAL,
        lambda i: i.update(
            findings=[{**FINDING, "location": {"repository": "r", "start_line": 5, "end_line": 4}}]
        ),
    ),
}


def _model_accepts(instance: object) -> bool:
    try:
        ScanReport.model_validate(instance)
    except ValidationError:
        return False
    return True


@pytest.mark.parametrize(
    "instance", case_params(VALID, "valid:") + case_params(INVALID, "invalid:")
)
def test_model_and_schema_agree(instance: Json) -> None:
    assert _model_accepts(instance) == (errors_of(VALIDATOR, instance) == [])


def test_schema_rejects_version_true() -> None:
    """`True == 1` in Python: `const: 1` non deve accettarlo."""
    assert errors_of(VALIDATOR, mutated(MINIMAL, lambda i: i.update(version=True))) != []


def test_model_rejects_version_true() -> None:
    assert not _model_accepts(mutated(MINIMAL, lambda i: i.update(version=True)))


@pytest.mark.parametrize("instance", case_params(MODEL_ONLY))
def test_model_only_rules_are_rejected_by_model_and_accepted_by_schema(instance: Json) -> None:
    assert not _model_accepts(instance)
    assert errors_of(VALIDATOR, instance) == []
