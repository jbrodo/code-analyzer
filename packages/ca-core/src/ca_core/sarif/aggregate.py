"""SARIF aggregato (K-14, ADR-0011): un solo `run` con driver `code-analyzer`.

Layout (contratto pubblico, coperto da `tests/contract/test_aggregate_sarif_contract.py`):

- `tool.driver.name = "code-analyzer"`; gli scanner eseguiti in `tool.extensions` con versione.
- un `result` per finding con posizione; `partialFingerprints["codeAnalyzer/v1"]` = fingerprint;
  `level`: critico e alto `error`, medio `warning`, basso `note`.
- `properties`: `level`, `level_source`, `category`, `tools`, `status`, `purl` se c'è;
  `security-severity` solo con un CVSS, mai inventato.
- finding senza `location.path` e avvisi del report: `invocations[0].toolExecutionNotifications`.
- con una baseline valida (ADR-0025): `baselineState` su ogni risultato (`new`, `unchanged` o
  `updated` se posizione o livello sono cambiati); i risolti compaiono come risultati `absent`,
  senza il resto dei campi del finding. Senza baseline il campo manca.
- eccezione applicata: `suppressions` con `kind: external` e la motivazione.
- URI relativi alla radice, senza `uriBaseId`; nessuno `snippet`; il messaggio è quello del
  finding (per i segreti già sintetizzato, ADR-0012).
- output deterministico (chiavi ordinate, ordine dei finding del report) e validato contro lo
  schema SARIF 2.1.0 prima di essere restituito.
"""

import json
import re
from collections.abc import Mapping
from datetime import UTC
from typing import Any

from ca_core.formats import SARIF_VERSION
from ca_core.models.finding import BaselineState, Finding, Level
from ca_core.models.scan_report import (
    AppliedException,
    BaselineStatus,
    ResolvedFinding,
    ScanReport,
)
from ca_core.sarif.errors import SarifError, SarifErrorCode
from ca_core.schema_validation import SchemaStore
from ca_core.scoring.levels import best_cvss

DRIVER_NAME = "code-analyzer"
FINGERPRINT_KEY = "codeAnalyzer/v1"
SARIF_SCHEMA_URI = "https://json.schemastore.org/sarif-2.1.0.json"
_SARIF_LEVEL = {
    Level.CRITICAL: "error",
    Level.HIGH: "error",
    Level.MEDIUM: "warning",
    Level.LOW: "note",
}
_UNRESERVED = re.compile(rb"[A-Za-z0-9._~-]")


def _uri(path: str) -> str:
    def encode(segment: str) -> str:
        raw = segment.encode("utf-8", "surrogateescape")
        return "".join(chr(b) if _UNRESERVED.fullmatch(bytes([b])) else f"%{b:02X}" for b in raw)

    return "/".join(encode(s) for s in path.split("/"))


def _level(finding: Finding) -> str:
    return _SARIF_LEVEL.get(finding.level, "warning") if finding.level else "warning"


def _properties(finding: Finding) -> dict[str, Any]:
    props: dict[str, Any] = {
        "level": finding.level.value if finding.level else None,
        "level_source": finding.level_source.value if finding.level_source else None,
        "category": finding.category.value,
        "tools": sorted(finding.tools),
        "status": finding.status.value,
    }
    props = {k: v for k, v in props.items() if v is not None}
    if finding.location.purl:
        props["purl"] = finding.location.purl
    cvss = best_cvss(finding)
    if cvss is not None:
        props["security-severity"] = f"{cvss:.1f}"
    return props


def _state(finding: Finding, updated: frozenset[str]) -> str | None:
    if finding.baseline_state is BaselineState.NEW:
        return "new"
    if finding.baseline_state is BaselineState.EXISTING:
        return "updated" if finding.fingerprint in updated else "unchanged"
    return None


def _absent(resolved: ResolvedFinding, rule_index: int) -> dict[str, Any]:
    result: dict[str, Any] = {
        "ruleId": resolved.rule_id,
        "ruleIndex": rule_index,
        "level": "note",
        "message": {"text": resolved.title},
        "partialFingerprints": {FINGERPRINT_KEY: resolved.fingerprint},
        "baselineState": "absent",
    }
    if resolved.path is not None:
        result["locations"] = [
            {"physicalLocation": {"artifactLocation": {"uri": _uri(resolved.path)}}}
        ]
    return result


def _result(
    finding: Finding,
    rule_index: int,
    applied: Mapping[str, AppliedException],
    updated: frozenset[str] = frozenset(),
) -> dict[str, Any]:
    assert finding.location.path is not None
    physical: dict[str, Any] = {"artifactLocation": {"uri": _uri(finding.location.path)}}
    region = {
        k: v
        for k, v in (
            ("startLine", finding.location.start_line),
            ("endLine", finding.location.end_line),
        )
        if v is not None
    }
    if region:
        physical["region"] = region
    result: dict[str, Any] = {
        "ruleId": finding.rule_id,
        "ruleIndex": rule_index,
        "level": _level(finding),
        "message": {"text": finding.message},
        "locations": [{"physicalLocation": physical}],
        "partialFingerprints": {FINGERPRINT_KEY: finding.fingerprint},
        "properties": _properties(finding),
    }
    state = _state(finding, updated)
    if state is not None:
        result["baselineState"] = state
    exception = applied.get(finding.fingerprint)
    if exception is not None:
        result["suppressions"] = [
            {"kind": "external", "status": "accepted", "justification": exception.reason}
        ]
    return result


def build_aggregate(report: ScanReport) -> dict[str, Any]:
    applied = {e.fingerprint: e for e in report.exceptions}
    located = [f for f in report.findings if f.location.path is not None]
    baseline = (
        report.baseline
        if report.baseline and report.baseline.status is BaselineStatus.VALID
        else None
    )
    resolved = baseline.resolved if baseline else []
    updated = frozenset(baseline.updated) if baseline else frozenset()
    rules = sorted({f.rule_id for f in located} | {r.rule_id for r in resolved})
    index = {rule: i for i, rule in enumerate(rules)}
    notifications: list[dict[str, Any]] = [
        {
            "level": _level(f),
            "message": {"text": f.message},
            "descriptor": {"id": f.rule_id},
            "properties": _properties(f) | {"fingerprint": f.fingerprint},
        }
        for f in report.findings
        if f.location.path is None
    ]
    notifications += [
        {
            "level": "warning",
            "message": {"text": w.message},
            "descriptor": {"id": w.code},
            **({"properties": {"subject": w.subject}} if w.subject else {}),
        }
        for w in report.warnings
    ]
    run: dict[str, Any] = {
        "tool": {
            "driver": {"name": DRIVER_NAME, "rules": [{"id": rule} for rule in rules]},
            "extensions": [
                {"name": p.name, "version": p.version}
                for p in sorted(report.plugins, key=lambda p: p.name)
            ],
        },
        "invocations": [
            {
                "executionSuccessful": report.status.value == "complete",
                "startTimeUtc": report.started_at.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
                "toolExecutionNotifications": notifications,
            }
        ],
        "results": [
            *(_result(f, index[f.rule_id], applied, updated) for f in located),
            *(_absent(r, index[r.rule_id]) for r in resolved),
        ],
    }
    return {"$schema": SARIF_SCHEMA_URI, "version": SARIF_VERSION, "runs": [run]}


def aggregate_sarif(report: ScanReport, store: SchemaStore) -> bytes:
    """SARIF aggregato in byte; `SarifError(SCHEMA)` se non valida (nulla viene scritto)."""
    document = build_aggregate(report)
    errors = store.validate_sarif(document)
    if errors:
        raise SarifError(
            SarifErrorCode.SCHEMA, "SARIF aggregato non conforme a 2.1.0", tuple(errors)
        )
    return json.dumps(document, sort_keys=True, separators=(",", ":")).encode()
