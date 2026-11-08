"""Costruttori condivisi dai test dei passi della pipeline (K-06..K-15)."""

from datetime import UTC, datetime
from typing import Any

from ca_core.fingerprint import compute_fingerprint
from ca_core.models.finding import Category, Finding, Level, Location
from ca_core.models.scan_report import ScanReport

NOW = datetime(2026, 6, 1, 12, 0, tzinfo=UTC)
DIGEST = "sha256:" + "d" * 64


def fp_of(n: str) -> str:
    return compute_fingerprint("code", n, "t", n, "")


def finding(
    n: str = "a",
    *,
    category: Category = Category.SAST,
    tool: str = "bandit",
    path: str | None = "app/run.py",
    level: Level | None = None,
    evidence: dict[str, Any] | None = None,
    **extra: Any,
) -> Finding:
    fp = fp_of(n)
    return Finding(
        id=fp,
        fingerprint=fp,
        category=category,
        rule_id=f"r-{n}",
        tool=tool,
        tools=[tool],
        title=f"t-{n}",
        message=f"m-{n}",
        location=Location(repository="repo", path=path, start_line=3 if path else None),
        evidence={tool: evidence or {}},
        level=level,
        first_seen=NOW,
        last_seen=NOW,
        **extra,
    )


def plugin(name: str = "bandit", **kv: Any) -> dict[str, Any]:
    return {
        "name": name,
        "version": "1.0.0",
        "digest": DIGEST,
        "signature": "verified",
        "isolation": "gvisor",
        "duration_seconds": 1.0,
        "outcome": "ok",
        **kv,
    }


def report(findings: list[Finding] | None = None, **kv: Any) -> ScanReport:
    data: dict[str, Any] = {
        "version": 1,
        "status": "complete",
        "started_at": NOW,
        "duration_seconds": 1.0,
        "repository": {"name": "repo", "history": "full"},
        "gate": {"mode": "all", "effective_mode": "all"},
        "plugins": [plugin()],
        "findings": findings or [],
    }
    data.update(kv)
    return ScanReport.model_validate(data)
