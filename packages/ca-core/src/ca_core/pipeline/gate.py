"""Valutazione del gate (K-13, ADR-0009, ADR-0010, ADR-0005). IPOTESI D-0009-A.

Funzione pura sul report: nessun accesso al disco né ai flag. Soglia di blocco, per precedenza:
`fail_on` (flag CLI), `report.gate.block_on`, `DEFAULT_BLOCK_ON`. Una lista vuota è una scelta
esplicita: nulla blocca. In Fase 1 la modalità è sempre `all` (anche `new-findings-only`, ADR-0009).

Non contano solo i finding `accettato` (eccezione attiva, ADR-0014); è la lettura più severa tra gli
stati. Exit: 0 superato, 1 fallito, 2 errore. Con 2: scansione parziale, un plugin con
`signature: skipped` (ADR-0005), o un finding senza livello (report non prodotto dalla pipeline).
`allow_partial` valuta comunque i finding e segnala i motivi in `reasons`.
"""

from collections.abc import Sequence
from typing import Literal

from pydantic import BaseModel, ConfigDict

from ca_core.models.finding import Category, Finding, Level, Status
from ca_core.models.scan_report import Outcome, ReportStatus, ScanReport, Signature

DEFAULT_BLOCK_ON: tuple[Level, ...] = (Level.CRITICAL, Level.HIGH)


class _Frozen(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class GateFinding(_Frozen):
    fingerprint: str
    level: Level | None
    category: Category
    rule_id: str


class GateResult(_Frozen):
    exit_code: Literal[0, 1, 2]
    block_on: list[Level]
    block_on_source: Literal["cli", "config", "default"]
    blocking: list[GateFinding]
    warned: list[GateFinding]
    # codici: `partial-scan`, `signature-skipped`, `finding-without-level`
    reasons: list[str]


def _brief(finding: Finding) -> GateFinding:
    return GateFinding(
        fingerprint=finding.fingerprint,
        level=finding.level,
        category=finding.category,
        rule_id=finding.rule_id,
    )


def evaluate_gate(
    report: ScanReport,
    *,
    fail_on: Sequence[Level] | None = None,
    allow_partial: bool = False,
) -> GateResult:
    source: Literal["cli", "config", "default"]
    if fail_on is not None:
        block_on, source = list(fail_on), "cli"
    elif report.gate.block_on is not None:
        block_on, source = list(report.gate.block_on), "config"
    else:
        block_on, source = list(DEFAULT_BLOCK_ON), "default"
    warn_on = set(report.gate.warn_on or ())

    reasons: list[str] = []
    if report.status is ReportStatus.PARTIAL or any(
        p.outcome is Outcome.FAILED for p in report.plugins
    ):
        reasons.append("partial-scan")
    if any(p.signature is Signature.SKIPPED for p in report.plugins):
        reasons.append("signature-skipped")

    active = [f for f in report.findings if f.status is not Status.ACCEPTED]
    if any(f.level is None for f in active):
        reasons.append("finding-without-level")
    blocking = [_brief(f) for f in active if f.level is not None and f.level in block_on]
    warned = [
        _brief(f) for f in active if f.level is not None and f.level in warn_on - set(block_on)
    ]

    if "finding-without-level" in reasons or (reasons and not allow_partial):
        exit_code: Literal[0, 1, 2] = 2
    else:
        exit_code = 1 if blocking else 0
    return GateResult(
        exit_code=exit_code,
        block_on=block_on,
        block_on_source=source,
        blocking=blocking,
        warned=warned,
        reasons=reasons,
    )
