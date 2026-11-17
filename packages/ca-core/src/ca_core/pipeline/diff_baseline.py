"""Passo `diff_baseline` (K-17, ADR-0025 §3): stato di ogni finding rispetto alla baseline.

Confronto per fingerprint; poi un secondo passaggio accoppia un `new` e un `resolved` che hanno la
stessa chiave senza percorso (file rinominato). Funzione pura: nessun I/O.

Un finding della baseline che manca perché uno dei suoi strumenti non è riuscito in questa scansione
non è risolto: non entra nei conteggi e il report lo dice (`not_evaluated`). Per i finding che non
vengono da un plugin (la policy delle licenze, `ca-core`) vale l'esito di tutti i plugin, perché
dipendono dall'output di più di uno.
"""

from collections import defaultdict
from collections.abc import Sequence

from pydantic import BaseModel, ConfigDict

from ca_core.models.finding import BaselineState, Finding
from ca_core.models.scan_report import (
    Baseline,
    BaselineStatus,
    Outcome,
    PluginRun,
    ResolvedFinding,
    Warning_,
)
from ca_core.pipeline.baseline import LoadedBaseline


class _Frozen(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class DiffResult(_Frozen):
    findings: list[Finding]
    baseline: Baseline
    warnings: list[Warning_] = []


def _position(finding: Finding) -> tuple[str | None, int | None, int | None]:
    location = finding.location
    return location.path, location.start_line, location.end_line


def _unrelated(status: BaselineStatus, reason: str | None) -> Baseline:
    return Baseline(status=status, reason=reason)


def diff_baseline(
    findings: Sequence[Finding], plugins: Sequence[PluginRun], loaded: LoadedBaseline
) -> DiffResult:
    """Finding con lo stato rispetto alla baseline e la sezione `baseline` del report."""
    if loaded.status is not BaselineStatus.VALID or loaded.report is None:
        return DiffResult(
            findings=list(findings), baseline=_unrelated(loaded.status, loaded.reason)
        )
    assert loaded.source is not None
    report = loaded.report
    before = {f.fingerprint: f for f in report.findings}
    now = {f.fingerprint for f in findings}
    ok = {p.name for p in plugins if p.outcome is Outcome.OK}
    all_ok = all(p.outcome is Outcome.OK for p in plugins)
    known = {p.name for p in plugins} | {p.name for p in report.plugins}

    def evaluable(finding: Finding) -> bool:
        return all((t in ok) if t in known else all_ok for t in finding.tools)

    gone = [f for fp, f in sorted(before.items()) if fp not in now]
    resolved_pool = [f for f in gone if evaluable(f)]
    not_evaluated = len(gone) - len(resolved_pool)

    # secondo passaggio: file rinominati, solo gruppi di uno contro uno su percorsi diversi
    new_by_key: dict[str, list[Finding]] = defaultdict(list)
    gone_by_key: dict[str, list[Finding]] = defaultdict(list)
    for f in findings:
        if f.fingerprint not in before and f.pathless_key is not None:
            new_by_key[f.pathless_key].append(f)
    for f in resolved_pool:
        if f.pathless_key is not None:
            gone_by_key[f.pathless_key].append(f)
    moved: dict[str, Finding] = {}  # fingerprint del nuovo -> finding della baseline
    for key, news in new_by_key.items():
        olds = gone_by_key.get(key, [])
        if len(news) == 1 and len(olds) == 1:
            new, old = news[0], olds[0]
            if new.location.path and old.location.path and new.location.path != old.location.path:
                moved[new.fingerprint] = old
    taken = {old.fingerprint for old in moved.values()}

    out: list[Finding] = []
    updated: list[str] = []
    for f in findings:
        old = before.get(f.fingerprint) or moved.get(f.fingerprint)
        if old is None:
            out.append(f.model_copy(update={"baseline_state": BaselineState.NEW}))
            continue
        previous = old.location.path if f.fingerprint in moved else None
        out.append(
            f.model_copy(
                update={"baseline_state": BaselineState.EXISTING, "previous_path": previous}
            )
        )
        if _position(f) != _position(old) or f.level != old.level:
            updated.append(f.fingerprint)
    resolved = [
        ResolvedFinding(
            fingerprint=f.fingerprint, rule_id=f.rule_id, title=f.title, path=f.location.path
        )
        for f in resolved_pool
        if f.fingerprint not in taken
    ]
    states = [f.baseline_state for f in out]
    baseline = Baseline(
        status=BaselineStatus.VALID,
        commit=report.repository.commit,
        source=loaded.source,
        new=states.count(BaselineState.NEW),
        existing=states.count(BaselineState.EXISTING),
        resolved=resolved,
        updated=sorted(updated),
        not_evaluated=not_evaluated,
    )
    return DiffResult(findings=out, baseline=baseline)
