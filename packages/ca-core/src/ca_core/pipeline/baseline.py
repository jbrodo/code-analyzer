"""Passo `load_baseline` (K-16, ADR-0025): lettura e validazione della baseline.

La baseline è un report di una scansione completa del commit base, fornito come file da fuori dal
repository. Qui non si calcola nulla sui file cambiati (ADR-0025 §4: nessuna restrizione in Fase 2).

Una baseline non utilizzabile non blocca la scansione: la modalità PR avvisa e valuta tutto, con la
configurazione del file della PR. Ogni rifiuto ha un codice stabile in `Baseline.reason`.
"""

import posixpath
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, ValidationError

from ca_core.models.config import CodeAnalyzerConfig
from ca_core.models.scan_report import (
    BaselineSourceKind,
    BaselineStatus,
    ReportStatus,
    ScanKind,
    ScanReport,
    Warning_,
)
from ca_core.ports import BaselineLookup, BaselineOutcome, SourceError, SourceReader

MAX_BASELINE_BYTES = 64 * 1024 * 1024


class RejectReason(StrEnum):
    INSIDE_WORKSPACE = "baseline-inside-workspace"
    UNREADABLE = "baseline-unreadable"
    INVALID = "baseline-invalid"
    COMMIT_MISMATCH = "baseline-commit-mismatch"
    NOT_FULL = "baseline-not-full"


class _Frozen(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class LoadedBaseline(_Frozen):
    status: BaselineStatus
    reason: str | None = None
    report: ScanReport | None = None  # solo con `valid`
    source: BaselineSourceKind | None = None
    config: CodeAnalyzerConfig  # quella con cui girano tutti i passi (ADR-0025 §5)
    warnings: list[Warning_]


def _warning(code: str, message: str, subject: str | None = None) -> Warning_:
    return Warning_(code=code, message=message, subject=subject)


def _inside(location: str, workspace: str) -> bool:
    target, root = posixpath.normpath(location), posixpath.normpath(workspace)
    return target == root or target.startswith(root.rstrip("/") + "/")


def changed_sections(head: CodeAnalyzerConfig, base: CodeAnalyzerConfig) -> list[str]:
    """Sezioni di primo livello che differiscono (`config-changed-in-pr`)."""
    left, right = head.model_dump(mode="json"), base.model_dump(mode="json")
    return sorted(k for k in left.keys() | right.keys() if left.get(k) != right.get(k))


def _unusable(
    reason: RejectReason, message: str, head_config: CodeAnalyzerConfig
) -> LoadedBaseline:
    return LoadedBaseline(
        status=BaselineStatus.REJECTED,
        reason=reason.value,
        config=head_config,
        warnings=[
            _warning(reason.value, message),
            _warning(
                "pr-config-from-head",
                "Nessuna configurazione del branch base: vale quella della PR.",
            ),
        ],
    )


def load_baseline(
    lookup: BaselineLookup | None,
    *,
    base_commit: str,
    workspace: str,
    head_config: CodeAnalyzerConfig,
    reader: SourceReader,
    max_bytes: int = MAX_BASELINE_BYTES,
) -> LoadedBaseline:
    """Baseline valida con la sua configurazione, oppure `missing`/`rejected` con gli avvisi.

    `workspace` e il percorso della baseline sono già risolti dal chiamante (nessun symlink).
    """
    if lookup is None or lookup.outcome is BaselineOutcome.MISSING or lookup.location is None:
        return LoadedBaseline(
            status=BaselineStatus.MISSING,
            config=head_config,
            warnings=[
                _warning(
                    "baseline-missing", "Nessuna baseline: tutti i finding valgono come nuovi."
                ),
                _warning(
                    "pr-config-from-head",
                    "Nessuna configurazione del branch base: vale quella della PR.",
                ),
            ],
        )
    if _inside(lookup.location, workspace):
        return _unusable(
            RejectReason.INSIDE_WORKSPACE,
            "La baseline sta dentro la directory analizzata: una PR potrebbe contenerla.",
            head_config,
        )
    directory, name = posixpath.split(lookup.location)
    try:
        data = reader.read_file(directory or "/", name, max_bytes)
    except SourceError:
        return _unusable(
            RejectReason.UNREADABLE, "La baseline non è leggibile o supera il limite.", head_config
        )
    try:
        report = ScanReport.model_validate_json(data)
    except ValidationError:
        return _unusable(RejectReason.INVALID, "La baseline non è un report valido.", head_config)
    if report.scan.kind is not ScanKind.FULL:
        return _unusable(
            RejectReason.NOT_FULL, "La baseline non è di una scansione completa.", head_config
        )
    if report.repository.commit != base_commit:
        return _unusable(
            RejectReason.COMMIT_MISMATCH,
            "Il commit della baseline è diverso dal commit base: una baseline di un altro "
            "commit può nascondere finding.",
            head_config,
        )
    warnings: list[Warning_] = []
    if report.status is ReportStatus.PARTIAL:
        failed = sorted(p.name for p in report.plugins if p.outcome.value == "failed")
        warnings.append(
            _warning(
                "baseline-partial",
                "La baseline è parziale: i finding degli strumenti falliti risultano nuovi.",
                ", ".join(failed) or None,
            )
        )
    config = report.effective_config
    if config is None:
        warnings.append(
            _warning(
                "baseline-without-config",
                "La baseline non registra la configurazione: vale quella della PR.",
            )
        )
        config = head_config
    else:
        changed = changed_sections(head_config, config)
        if changed:
            warnings.append(
                _warning(
                    "config-changed-in-pr",
                    "La configurazione della PR differisce da quella del branch base; "
                    "vale la seconda.",
                    ", ".join(changed),
                )
            )
    return LoadedBaseline(
        status=BaselineStatus.VALID,
        report=report,
        source=lookup.source,
        config=config,
        warnings=warnings,
    )
