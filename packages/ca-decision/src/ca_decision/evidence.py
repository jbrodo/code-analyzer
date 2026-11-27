"""Cosa può leggere il motore di un finding (DE-02; ADR-0036, emendamento del 2026-11-27).

Nel dubbio non si dà nulla e decide l'umano. Nell'ordine:

1. Solo finding SAST, e non quelli delle regole che segnalano segreti.
2. Se la ricerca dei segreti non è riuscita in questa scansione, **niente codice**.
3. Se il file ha un finding di segreti, niente codice di quel file.
4. Se un segreto indica un percorso che nel commit non c'è, **niente codice**: gitleaks legge la
   storia, e dopo una rinomina il segreto resta segnalato col nome vecchio mentre sta nel nuovo.
5. In ciò che resta si oscura quel che somiglia a una credenziale (`ca_decision.redaction`).

Chi chiama deve passare **il testo del file al commit del report**: la ricerca dei segreti, con la
storia git, non vede le modifiche non registrate (DE-04). Nessun I/O e nessun log qui.
"""

from collections.abc import Collection
from dataclasses import dataclass
from importlib.resources import files
from typing import Literal

from ca_core.models.decision import Evidence, EvidenceSettings
from ca_core.models.finding import Category, Finding
from ca_core.models.scan_report import Outcome, ScanReport
from ca_decision.redaction import MASK, redact

SECRET_SCANNER = "gitleaks"
CUT = " […]"

Withheld = Literal[
    "categoria",
    "regola-sui-segreti",
    "ricerca-segreti-non-disponibile",
    "segreto-nel-file",
    "segreto-in-percorso-scomparso",
    "senza-posizione",
    "troppo-grande",
]


@dataclass(frozen=True)
class Selection:
    """L'evidenza, oppure il motivo per cui non c'è."""

    evidence: Evidence | None = None
    withheld: Withheld | None = None
    redactions: int = 0  # segni di oscuramento che il motore vede


def packaged_settings() -> EvidenceSettings:
    return EvidenceSettings.model_validate_json(
        files("ca_decision").joinpath("evidence.json").read_bytes()
    )


def secret_paths(report: ScanReport) -> set[str]:
    """I percorsi di tutti i finding di segreti, qualunque sia il loro stato, comprese le altre
    posizioni raccolte dalla deduplicazione."""
    paths = set()
    for finding in report.findings:
        if finding.category is not Category.SECRET:
            continue
        occurrences = finding.evidence.get("occurrences", [])
        for path in [finding.location.path, *(o.get("path") for o in occurrences)]:
            if path:
                paths.add(path)
    return paths


def blocked(
    finding: Finding,
    report: ScanReport,
    committed_paths: Collection[str],
    settings: EvidenceSettings,
) -> Withheld | None:
    """Le regole 1-4, senza leggere codice."""
    if finding.category is not Category.SAST:
        return "categoria"
    if finding.rule_id in settings.secret_rules:
        return "regola-sui-segreti"
    scanned = [p for p in report.plugins if p.name == SECRET_SCANNER]
    if not scanned or any(p.outcome is not Outcome.OK for p in scanned):
        return "ricerca-segreti-non-disponibile"
    if finding.location.path is None or finding.location.start_line is None:
        return "senza-posizione"
    secrets = secret_paths(report)
    if finding.location.path in secrets:
        return "segreto-nel-file"
    if not secrets <= set(committed_paths):
        return "segreto-in-percorso-scomparso"
    return None


def _clip(line: str, limit: int) -> tuple[str, bool]:
    return (line[:limit] + CUT, True) if len(line) > limit else (line, False)


def _render(
    header: str, lines: list[str], first: int, last: int, marked: range, limit: int
) -> tuple[str, bool]:
    rows, cut = [], False
    for number in range(first, last + 1):
        line, clipped = _clip(lines[number - 1], limit)
        cut = cut or clipped
        rows.append(f"{'>' if number in marked else ' '} {number}: {line}")
    return header + "\n".join(rows), cut


def select_evidence(
    finding: Finding,
    source: str,
    report: ScanReport,
    committed_paths: Collection[str],
    settings: EvidenceSettings,
) -> Selection:
    """`source` è il file del finding al commit del report; `committed_paths` i file di quel
    commit."""
    reason = blocked(finding, report, committed_paths, settings)
    if reason:
        return Selection(withheld=reason)
    path, start = finding.location.path, finding.location.start_line
    assert path is not None and start is not None
    # Si oscura il file intero: un blocco che comincia fuori dalla finestra si riconosce lo stesso.
    text, _ = redact(source.replace("\r\n", "\n"), settings)
    message, _ = redact(finding.message, settings)
    lines = text.split("\n")
    if start > len(lines):
        return Selection(withheld="senza-posizione")
    end = min(max(finding.location.end_line or start, start), len(lines))
    message, message_cut = _clip(" ".join(message.split()), settings.max_line_characters)
    header = f"Regola: {finding.rule_id} ({finding.tool})\nMessaggio: {message}\nFile: {path}\n\n"
    for window in range(settings.window_lines, -1, -1):
        body, line_cut = _render(
            header,
            lines,
            max(1, start - window),
            min(len(lines), end + window),
            range(start, end + 1),
            settings.max_line_characters,
        )
        if len(body) <= settings.max_characters:
            reduced = message_cut or line_cut or window < settings.window_lines
            evidence = Evidence(text=body, reduced=reduced)
            return Selection(evidence=evidence, redactions=body.count(MASK))
    return Selection(withheld="troppo-grande")
