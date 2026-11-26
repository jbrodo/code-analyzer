"""Formato del commento e della check run (N-03, ADR-0027). Funzioni pure sul report.

Tutto il testo che viene dal report è non fidato (titoli, messaggi e percorsi arrivano dal
repository e dagli scanner). Qui diventa testo semplice: niente caratteri di controllo né di
formattazione bidirezionale, ogni segno di punteggiatura ASCII preceduto da un backslash (Markdown
e HTML non si attivano), menzioni, riferimenti `#n`, indirizzi, hash di commit e collegamenti
automatici interrotti da un carattere invisibile, lunghezza limitata. Nessun collegamento è
costruito da quei testi. Il report non contiene frammenti di codice né valori di segreti
(ADR-0012); un test lo prova comunque.

I limiti di GitHub sono quelli di `ca_integrations.limits`, scritti a memoria: **non verificati
alla fonte** (nessun accesso alla rete in questo lavoro). Il corpo resta sotto
`GITHUB_COMMENT_MAX_CHARS` meno un margine, e un finding non si taglia mai a metà.
"""

import re
import unicodedata
from collections.abc import Sequence

from ca_core.models.finding import BaselineState, Finding, Level, Status
from ca_core.models.scan_report import BaselineStatus, ReportStatus, ScanReport
from ca_core.pipeline.gate import GateResult, evaluate_gate
from ca_core.scoring.levels import sort_findings
from ca_integrations import limits
from ca_integrations.models import (
    Annotation,
    AnnotationLevel,
    CheckRun,
    CheckRunOutput,
    Conclusion,
    PullRequestComment,
)

MARKER = "<!-- code-analyzer:1 -->"
ZWSP = "​"  # interrompe i collegamenti automatici senza alterare il testo visibile
COMMENT_MARGIN = 2_000  # per il pié di pagina e per sicurezza sui limiti scritti a memoria
TITLE_MAX = 160
RULE_MAX = 80
PATH_MAX = 200
REMEDIATION_MAX = 300
WARNING_MAX = 200
MAX_WARNINGS_SHOWN = 10
MAX_TOOLS_SHOWN = 5

_HEX_RUN = re.compile(r"(?<![0-9A-Za-z])[0-9a-fA-F]{7,40}(?![0-9A-Za-z])")
_LEVEL_LABEL = {
    Level.CRITICAL: "critico",
    Level.HIGH: "alto",
    Level.MEDIUM: "medio",
    Level.LOW: "basso",
}
_ANNOTATION_LEVEL = {
    Level.CRITICAL: AnnotationLevel.FAILURE,
    Level.HIGH: AnnotationLevel.FAILURE,
    Level.MEDIUM: AnnotationLevel.WARNING,
    Level.LOW: AnnotationLevel.NOTICE,
}


def clean_text(value: str, limit: int) -> str:
    """Testo su una riga, senza caratteri di controllo né di formato, al più `limit` caratteri."""
    kept = []
    for ch in value:
        category = unicodedata.category(ch)
        if ch.isspace() or category in ("Zl", "Zp"):
            kept.append(" ")
        elif category[0] != "C":  # controllo, formato (bidi, ZWSP), surrogati, non assegnati
            kept.append(ch)
    text = " ".join("".join(kept).split())
    return text if len(text) <= limit else text[: limit - 1] + "…"


def neutralize(value: str, limit: int) -> str:
    """`clean_text` più la neutralizzazione di Markdown, HTML, menzioni e collegamenti."""
    text = clean_text(value, limit)
    text = _HEX_RUN.sub(lambda m: m.group()[:6] + ZWSP + m.group()[6:], text)
    for token, repl in (("://", ":" + ZWSP + "//"), ("www.", "www" + ZWSP + ".")):
        text = text.replace(token, repl).replace(token.upper(), repl.upper())
    out = []
    for ch in text:
        if ch.isascii() and not ch.isalnum() and not ch.isspace():
            out.append("\\" + ch)
            if ch in "@#":
                out.append(ZWSP)
        else:
            out.append(ch)
    return "".join(out)


def _active(report: ScanReport) -> list[Finding]:
    return [f for f in sort_findings(report.findings) if f.status is not Status.ACCEPTED]


def _has_baseline(report: ScanReport) -> bool:
    return report.baseline is not None and report.baseline.status is BaselineStatus.VALID


def selected(report: ScanReport, gate: GateResult | None = None) -> list[Finding]:
    """I finding da mostrare: i nuovi con una baseline valida, altrimenti quelli che bloccano.

    Un gruppo di correlazione compare una volta sola (il primo, nell'ordine dell'elenco).
    """
    if _has_baseline(report):
        pool = [f for f in _active(report) if f.baseline_state is BaselineState.NEW]
    else:
        blocking = {b.fingerprint for b in (gate or evaluate_gate(report)).blocking}
        pool = [f for f in _active(report) if f.fingerprint in blocking]
    seen: set[str] = set()
    out = []
    for finding in pool:
        if finding.correlation is not None:
            if finding.correlation in seen:
                continue
            seen.add(finding.correlation)
        out.append(finding)
    return out


def _others(report: ScanReport, finding: Finding) -> list[str]:
    """Strumenti degli altri finding dello stesso gruppo di correlazione."""
    if finding.correlation is None:
        return sorted(finding.tools)
    tools = {t for f in report.findings if f.correlation == finding.correlation for t in f.tools}
    return sorted(tools)


def _where(finding: Finding) -> str:
    location = finding.location
    if location.path is None:
        return ""
    line = f":{location.start_line}" if location.start_line else ""
    return neutralize(location.path + line, PATH_MAX)


def _entry(number: int, report: ScanReport, finding: Finding) -> str:
    label = _LEVEL_LABEL.get(finding.level, "senza livello") if finding.level else "senza livello"
    head = f"{number}. **{label}** · {neutralize(finding.title, TITLE_MAX)}"
    lines = [head]
    detail = [f"regola {neutralize(finding.rule_id, RULE_MAX)}"]
    if where := _where(finding):
        detail.append(where)
    tools = _others(report, finding)
    if len(tools) > 1:
        shown = ", ".join(neutralize(t, 40) for t in tools[:MAX_TOOLS_SHOWN])
        detail.append(f"strumenti: {shown}")
    lines.append("   " + " · ".join(detail))
    if finding.remediation is not None:
        lines.append("   Correzione: " + neutralize(finding.remediation.text, REMEDIATION_MAX))
    return "\n".join(lines)


def build_comment(
    report: ScanReport,
    *,
    max_findings: int = limits.DEFAULT_COMMENT_FINDINGS,
    gate: GateResult | None = None,
) -> PullRequestComment:
    """Il commento unico della PR (ADR-0027), con il marcatore in testa."""
    gate = gate or evaluate_gate(report)
    findings = selected(report, gate)
    lines = [MARKER, "## Code Analyzer", ""]
    if report.status is ReportStatus.PARTIAL:
        lines += ["**Scansione parziale:** alcuni strumenti non hanno prodotto un risultato.", ""]
    for warning in report.warnings[:MAX_WARNINGS_SHOWN]:
        lines.append(
            f"- Avviso {neutralize(warning.code, 64)}: {neutralize(warning.message, WARNING_MAX)}"
        )
    if len(report.warnings) > MAX_WARNINGS_SHOWN:
        lines.append(f"- … e altri {len(report.warnings) - MAX_WARNINGS_SHOWN} avvisi")
    if report.warnings:
        lines.append("")
    baseline = report.baseline
    if baseline is not None and baseline.status is BaselineStatus.VALID:
        lines.append(
            f"Rispetto al commit base: **{baseline.new} nuovi**, {baseline.existing} esistenti, "
            f"{len(baseline.resolved)} risolti."
        )
        if baseline.not_evaluated:
            lines.append(f"{baseline.not_evaluated} non valutati perché uno strumento è fallito.")
        heading = "Finding nuovi"
    else:
        lines.append(
            "Nessuna baseline valida: non si distingue ciò che la PR introduce. "
            "Sono elencati i finding che bloccano il gate."
        )
        heading = "Finding che bloccano"
    lines.append("")
    footer_room = limits.GITHUB_COMMENT_MAX_CHARS - COMMENT_MARGIN
    shown = 0
    entries: list[str] = []
    size = len("\n".join(lines)) + len(heading) + 20
    for finding in findings[: max(0, max_findings)]:
        entry = _entry(shown + 1, report, finding)
        if size + len(entry) + 1 > footer_room:
            break
        entries.append(entry)
        size += len(entry) + 1
        shown += 1
    hidden = len(findings) - shown
    if findings:
        lines.append(f"### {heading} ({shown} di {len(findings)})")
        lines += entries
        if hidden:
            lines.append(f"… e altri {hidden} non mostrati. Il dettaglio è nel report.")
    else:
        lines.append("Nessun finding da mostrare.")
    body = "\n".join(lines) + "\n"
    return PullRequestComment(
        marker=MARKER, body=body, findings_shown=shown, findings_hidden=hidden
    )


def conclusion_for(gate: GateResult) -> Conclusion:
    """Stessa regola di `gate`: fallito, parziale (exit 2), riuscito."""
    return {1: Conclusion.FAILURE, 2: Conclusion.NEUTRAL}.get(gate.exit_code, Conclusion.SUCCESS)


def annotations_for(
    findings: Sequence[Finding], limit: int = limits.DEFAULT_ANNOTATIONS
) -> list[Annotation]:
    """Annotazioni dei finding con posizione, al più `limit` (massimo di GitHub per richiesta)."""
    out: list[Annotation] = []
    for finding in findings:
        location = finding.location
        if location.path is None or location.start_line is None or finding.level is None:
            continue
        if len(out) >= min(limit, limits.GITHUB_ANNOTATIONS_PER_REQUEST):
            break
        start = location.start_line
        out.append(
            Annotation(
                path=location.path,
                start_line=start,
                end_line=max(start, location.end_line or start),
                level=_ANNOTATION_LEVEL[finding.level],
                title=clean_text(finding.title, limits.GITHUB_ANNOTATION_TITLE_MAX) or "finding",
                message=clean_text(finding.message, 2000) or "finding",
            )
        )
    return out


def build_check_run(
    report: ScanReport,
    *,
    max_annotations: int = limits.DEFAULT_ANNOTATIONS,
    gate: GateResult | None = None,
) -> CheckRun:
    gate = gate or evaluate_gate(report)
    findings = selected(report, gate)
    annotations = annotations_for(findings, max_annotations)
    located = sum(1 for f in findings if f.location.path and f.location.start_line)
    conclusion = conclusion_for(gate)
    title = {
        Conclusion.FAILURE: "Gate non superato",
        Conclusion.NEUTRAL: "Scansione parziale",
        Conclusion.SUCCESS: "Gate superato",
    }[conclusion]
    lines = [f"Finding da mostrare: {len(findings)}."]
    if located > len(annotations):
        lines.append(f"Annotazioni: {len(annotations)} di {located}; il resto è nel commento.")
    for reason in gate.reasons:
        lines.append(f"Motivo: {neutralize(reason, 64)}.")
    summary = "\n".join(lines)
    return CheckRun(
        conclusion=conclusion,
        output=CheckRunOutput(title=title, summary=summary, annotations=annotations),
    )
