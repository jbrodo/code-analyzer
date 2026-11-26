"""Report nativi di GitLab dal report di `scan` (N-06, ADR-0027, §12.2). Solo dati, nessun I/O.

`sast` (finding `sast`), `dependency_scanning` (finding `dependency`) e `codequality` (finding
`quality`), più il CycloneDX riportato alla 1.6, la più alta che GitLab accetta. I finding di
segreti, licenze, IaC, architettura, test e salute non hanno posto in questi formati: restano nel
report e nel SARIF, e `not_exported` li conta perché chi esporta lo sappia. Un finding senza il
dato che il formato richiede (un percorso, una riga, una versione) non si esporta e si conta in
`skipped`: mai un valore inventato. I testi vengono dal repository analizzato, non sono fidati:
si tolgono i caratteri di controllo e si tagliano ai limiti dello schema (`limits`).
"""

import re
import uuid
from collections import Counter
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any
from urllib.parse import unquote

from ca_core.formats import EXPORT_CYCLONEDX_VERSIONS
from ca_core.models.finding import Category, Finding, Level
from ca_core.models.scan_report import ReportStatus, ScanReport
from ca_integrations import limits
from ca_integrations.models import CodeQualityIssue, CodeQualityLines, CodeQualityLocation

_CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_NAMESPACE = uuid.UUID("5d3f3c0e-6f0e-4d6e-9a53-2f0c1e1a7a10")  # fisso: gli id sono stabili
_CWE = re.compile(r"^(?:CWE-)?([0-9]{1,6})$")
_VULN_ID = re.compile(r"^[A-Za-z0-9._:-]{1,100}$")
_PURL = re.compile(r"^pkg:[a-z][a-z0-9.+-]*/(?P<rest>[^?#]+)")
_SEVERITY = {
    Level.CRITICAL: "Critical",
    Level.HIGH: "High",
    Level.MEDIUM: "Medium",
    Level.LOW: "Low",
}
_QUALITY_SEVERITY = {
    Level.CRITICAL: "critical",
    Level.HIGH: "major",
    Level.MEDIUM: "minor",
    Level.LOW: "info",
}
_EXPORTED = {Category.SAST, Category.DEPENDENCY, Category.QUALITY}
CODEQUALITY = "codequality"


class ExportError(ValueError):
    """Il documento da esportare non è convertibile; il messaggio è un codice, mai un contenuto."""


def _text(value: str, limit: int) -> str:
    return _CONTROL.sub("", value)[:limit]


def _utc(value: datetime) -> str:
    return value.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S")


def _vendor_info(version: str) -> dict[str, Any]:
    return {"id": "code-analyzer", "name": "Code Analyzer", "vendor": {"name": "Code Analyzer"},
            "version": version}  # fmt: skip


def _scan(report: ScanReport, kind: str, version: str) -> dict[str, Any]:
    start = report.started_at
    end = start + timedelta(seconds=report.duration_seconds)
    complete = report.status is ReportStatus.COMPLETE
    scan: dict[str, Any] = {
        "analyzer": _vendor_info(version),
        "scanner": _vendor_info(version),
        "type": kind,
        "start_time": _utc(start),
        "end_time": _utc(end),
        "status": "success" if complete else "failure",
    }
    if not complete:
        scan["messages"] = [{"level": "warn", "value": "scansione parziale: copertura ridotta"}]
    return scan


def _vulnerability_id(finding: Finding) -> str:
    return str(uuid.uuid5(_NAMESPACE, finding.fingerprint))


def _identifier(kind: str, name: str, value: str, url: str | None = None) -> dict[str, str]:
    item = {"type": kind, "name": _text(name, limits.GITLAB_NAME_MAX), "value": value}
    if url:
        item["url"] = url
    return item


def _cwe_identifiers(finding: Finding) -> list[dict[str, str]]:
    found = []
    for cwe in finding.cwe:
        match = _CWE.fullmatch(cwe)
        if match:
            number = match.group(1)
            url = f"https://cwe.mitre.org/data/definitions/{number}.html"
            found.append(_identifier("cwe", f"CWE-{number}", number, url))
    return found


def _common(finding: Finding, identifiers: list[dict[str, str]]) -> dict[str, Any]:
    vulnerability: dict[str, Any] = {
        "id": _vulnerability_id(finding),
        "name": _text(finding.title, limits.GITLAB_NAME_MAX) or finding.rule_id[:255],
        "description": _text(finding.message, limits.GITLAB_DESCRIPTION_MAX),
        "severity": _SEVERITY.get(finding.level, "Unknown") if finding.level else "Unknown",
        "identifiers": identifiers,
    }
    if not vulnerability["description"]:
        del vulnerability["description"]
    remediation = finding.remediation
    if remediation is not None:
        vulnerability["solution"] = _text(remediation.text, limits.GITLAB_SOLUTION_MAX)
        if remediation.references:
            vulnerability["links"] = [{"url": url} for url in remediation.references]
    return vulnerability


def _sast(finding: Finding) -> dict[str, Any] | None:
    where = finding.location
    if where.path is None:
        return None
    rule = _text(finding.rule_id, limits.GITLAB_NAME_MAX)
    identifiers = [_identifier(f"{finding.tool}_rule_id", rule, rule), *_cwe_identifiers(finding)]
    location: dict[str, Any] = {"file": where.path}
    if where.start_line is not None:
        location["start_line"] = where.start_line
        location["end_line"] = where.end_line or where.start_line
    return {**_common(finding, identifiers), "location": location}


def _package(purl: str | None) -> tuple[str, str] | None:
    """Nome e versione dal purl; senza versione il formato non è soddisfatto."""
    match = _PURL.match(purl or "")
    if match is None or "@" not in match.group("rest").rpartition("/")[2]:
        return None
    rest = match.group("rest")
    head, _, version = rest.rpartition("@")
    name = unquote(head)
    return (name, unquote(version)) if name and version else None


def _vulnerability_identifiers(finding: Finding) -> list[dict[str, str]]:
    ids = [*finding.cve, finding.rule_id]
    out: list[dict[str, str]] = []
    for vuln in dict.fromkeys(ids):
        if not _VULN_ID.fullmatch(vuln):
            continue
        if vuln.startswith("CVE-"):
            out.append(_identifier("cve", vuln, vuln, f"https://nvd.nist.gov/vuln/detail/{vuln}"))
        elif vuln.startswith("GHSA-"):
            out.append(_identifier("ghsa", vuln, vuln, f"https://github.com/advisories/{vuln}"))
        else:
            out.append(_identifier("vulnerability_id", vuln, vuln))
    return out + _cwe_identifiers(finding)


def _dependency(finding: Finding) -> dict[str, Any] | None:
    where = finding.location
    package = _package(where.purl)
    identifiers = _vulnerability_identifiers(finding)
    if where.path is None or package is None or not identifiers:
        return None
    name, version = package
    dependency: dict[str, Any] = {"package": {"name": name}, "version": version}
    if where.dependency_path:
        dependency["direct"] = len(where.dependency_path) <= 1
    return {
        **_common(finding, identifiers),
        "location": {"file": where.path, "dependency": dependency},
    }


def _quality(finding: Finding) -> CodeQualityIssue | None:
    where = finding.location
    if where.path is None or where.start_line is None:
        return None
    digest = finding.fingerprint.removeprefix("sha256:")
    return CodeQualityIssue(
        description=_text(finding.title, limits.GITLAB_DESCRIPTION_MAX) or finding.rule_id[:255],
        check_name=_text(finding.rule_id, limits.GITLAB_NAME_MAX) or "rule",
        fingerprint=digest,
        severity=_QUALITY_SEVERITY.get(finding.level, "info") if finding.level else "info",
        location=CodeQualityLocation(
            path=where.path, lines=CodeQualityLines(begin=where.start_line)
        ),
    )


@dataclass(frozen=True)
class GitLabReports:
    sast: dict[str, Any]
    dependency_scanning: dict[str, Any]
    codequality: list[dict[str, Any]]
    skipped: dict[str, int] = field(default_factory=dict)  # per report: senza il dato richiesto
    not_exported: dict[str, int] = field(default_factory=dict)  # per categoria: senza formato


def build_reports(report: ScanReport, *, version: str) -> GitLabReports:
    sast: list[dict[str, Any]] = []
    dependencies: list[dict[str, Any]] = []
    quality: list[dict[str, Any]] = []
    skipped: Counter[str] = Counter()
    not_exported: Counter[str] = Counter()
    for finding in report.findings:
        if finding.category not in _EXPORTED:
            not_exported[finding.category.value] += 1
        elif finding.category is Category.SAST:
            code = _sast(finding)
            if code is None:
                skipped["sast"] += 1
            else:
                sast.append(code)
        elif finding.category is Category.DEPENDENCY:
            built = _dependency(finding)
            if built is None:
                skipped["dependency_scanning"] += 1
            else:
                dependencies.append(built)
        else:
            issue = _quality(finding)
            if issue is None:
                skipped[CODEQUALITY] += 1
            else:
                quality.append(issue.model_dump(mode="json"))
    top = {"version": limits.GITLAB_SCHEMA_VERSION}
    return GitLabReports(
        sast={**top, "scan": _scan(report, "sast", version), "vulnerabilities": sast},
        dependency_scanning={
            **top,
            "scan": _scan(report, "dependency_scanning", version),
            "vulnerabilities": dependencies,
        },
        codequality=quality,
        skipped=dict(skipped),
        not_exported=dict(not_exported),
    )


def to_cyclonedx_16(document: Any) -> dict[str, Any]:
    """Il CycloneDX 1.7 del prodotto riportato alla 1.6, che GitLab accetta (1.4, 1.5 o 1.6).

    Cambia solo la dichiarazione di versione: se il documento usa qualcosa di esclusivo della 1.7
    non vale come 1.6 e il chiamante lo rileva validando il risultato contro lo schema 1.6.
    """
    if not isinstance(document, dict) or document.get("specVersion") != "1.7":
        raise ExportError("sbom-not-1.7")
    target = EXPORT_CYCLONEDX_VERSIONS[-1]
    converted = dict(document)
    converted["specVersion"] = target
    if "$schema" in converted:
        converted["$schema"] = f"http://cyclonedx.org/schema/bom-{target}.schema.json"
    return converted
