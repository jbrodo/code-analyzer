"""Fingerprint `fp1` (ADR-0008, "Precisazioni per K-04"). Solo libreria standard, nessun I/O.

Cambiare una qualunque regola qui cambia l'identità dei finding e richiede `fp2`: i vettori
golden in `tests/unit/core/test_fingerprint.py` ne sono la guardia. Ingressi non validi
sollevano `ValueError`.
"""

import hashlib
import re
from collections.abc import Sequence
from itertools import groupby
from typing import NamedTuple

VERSION = "fp1"
_NUL = "\0"
_SHA256_HEX = re.compile(r"[0-9a-f]{64}")
_PURL = re.compile(r"pkg:[a-z][a-z0-9.+-]*/\S+")
_BLANKS = re.compile(r"[ \t\x0b\x0c]+")  # SPACE, TAB, VT, FF: non `\s`, non gli spazi Unicode
_PEP503 = re.compile(r"[-_.]+")


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", "surrogateescape")).hexdigest()


def _field(name: str, value: str, *, allow_empty: bool = True) -> str:
    if _NUL in value:
        raise ValueError(f"{name} contiene NUL")
    if not allow_empty and not value:
        raise ValueError(f"{name} vuoto")
    return value


def _path(value: str) -> str:
    _field("path", value, allow_empty=False)
    if value.startswith("/") or any(s in ("", ".", "..") for s in value.split("/")):
        raise ValueError(f"path non POSIX relativo alla radice: {value!r}")
    return value


def compute_fingerprint(
    kind: str, rule_id: str, tool_family: str, normalized_location: str, component: str
) -> str:
    """`normalized_location` può contenere NUL: i suoi sotto-campi li controllano i chiamanti."""
    payload = _NUL.join(
        [
            VERSION,
            _field("kind", kind),
            _field("rule_id", rule_id),
            _field("tool_family", tool_family),
            normalized_location,
            _field("component", component),
        ]
    )
    return "sha256:" + _sha256(payload)


def _normalize_line(line: str) -> str:
    return _BLANKS.sub(" ", line).strip(" ")


def context_hash(source: str, start_line: int) -> str:
    """SHA-256 (64 hex) di riga precedente, iniziale e successiva, normalizzate."""
    if isinstance(start_line, bool) or start_line < 1:
        raise ValueError("start_line deve essere >= 1")
    text = source.removeprefix("﻿").replace("\r\n", "\n").replace("\r", "\n")
    lines = text.split("\n")  # solo LF: `splitlines` sposterebbe le righe

    def line(number: int) -> str:
        return _normalize_line(lines[number - 1]) if 1 <= number <= len(lines) else ""

    return _sha256("\n".join(line(n) for n in (start_line - 1, start_line, start_line + 1)))


def normalize_purl(purl: str) -> str:
    """purl senza versione, qualifier e subpath: l'identità è quella del pacchetto."""
    if not _PURL.fullmatch(purl) or _NUL in purl:
        raise ValueError(f"purl non valido: {purl!r}")
    body = purl.partition("#")[0].partition("?")[0]
    purl_type, _, rest = body.removeprefix("pkg:").partition("/")
    *namespace, last = rest.rstrip("/").split("/")
    name = last.partition("@")[0]
    if not name or not all(namespace):
        raise ValueError(f"purl senza nome o con segmenti vuoti: {purl!r}")
    if purl_type == "npm":
        namespace = [s.lower() for s in namespace]
        if namespace and namespace[0].startswith("@"):
            namespace[0] = "%40" + namespace[0][1:]
        name = name.lower()
    elif purl_type == "pypi":
        name = _PEP503.sub("-", name).lower()
    return "/".join([f"pkg:{purl_type}", *namespace, name])


def canonical_vuln_id(ids: Sequence[str]) -> str:
    """Minimo lessicografico tra i `CVE-`; altrimenti tra i `GHSA-`; altrimenti tra tutti."""
    if not ids:
        raise ValueError("nessun identificativo di vulnerabilità")
    for vuln_id in ids:
        _field("vuln_id", vuln_id, allow_empty=False)
    for prefix in ("CVE-", "GHSA-"):
        matching = [i for i in ids if i.startswith(prefix)]
        if matching:
            return min(matching)
    return min(ids)


class CodeSite(NamedTuple):
    rule_id: str
    tool: str
    path: str
    context_hash: str
    start_line: int
    start_column: int | None = None
    end_line: int | None = None
    end_column: int | None = None


def _position(site: CodeSite) -> tuple[int, int, int, int]:
    return (
        site.start_line,
        site.start_column or 0,
        site.start_line if site.end_line is None else site.end_line,
        site.end_column or 0,
    )


def assign_occurrences(sites: Sequence[CodeSite]) -> list[int]:
    """Indice di occorrenza per sito, nell'ordine di `sites`; indipendente da quell'ordine."""

    def key(site: CodeSite) -> tuple[str, str, str, str]:
        return (site.rule_id, site.tool, site.path, site.context_hash)

    result = [0] * len(sites)
    order = sorted(range(len(sites)), key=lambda i: key(sites[i]))
    for _, group in groupby(order, key=lambda i: key(sites[i])):
        members = list(group)
        ranks = {p: n for n, p in enumerate(sorted({_position(sites[i]) for i in members}))}
        for i in members:
            result[i] = ranks[_position(sites[i])]
    return result


def fingerprint_code(
    *, rule_id: str, tool: str, path: str, source: str, start_line: int, occurrence: int = 0
) -> str:
    if isinstance(occurrence, bool) or occurrence < 0:
        raise ValueError("occurrence deve essere >= 0")
    _field("rule_id", rule_id, allow_empty=False)
    _field("tool", tool, allow_empty=False)
    location = _NUL.join([_path(path), context_hash(source, start_line), str(occurrence)])
    return compute_fingerprint("code", rule_id, tool, location, "")


def fingerprint_dependency(*, vuln_ids: Sequence[str], purl: str) -> str:
    return compute_fingerprint(
        "dependency", canonical_vuln_id(vuln_ids), "vuln", "", normalize_purl(purl)
    )


def fingerprint_license_package(*, spdx: str, purl: str) -> str:
    _field("spdx", spdx, allow_empty=False)
    return compute_fingerprint(
        "license-package", "ca.license", "license", spdx, normalize_purl(purl)
    )


def fingerprint_license_file(*, path: str, spdx: str) -> str:
    _field("spdx", spdx, allow_empty=False)
    return compute_fingerprint(
        "license-file", "ca.license", "license", _NUL.join([_path(path), spdx]), ""
    )


def fingerprint_secret(*, rule_id: str, path: str, value_sha256: str) -> str:
    _field("rule_id", rule_id, allow_empty=False)
    if not _SHA256_HEX.fullmatch(value_sha256):
        raise ValueError("value_sha256 non è un SHA-256 esadecimale minuscolo")
    return compute_fingerprint(
        "secret", rule_id, "secret", _NUL.join([_path(path), value_sha256]), ""
    )


def fingerprint_coverage(*, rule_id: str, path: str) -> str:
    """Kind `coverage` (ADR-0026): una regola e un file, senza righe né contesto di codice."""
    _field("rule_id", rule_id, allow_empty=False)
    return compute_fingerprint("coverage", rule_id, "coverage", _path(path), "")


def fingerprint_health(*, plugin: str) -> str:
    _field("plugin", plugin, allow_empty=False)
    return compute_fingerprint("health", "ca.scanner-not-run", "ca", plugin, "")
