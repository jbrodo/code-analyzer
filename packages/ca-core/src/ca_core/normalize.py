"""Normalizzazione di un SARIF di plugin in `Finding` (K-05, ADR-0002, ADR-0007, ADR-0008).

L'ingresso è un SARIF già validato (`ParsedSarif`) e già adattato: le `properties` hanno solo le
chiavi di C-05 e gli `uri` sono relativi alla radice del workspace. Ogni risultato che non si
può normalizzare fa fallire il plugin con un `SarifError` (ADR-0007): nessun finding parziale.

Mappa i sei `kind` di ADR-0008:

| categoria          | kind                                                       |
| ------------------ | ---------------------------------------------------------- |
| `sast`, `iac`      | `code`                                                     |
| `dependency`       | `dependency` (purl obbligatorio)                           |
| `license`          | `license-package` se c'è `purl`, altrimenti `license-file` |
| `secret`           | `secret` (`secret_sha256` obbligatorio, mai copiato)       |
| `health`           | `health`                                                   |

`quality`, `architecture` e `test` non hanno un `kind` in Fase 1: il plugin fallisce.

Scelte conservative dove ADR e scheda non dicono:

- `uriBaseId` presente nell'`artifactLocation`: rifiutato (ADR-0007: gli `uri` sono senza).
- Solo la prima `location` di un risultato è usata.
- `title` è `rule_id` (id canonico per `dependency`); `rule_id` è `ca.license` per le licenze.
- Per `secret` il `message` è sintetizzato: il testo dello scanner non entra nel report.
- Risultato `code` senza `region`: nessun contesto e posizione `(1, 0, 1, 0)`, quindi più
  risultati della stessa regola nello stesso file senza `region` hanno la stessa occorrenza e si
  fondono. File oltre il limite: nessun contesto ma le posizioni reali distinguono i risultati.
"""

import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from pydantic import ValidationError

from ca_core import fingerprint as fp
from ca_core.models.finding import Category, Finding, Location
from ca_core.models.plugin_manifest import PluginManifest
from ca_core.models.plugin_sarif import PluginSarifProperties
from ca_core.models.scan_report import Warning_
from ca_core.ports import Clock, SourceError, SourceReader, SourceTooLarge
from ca_core.sarif.errors import SarifError, SarifErrorCode
from ca_core.sarif.reader import ParsedSarif, SarifResult

# Provvisorio come i limiti di `SarifLimits`: da rivedere con i pilota (X-04).
DEFAULT_MAX_SOURCE_BYTES = 2 * 1024 * 1024
HEALTH_RULE_ID = "ca.scanner-not-run"
LICENSE_RULE_ID = "ca.license"
_MAX_TEXT = 4096
_PERCENT = re.compile(rb"%([0-9A-Fa-f]{2})")  # `urllib` è vietato in ca_core (lint-imports)
_SCHEME = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*:")
_CODE_CATEGORIES = frozenset({Category.SAST, Category.IAC, Category.QUALITY})


def _fail(code: SarifErrorCode, message: str, pointer: str) -> SarifError:
    return SarifError(code, message, (pointer,))


def _pointer(result: SarifResult) -> str:
    return f"/runs/{result.run_index}/results/{result.index}"


def relative_path(uri: str, pointer: str) -> str:
    """Percorso POSIX relativo alla radice ricavato dall'`uri`, o `SarifError(URI)`."""
    if _SCHEME.match(uri) or uri.startswith(("/", "\\")) or "?" in uri or "#" in uri:
        raise _fail(SarifErrorCode.URI, "uri assoluto o con schema, query o frammento", pointer)
    try:
        raw = _PERCENT.sub(lambda m: bytes([int(m[1], 16)]), uri.encode("utf-8", "surrogateescape"))
    except UnicodeEncodeError as exc:  # surrogato isolato nel JSON
        raise _fail(SarifErrorCode.URI, "uri non codificabile", pointer) from exc
    path = raw.decode("utf-8", "surrogateescape")
    if "\x00" in path or path.startswith("/") or any(s in ("", ".", "..") for s in path.split("/")):
        raise _fail(
            SarifErrorCode.URI, "percorso vuoto, assoluto o con segmenti `.` o `..`", pointer
        )
    return path


@dataclass(frozen=True)
class _Draft:
    result: SarifResult
    category: Category
    kind: str
    rule_id: str
    path: str | None
    region: Mapping[str, Any]
    properties: PluginSarifProperties


def _category(result: SarifResult, manifest: PluginManifest) -> Category:
    declared = result.properties.category if result.properties else None
    if declared is None:
        if len(manifest.categories) != 1:
            raise _fail(SarifErrorCode.MAPPING, "category mancante", _pointer(result))
        return manifest.categories[0]
    if declared not in manifest.categories:
        raise _fail(
            SarifErrorCode.MAPPING, "category non dichiarata dal manifest", _pointer(result)
        )
    return declared


def _kind(category: Category, properties: PluginSarifProperties, pointer: str) -> str:
    if category in _CODE_CATEGORIES:
        return "code"
    if category is Category.LICENSE:
        return "license-package" if properties.purl else "license-file"
    if category is Category.TEST:
        return "coverage"
    if category in (Category.DEPENDENCY, Category.SECRET, Category.HEALTH):
        return category.value
    raise _fail(SarifErrorCode.MAPPING, "categoria senza kind", pointer)


def _draft(result: SarifResult, manifest: PluginManifest) -> _Draft:
    pointer = _pointer(result)
    category = _category(result, manifest)
    properties = result.properties or PluginSarifProperties()
    kind = _kind(category, properties, pointer)
    data = result.data
    rule_id = data.get("ruleId") or (data.get("rule") or {}).get("id")
    if not isinstance(rule_id, str) or not rule_id:
        raise _fail(SarifErrorCode.MAPPING, "ruleId mancante", pointer)
    path: str | None = None
    region: Mapping[str, Any] = {}
    locations = data.get("locations") or ()
    if locations:
        physical = locations[0].get("physicalLocation") or {}
        artifact = physical.get("artifactLocation") or {}
        base = f"{pointer}/locations/0/physicalLocation/artifactLocation"
        if "uriBaseId" in artifact:
            raise _fail(SarifErrorCode.URI, "uriBaseId non ammesso", base)
        if "uri" in artifact:
            path = relative_path(artifact["uri"], f"{base}/uri")
        region = physical.get("region") or {}
    return _Draft(result, category, kind, rule_id, path, region, properties)


def _vuln_ids(draft: _Draft) -> list[str]:
    return [draft.rule_id, *draft.properties.aliases]


def _line(region: Mapping[str, Any]) -> int | None:
    value = region.get("startLine")
    return value if isinstance(value, int) else None


@dataclass(frozen=True)
class _Source:
    text: str
    start_line: int  # riga con cui si calcola il contesto


def _read(reader: SourceReader, workspace: str, path: str, limit: int, pointer: str) -> str | None:
    """Testo del file; `None` se oltre il limite (finding senza contesto, ADR-0008)."""
    try:
        data = reader.read_file(workspace, path, limit)
    except SourceTooLarge:
        return None
    except SourceError as exc:  # fuori dalla radice, symlink, non regolare, inesistente
        raise _fail(SarifErrorCode.SOURCE, "file del workspace non leggibile", pointer) from exc
    return data.decode("utf-8", errors="surrogateescape")


def _occurrences(
    drafts: Sequence[_Draft], tool: str, sources: Mapping[int, _Source]
) -> dict[int, int]:
    """Occorrenza per indice di draft `code`, calcolata una volta per SARIF (ADR-0008 §4)."""
    indices = [i for i, d in enumerate(drafts) if d.kind == "code"]
    sites = []
    for i in indices:
        draft, region = drafts[i], drafts[i].region
        start = _line(region)
        end = region.get("endLine")
        assert draft.path is not None
        sites.append(
            fp.CodeSite(
                rule_id=draft.rule_id,
                tool=tool,
                path=draft.path,
                context_hash=fp.context_hash(sources[i].text, sources[i].start_line),
                start_line=start if start is not None else 1,
                start_column=region.get("startColumn") if start is not None else None,
                end_line=end if start is not None else None,
                end_column=region.get("endColumn") if start is not None else None,
            )
        )
    return dict(zip(indices, fp.assign_occurrences(sites), strict=True))


def _fingerprint(draft: _Draft, tool: str, source: _Source | None, occurrence: int) -> str:
    props, pointer = draft.properties, _pointer(draft.result)
    if draft.kind == "code":
        assert draft.path is not None and source is not None
        return fp.fingerprint_code(
            rule_id=draft.rule_id,
            tool=tool,
            path=draft.path,
            source=source.text,
            start_line=source.start_line,
            occurrence=occurrence,
        )
    if draft.kind == "coverage":
        assert draft.path is not None
        return fp.fingerprint_coverage(rule_id=draft.rule_id, path=draft.path)
    if draft.kind == "dependency":
        assert props.purl is not None
        return fp.fingerprint_dependency(vuln_ids=_vuln_ids(draft), purl=props.purl)
    if draft.kind == "license-package":
        assert props.license_spdx and props.purl
        return fp.fingerprint_license_package(spdx=props.license_spdx, purl=props.purl)
    if draft.kind == "license-file":
        assert props.license_spdx and draft.path
        return fp.fingerprint_license_file(path=draft.path, spdx=props.license_spdx)
    if draft.kind == "secret":
        assert props.secret_sha256 and draft.path
        return fp.fingerprint_secret(
            rule_id=draft.rule_id, path=draft.path, value_sha256=props.secret_sha256
        )
    return fp.fingerprint_health(plugin=tool) if draft.kind == "health" else _unreachable(pointer)


def _pathless_key(draft: _Draft, tool: str, source: _Source | None) -> str | None:
    """Chiave senza percorso (ADR-0025) per i soli kind `code` e `secret`.

    Un finding `code` senza contesto di codice (nessuna riga, o file oltre il limite) non ne ha:
    la sola regola accoppierebbe finding non imparentati.
    """
    props = draft.properties
    if draft.kind == "code" and source is not None and source.text:
        return fp.pathless_key_code(
            rule_id=draft.rule_id, tool=tool, source=source.text, start_line=source.start_line
        )
    if draft.kind == "secret" and props.secret_sha256:
        return fp.pathless_key_secret(rule_id=draft.rule_id, value_sha256=props.secret_sha256)
    return None


def _unreachable(pointer: str) -> str:
    raise _fail(SarifErrorCode.MAPPING, "kind sconosciuto", pointer)


def _require(draft: _Draft) -> None:
    """Campi obbligatori per kind: il fingerprint non si calcola senza."""
    props, pointer = draft.properties, _pointer(draft.result)
    missing: list[str] = []
    if draft.kind in ("code", "secret", "license-file", "coverage") and draft.path is None:
        missing.append("locations/0/physicalLocation/artifactLocation/uri")
    if draft.kind in ("dependency", "license-package") and not props.purl:
        missing.append("properties/purl")
    if draft.kind == "secret" and not props.secret_sha256:
        missing.append("properties/secret_sha256")
    if draft.kind in ("license-package", "license-file") and not props.license_spdx:
        missing.append("properties/license_spdx")
    if missing:
        raise SarifError(
            SarifErrorCode.MAPPING,
            "campo obbligatorio mancante per la categoria",
            tuple(f"{pointer}/{m}" for m in missing),
        )


def _text(value: Any, default: str) -> str:
    return value[:_MAX_TEXT] if isinstance(value, str) and value else default


def _evidence(draft: _Draft) -> dict[str, Any]:
    """Evidenza del tool. `secret_sha256` non entra mai: serve solo al fingerprint."""
    props = draft.properties
    evidence: dict[str, Any] = {
        "sarif_level": draft.result.data.get("level"),
        "tool_severity": props.tool_severity,
        "cvss": props.cvss.model_dump(mode="json") if props.cvss else None,
        "metric": props.metric.model_dump(mode="json") if props.metric else None,
        "aliases": sorted(set(props.aliases)) if props.aliases else None,
        "path_confirmed": True if props.taint else None,  # regola taint del prodotto (ADR-0021)
    }
    return {k: v for k, v in evidence.items() if v is not None}


def _finding(
    draft: _Draft,
    *,
    tool: str,
    fingerprint: str,
    pathless_key: str | None,
    repository: str,
    commit: str | None,
    now: Any,
) -> Finding:
    props = draft.properties
    vuln_ids = _vuln_ids(draft)
    if draft.kind == "dependency":
        rule_id = title = fp.canonical_vuln_id(vuln_ids)
    elif draft.kind.startswith("license"):
        rule_id, title = LICENSE_RULE_ID, f"Licenza {props.license_spdx}"
    elif draft.kind == "health":
        rule_id, title = HEALTH_RULE_ID, f"Scanner non eseguito: {tool}"
    else:
        rule_id, title = draft.rule_id, draft.rule_id
    if draft.kind == "secret":  # il testo dello scanner non entra nel report (ADR-0012)
        message = f"Segreto rilevato dalla regola {draft.rule_id} in {draft.path}"[:_MAX_TEXT]
    else:
        message = _text(draft.result.data.get("message", {}).get("text"), title)
    region = draft.region
    try:
        location = Location(
            repository=repository,
            commit=commit,
            path=draft.path,
            start_line=region.get("startLine"),
            end_line=region.get("endLine"),
            purl=props.purl,
        )
        return Finding(
            id=fingerprint,
            fingerprint=fingerprint,
            category=draft.category,
            rule_id=rule_id,
            tool=tool,
            tools=[tool],
            title=title[:_MAX_TEXT],
            message=message,
            location=location,
            cve=sorted({i for i in vuln_ids if i.startswith("CVE-")})
            if draft.kind == "dependency"
            else [],
            license_spdx=props.license_spdx if draft.kind.startswith("license") else None,
            pathless_key=pathless_key,
            evidence={tool: _evidence(draft)},
            first_seen=now,
            last_seen=now,
        )
    except ValidationError as exc:
        raise _fail(
            SarifErrorCode.MAPPING, "campi del risultato non validi", _pointer(draft.result)
        ) from exc


def normalize_sarif(
    parsed: ParsedSarif,
    *,
    manifest: PluginManifest,
    repository: str,
    commit: str | None,
    workspace: str,
    reader: SourceReader,
    clock: Clock,
    max_source_bytes: int = DEFAULT_MAX_SOURCE_BYTES,
) -> list[Finding]:
    """Findings del SARIF di `manifest.name`, nell'ordine dei risultati.

    `commit` è `None` per una cartella non git. `SarifError` fa fallire il plugin.
    """
    tool = manifest.name
    now = clock.now()
    drafts = [_draft(result, manifest) for result in parsed.results]
    for draft in drafts:
        _require(draft)
    cache: dict[str, str | None] = {}
    sources: dict[int, _Source] = {}
    for i, draft in enumerate(drafts):
        if draft.kind != "code":
            continue
        assert draft.path is not None
        if draft.path not in cache:
            cache[draft.path] = _read(
                reader, workspace, draft.path, max_source_bytes, _pointer(draft.result)
            )
        text, start = cache[draft.path], _line(draft.region)
        # senza contesto (nessuna region, o file oltre il limite): sorgente vuoto, riga 1
        sources[i] = (
            _Source(text, start) if text is not None and start is not None else _Source("", 1)
        )
    occurrences = _occurrences(drafts, tool, sources)
    findings = []
    for i, draft in enumerate(drafts):
        fingerprint = _fingerprint(draft, tool, sources.get(i), occurrences.get(i, 0))
        findings.append(
            _finding(
                draft,
                tool=tool,
                fingerprint=fingerprint,
                pathless_key=_pathless_key(draft, tool, sources.get(i)),
                repository=repository,
                commit=commit,
                now=now,
            )
        )
    return findings


_NOTIFICATION_ID = re.compile(r"[a-z][a-z0-9-]{0,40}")
_NOTIFICATION_LEVELS = frozenset({"warning", "error"})
# `plugin-skipped` è un avviso del motore: una notifica non può produrre lo stesso codice.
_RESERVED_NOTIFICATION_IDS = frozenset({"skipped"})
_NOTIFICATION_TEXT = 300
MAX_NOTIFICATIONS = 16  # per plugin: oltre, il resto è scartato


def notification_warnings(parsed: ParsedSarif, plugin: str) -> list[Warning_]:
    """Notifiche `warning` ed `error` in `invocations` del SARIF di `plugin`, come avvisi (K-19).

    L'output del plugin non è fidato: il codice è sempre `plugin-<id>`, così non può imitare un
    avviso del motore; `<id>` è `descriptor.id` se ha la forma attesa, altrimenti `notification`.
    Il testo è ridotto a caratteri ASCII stampabili e troncato. Al più `MAX_NOTIFICATIONS`,
    senza duplicati. Ogni forma inattesa è ignorata: una notifica non fa mai fallire il plugin.
    """
    warnings: list[Warning_] = []
    seen: set[tuple[str, str]] = set()
    runs = parsed.document.get("runs")
    for run in runs if isinstance(runs, list) else []:
        invocations = run.get("invocations") if isinstance(run, Mapping) else None
        for invocation in invocations if isinstance(invocations, list) else []:
            found = (
                invocation.get("toolExecutionNotifications")
                if isinstance(invocation, Mapping)
                else None
            )
            for item in found if isinstance(found, list) else []:
                if not isinstance(item, Mapping):
                    continue
                if item.get("level", "warning") not in _NOTIFICATION_LEVELS:
                    continue
                descriptor, message = item.get("descriptor"), item.get("message")
                ident = descriptor.get("id") if isinstance(descriptor, Mapping) else None
                if (
                    not isinstance(ident, str)
                    or not _NOTIFICATION_ID.fullmatch(ident)
                    or ident in _RESERVED_NOTIFICATION_IDS
                ):
                    ident = "notification"
                text = message.get("text") if isinstance(message, Mapping) else None
                text = re.sub(r"[^\x20-\x7e]+", " ", text) if isinstance(text, str) else ""
                text = " ".join(text.split())[:_NOTIFICATION_TEXT] or "notifica senza testo"
                key = (ident, text)
                if key in seen:
                    continue
                seen.add(key)
                warnings.append(Warning_(code=f"plugin-{ident}", message=text, subject=plugin))
                if len(warnings) == MAX_NOTIFICATIONS:
                    return warnings
    return warnings


def health_finding(
    plugin: str, detail: str, *, repository: str, commit: str | None, clock: Clock
) -> Finding:
    """Finding `health` per un plugin fallito (§5, §7.2, ADR-0007); `detail` è un testo breve
    del runner, mai output dello scanner."""
    fingerprint = fp.fingerprint_health(plugin=plugin)
    now = clock.now()
    return Finding(
        id=fingerprint,
        fingerprint=fingerprint,
        category=Category.HEALTH,
        rule_id=HEALTH_RULE_ID,
        tool=plugin,
        tools=[plugin],
        title=f"Scanner non eseguito: {plugin}",
        message=detail[:_MAX_TEXT] or f"Scanner non eseguito: {plugin}",
        location=Location(repository=repository, commit=commit),
        evidence={plugin: {}},
        first_seen=now,
        last_seen=now,
    )


# --- K-06: licenze dichiarate da SBOM (ADR-0007, ADR-0013) -------------------------------------

_LICENSE_REF_CHARS = re.compile(r"[^A-Za-z0-9.-]+")
_MAX_LICENSE = 256


_LOCATION_PROPERTY = re.compile(r"syft:location:\d+:path")


@dataclass(frozen=True)
class DeclaredLicense:
    """Licenza dichiarata di un componente. `expression` è `None` se manca; `NOASSERTION` e
    `LicenseRef-*` restano come dichiarati: li classifica la policy (K-12), non l'estrazione."""

    name: str
    purl: str | None
    expression: str | None
    locations: tuple[str, ...] = ()  # file da cui proviene il componente, se noti


def _license_term(entry: Any) -> str | None:
    if not isinstance(entry, Mapping):
        return None
    expression = entry.get("expression")
    if isinstance(expression, str) and expression.strip():
        return f"({expression.strip()})"
    license_ = entry.get("license")
    if not isinstance(license_, Mapping):
        return None
    spdx = license_.get("id")
    if isinstance(spdx, str) and spdx.strip():
        return spdx.strip()
    name = license_.get("name")
    if isinstance(name, str) and name.strip():
        if name.strip() == "NOASSERTION":
            return "NOASSERTION"
        # nome libero, non SPDX: come dichiarazione personalizzata, quindi "da verificare"
        return "LicenseRef-" + (_LICENSE_REF_CHARS.sub("-", name.strip()).strip("-") or "unnamed")
    return None


def _component_locations(component: Mapping[str, Any]) -> tuple[str, ...]:
    return tuple(
        p["value"]
        for p in component.get("properties") or ()
        if isinstance(p, Mapping)
        and isinstance(p.get("name"), str)
        and _LOCATION_PROPERTY.fullmatch(p["name"])
        and isinstance(p.get("value"), str)
    )


def declared_licenses(document: Mapping[str, Any]) -> list[DeclaredLicense]:
    """Un elemento per componente (anche annidato), nell'ordine del documento.

    Più voci in `licenses` si combinano con `AND`: la lettura più severa. Il documento deve
    essere già validato (`parse_cyclonedx`).
    """
    found: list[DeclaredLicense] = []
    stack = [iter(document.get("components") or ())]
    while stack:
        component = next(stack[-1], None)
        if component is None:
            stack.pop()
            continue
        if not isinstance(component, Mapping):
            continue
        terms = [t for e in component.get("licenses") or () if (t := _license_term(e))]
        expression = " AND ".join(terms)[:_MAX_LICENSE] if terms else None
        if len(terms) == 1 and terms[0].startswith("("):
            expression = terms[0][1:-1][:_MAX_LICENSE]
        purl = component.get("purl")
        name = component.get("name")
        found.append(
            DeclaredLicense(
                name=name if isinstance(name, str) else "",
                purl=purl if isinstance(purl, str) and purl else None,
                expression=expression,
                locations=_component_locations(component),
            )
        )
        stack.append(iter(component.get("components") or ()))
    return found
