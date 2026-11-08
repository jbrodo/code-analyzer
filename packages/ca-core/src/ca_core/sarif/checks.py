"""Controllo strutturale dei SARIF dei plugin (K-10, ADR-0012 con emendamento dopo V-09).

La CLI non conosce il valore di un segreto, quindi non può cercarlo: controlla la forma.
Per ogni plugin, la chiave `snippet` a qualunque profondità fa fallire il plugin (anche con il
valore `REDACTED` di gitleaks). Per gitleaks, inoltre, `message` deve essere quello del modello
oscurato e `partialFingerprints` non deve portare dati personali.

Interpretazione conservativa del "modello oscurato": `message` ha la sola chiave `text`, e il
testo è esattamente `<ruleId> has detected secret for file <uri>[ at commit <sha>].` con `uri`
quello della prima posizione del risultato. Ogni altro testo (compreso un valore del segreto
interpolato) è rifiutato. Non si controlla `date` né `commitSha`: la scheda elenca `email`,
`author` e `commitMessage`.
"""

import re
from collections.abc import Iterator, Mapping
from typing import Any

from ca_core.sarif.errors import SarifError, SarifErrorCode
from ca_core.sarif.reader import SarifCheck

GITLEAKS = "gitleaks"
FORBIDDEN_FINGERPRINT_KEYS = frozenset({"email", "author", "commitMessage"})
_COMMIT = re.compile(r"[0-9a-f]{7,64}")
_MAX_PATH_CHARS = 200
_MAX_REPORTED = 20


def _pointer(tokens: tuple[str, ...]) -> str:
    return ("/" + "/".join(tokens))[:_MAX_PATH_CHARS]


def _snippet_paths(document: Any) -> Iterator[tuple[str, ...]]:
    """Visita iterativa: il documento è ostile e può essere profondo."""
    stack: list[tuple[Any, tuple[str, ...]]] = [(document, ())]
    while stack:
        node, path = stack.pop()
        if isinstance(node, dict):
            for key, value in node.items():
                if isinstance(key, str) and key.casefold() == "snippet":
                    yield (*path, key)
                else:
                    stack.append((value, (*path, str(key))))
        elif isinstance(node, list):
            stack.extend((item, (*path, str(i))) for i, item in enumerate(node))


def no_snippet(document: Mapping[str, Any]) -> None:
    found = []
    for path in _snippet_paths(document):
        found.append(_pointer(path))
        if len(found) >= _MAX_REPORTED:
            break
    if found:
        raise SarifError(
            SarifErrorCode.CHECK, "chiave `snippet` presente (ADR-0012)", tuple(sorted(found))
        )


def _results(document: Mapping[str, Any]) -> Iterator[tuple[str, Any]]:
    for run_index, run in enumerate(document.get("runs") or ()):
        for index, result in enumerate(run.get("results") or ()):
            yield f"/runs/{run_index}/results/{index}", result


def _first_uri(result: Mapping[str, Any]) -> str | None:
    for location in result.get("locations") or ():
        uri = ((location.get("physicalLocation") or {}).get("artifactLocation") or {}).get("uri")
        return uri if isinstance(uri, str) else None
    return None


def _is_redacted_message(result: Mapping[str, Any]) -> bool:
    message = result.get("message")
    if not isinstance(message, dict) or set(message) != {"text"}:
        return False
    text, rule_id, uri = message["text"], result.get("ruleId"), _first_uri(result)
    if not (isinstance(text, str) and isinstance(rule_id, str) and uri is not None):
        return False
    head = f"{rule_id} has detected secret for file {uri}"
    if text == f"{head}.":
        return True
    prefix, suffix = f"{head} at commit ", "."
    return (
        text.startswith(prefix)
        and text.endswith(suffix)
        and _COMMIT.fullmatch(text[len(prefix) : -len(suffix)]) is not None
    )


def gitleaks_redacted(document: Mapping[str, Any]) -> None:
    problems: list[str] = []
    for base, result in _results(document):
        if not _is_redacted_message(result):
            problems.append(f"{base}/message")
        fingerprints = result.get("partialFingerprints") or {}
        problems += [
            f"{base}/partialFingerprints/{key}"
            for key in sorted(FORBIDDEN_FINGERPRINT_KEYS & set(fingerprints))
        ]
        if len(problems) >= _MAX_REPORTED:
            break
    if problems:
        raise SarifError(
            SarifErrorCode.CHECK,
            "output gitleaks non conforme al modello oscurato (ADR-0012)",
            tuple(problems[:_MAX_REPORTED]),
        )


def structural_checks(plugin: str) -> tuple[SarifCheck, ...]:
    """Controlli da passare a `parse_sarif` per il plugin `plugin` (nome del manifest)."""
    return (no_snippet, gitleaks_redacted) if plugin == GITLEAKS else (no_snippet,)
