"""Fattore E (K-04, §6.1, ADR-0022, ADR-0021): raggiungibilità ed esposizione del servizio.

Comune alle due varianti. I valori vengono dalla configurazione di scoring. La raggiungibilità
viene dal protocollo `Reachability` (il grafo, G-12); senza grafo è `ignota` e l'evidenza lo dice.

- finding su un modulo del grafo: stato del modulo; su più membri (un ciclo): il migliore;
- finding su una dipendenza (`dependency`, e licenza di un componente con `purl`): l'uso del
  pacchetto nel grafo, mai «non usata»;
- finding senza modulo né pacchetto (IaC, segreti, licenze su file non sorgente, salute): la
  raggiungibilità non si applica e vale `raggiungibile`, salvo i file sotto percorsi di test.

L'esposizione conta solo per `raggiungibile`. Una dipendenza di sviluppo dichiarata da lockfile o
SBOM (E = `not_reachable_or_test`) richiede dati che arrivano con K-15 e oggi non si applica.
"""

import re
from collections.abc import Mapping
from typing import Any

from ca_core.models.finding import Category, Finding
from ca_core.scoring.base import Factor, ScoringContext
from ca_core.scoring.reach import ReachResult, ReachState, best

_PERCENT = re.compile(r"(?:%[0-9A-Fa-f]{2})+")
_PURL = re.compile(r"^pkg:(?P<type>[a-z][a-z0-9.+-]*)/(?P<rest>[^?#]+)")
_ECOSYSTEMS = {"pypi": "pypi", "npm": "npm"}
_TEST_DIRS = frozenset({"test", "tests", "testing", "__tests__", "__mocks__"})
_DEPENDENCY_CATEGORIES = frozenset({Category.DEPENDENCY, Category.LICENSE})
_MEMBER_CATEGORIES = frozenset({Category.ARCHITECTURE})


def is_test_path(path: str) -> bool:
    """File di test dal percorso: le stesse regole fisse dell'estrattore del grafo (G-02)."""
    *dirs, name = path.casefold().split("/")
    stem = name.rsplit(".", 1)[0]
    return (
        not _TEST_DIRS.isdisjoint(dirs)
        or name == "conftest.py"
        or name.startswith("test_")
        or stem.endswith(("_test", ".test", ".spec"))
    )


def _unquote(text: str) -> str:
    """Decodifica `%XX` (il purl codifica `@` come `%40`); `urllib` è vietato nel nucleo."""
    return _PERCENT.sub(
        lambda m: bytes.fromhex(m.group().replace("%", "")).decode("utf-8", "replace"), text
    )


def purl_package(purl: str | None) -> tuple[str, str] | None:
    """(ecosistema, nome) dal purl; `None` se non è npm o PyPI o non ha un nome."""
    match = _PURL.match(purl or "")
    if match is None or match.group("type") not in _ECOSYSTEMS:
        return None
    rest = match.group("rest")
    head, _, last = rest.rpartition("/")
    name = (
        _unquote(last.partition("@")[0])
        if not head
        else _unquote(head + "/" + last.partition("@")[0])
    )
    return (_ECOSYSTEMS[match.group("type")], name) if name else None


def _members(finding: Finding) -> list[str]:
    """Moduli o cartelle di un finding su più membri; altrimenti il suo percorso."""
    for evidence in finding.evidence.values():
        if isinstance(evidence, Mapping) and isinstance(evidence.get("members"), list):
            found = [m for m in evidence["members"] if isinstance(m, str)]
            if found:
                return found
    return [finding.location.path] if finding.location.path else []


def _of_path(path: str, context: ScoringContext, *, directory: bool) -> ReachResult:
    reach = context.reachability
    found = reach.module(path)
    if found is None and directory:
        found = reach.package(path)
    if found is not None:
        return found
    if is_test_path(path):
        return ReachResult(ReachState.TEST_ONLY, reason="percorso-di-test")
    return ReachResult(ReachState.REACHABLE, reason="senza-modulo")


def reach_of(finding: Finding, context: ScoringContext) -> tuple[str, ReachResult]:
    """(regola, risultato) per un finding."""
    where = finding.location
    if finding.category in _DEPENDENCY_CATEGORIES and where.purl:
        package = purl_package(where.purl)
        if package is None:
            return "dipendenza", ReachResult(ReachState.UNKNOWN, reason="purl-non-supportato")
        return "dipendenza", context.reachability.dependency(*package)
    if finding.category in _MEMBER_CATEGORIES:
        members = _members(finding)
        if members:
            return "membri", best([_of_path(m, context, directory=True) for m in members])
    if where.path:
        return "modulo", _of_path(where.path, context, directory=False)
    return "senza-percorso", ReachResult(ReachState.REACHABLE, reason="senza-modulo")


def factor_e(finding: Finding, context: ScoringContext) -> Factor:
    table = context.config.e
    rule, result = reach_of(finding, context)
    exposure = context.service.internet_facing
    evidence: dict[str, Any] = {
        "rule": rule,
        "reachability": result.state.value,
        "entrypoint": result.entrypoint,
        "reason": result.reason,
        "exposure": {"value": exposure.value, "source": exposure.source},
    }
    state = result.state
    if state is ReachState.REACHABLE:
        if exposure.value is True:
            value = table.reachable_exposed
        elif exposure.value is False:
            value = table.reachable_internal
        else:
            value = table.reachable_exposure_unknown
    elif state is ReachState.UNKNOWN:
        value = table.unknown
    else:
        value = table.not_reachable_or_test
    return Factor(value, evidence)
