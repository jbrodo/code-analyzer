"""Motore della policy licenze (K-12, ADR-0013). Policy configurata per progetto.

Puro: nessun elenco di licenze nel codice, `forbidden` e `require_approval` vengono solo dalla
configurazione. Le voci sono identificatori SPDX esatti, senza equivalenze implicite
(`GPL-3.0-or-later` non è `GPL-3.0-only`, `GPL-3.0+` non è `GPL-3.0-or-later`). Con `WITH` vale
la voce completa oppure l'identificatore base, il caso più severo.

Semantica: ogni foglia ha un rango (conforme < ignota < da approvare < vietata); `AND` prende il
massimo dei termini, `OR` il minimo (viola solo se tutti i termini violano). Ignota: licenza
mancante, `NOASSERTION`, `NONE`, `LicenseRef-*` o espressione non valida. Una voce della
policy ha la precedenza sulla classificazione di ignota; vietata prevale su da approvare.

Fonti: licenze dichiarate da SBOM (K-06) e finding `license` rilevati da scancode, che qui si
consumano e non passano al report: restano solo i finding della policy (`tool = "ca-core"`,
`rule_id = "ca.license"`). Un finding per fingerprint, con le fonti in `evidence`.

Policy assente (`licenses` è `None`; una sezione vuota è una policy valutata): nessun finding
e avviso `license-policy-absent`. Componenti SBOM senza purl non hanno una posizione: avviso
`license-component-without-purl` con il conteggio.
"""

import re
from collections.abc import Sequence
from dataclasses import dataclass, field
from enum import IntEnum

from ca_core import fingerprint as fp
from ca_core.models.config import Licenses
from ca_core.models.finding import Category, Finding, Level, LevelSource, Location
from ca_core.models.scan_report import Warning_
from ca_core.normalize import LICENSE_RULE_ID, DeclaredLicense
from ca_core.ports import Clock

TOOL = "ca-core"
MAX_EXPRESSION = 256
_MAX_DEPTH = 32
_TOKEN = re.compile(r"\(|\)|[^\s()]+")
_ID = re.compile(r"[A-Za-z0-9.-]+\+?")
_REF = re.compile(r"(?:DocumentRef-[A-Za-z0-9.-]+:)?LicenseRef-[A-Za-z0-9.-]+")
_UNKNOWN_IDS = frozenset({"NOASSERTION", "NONE"})


class SpdxSyntaxError(ValueError):
    """Espressione SPDX non valida (anche per `config validate`, ADR-0014)."""


class Verdict(IntEnum):
    COMPLIANT = 0
    UNKNOWN = 1
    APPROVAL = 2
    FORBIDDEN = 3


@dataclass(frozen=True)
class LicenseLevelTable:
    """Livelli di ADR-0013; `forbidden_distributed` vale anche con `distributed_product` nullo."""

    forbidden_distributed: Level = Level.CRITICAL
    forbidden_internal: Level = Level.HIGH
    require_approval: Level = Level.HIGH  # alternativa dell'ADR: Level.MEDIUM
    unknown: Level = Level.MEDIUM


DEFAULT_LICENSE_LEVELS = LicenseLevelTable()


# --- espressioni SPDX -----------------------------------------------------------------------


@dataclass(frozen=True)
class Leaf:
    name: str  # identificatore, con `+` se presente
    full: str  # con `WITH eccezione` se presente


@dataclass(frozen=True)
class Node:
    op: str  # "AND" | "OR"
    children: tuple["Node | Leaf", ...]


class _Parser:
    def __init__(self, text: str) -> None:
        self.tokens = _TOKEN.findall(text)
        self.pos = 0

    def peek(self) -> str | None:
        return self.tokens[self.pos] if self.pos < len(self.tokens) else None

    def take(self) -> str:
        token = self.peek()
        if token is None:
            raise SpdxSyntaxError("espressione incompleta")
        self.pos += 1
        return token

    def parse(self) -> "Node | Leaf":
        if not self.tokens:
            raise SpdxSyntaxError("espressione vuota")
        node = self.or_(0)
        if self.peek() is not None:
            raise SpdxSyntaxError("token inatteso")
        return node

    def or_(self, depth: int) -> "Node | Leaf":
        items = [self.and_(depth)]
        while self.peek() == "OR":
            self.pos += 1
            items.append(self.and_(depth))
        return items[0] if len(items) == 1 else Node("OR", tuple(items))

    def and_(self, depth: int) -> "Node | Leaf":
        items = [self.atom(depth)]
        while self.peek() == "AND":
            self.pos += 1
            items.append(self.atom(depth))
        return items[0] if len(items) == 1 else Node("AND", tuple(items))

    def atom(self, depth: int) -> "Node | Leaf":
        token = self.take()
        if token == "(":
            if depth >= _MAX_DEPTH:
                raise SpdxSyntaxError("troppo annidata")
            node = self.or_(depth + 1)
            if self.take() != ")":
                raise SpdxSyntaxError("parentesi non chiusa")
            return node
        if token in (")", "AND", "OR", "WITH") or not (
            _ID.fullmatch(token) or _REF.fullmatch(token)
        ):
            raise SpdxSyntaxError("identificatore non valido")
        if self.peek() == "WITH":
            self.pos += 1
            exception = self.take()
            if not _ID.fullmatch(exception) or exception.endswith("+"):
                raise SpdxSyntaxError("eccezione non valida")
            return Leaf(token, f"{token} WITH {exception}")
        return Leaf(token, token)


def parse_expression(text: str) -> "Node | Leaf":
    """Albero dell'espressione; `SpdxSyntaxError` se non valida. `AND` lega più di `OR`."""
    if len(text) > MAX_EXPRESSION:
        raise SpdxSyntaxError("espressione troppo lunga")
    return _Parser(text).parse()


# --- valutazione ----------------------------------------------------------------------------


def _leaf_verdict(leaf: Leaf, forbidden: frozenset[str], approval: frozenset[str]) -> Verdict:
    names = {leaf.full, leaf.name}
    if names & forbidden:
        return Verdict.FORBIDDEN
    if names & approval:
        return Verdict.APPROVAL
    if leaf.name in _UNKNOWN_IDS or _REF.fullmatch(leaf.name):
        return Verdict.UNKNOWN
    return Verdict.COMPLIANT


def _evaluate(
    node: "Node | Leaf", forbidden: frozenset[str], approval: frozenset[str]
) -> tuple[Verdict, list[str]]:
    """Verdetto e foglie che lo determinano."""
    if isinstance(node, Leaf):
        return _leaf_verdict(node, forbidden, approval), [node.full]
    results = [_evaluate(child, forbidden, approval) for child in node.children]
    pick = max if node.op == "AND" else min
    verdict = pick(v for v, _ in results)
    return verdict, sorted({t for v, terms in results if v == verdict for t in terms})


def evaluate_expression(expression: str | None, licenses: Licenses) -> tuple[Verdict, list[str]]:
    """Verdetto per un'espressione dichiarata o rilevata (`None`: licenza mancante)."""
    if expression is None:
        return Verdict.UNKNOWN, []
    try:
        tree = parse_expression(expression)
    except SpdxSyntaxError:
        return Verdict.UNKNOWN, []
    return _evaluate(tree, frozenset(licenses.forbidden), frozenset(licenses.require_approval))


def _level(verdict: Verdict, licenses: Licenses, table: LicenseLevelTable) -> Level | None:
    if verdict is Verdict.FORBIDDEN:
        return (
            table.forbidden_internal
            if licenses.distributed_product is False
            else table.forbidden_distributed
        )
    if verdict is Verdict.APPROVAL:
        return table.require_approval
    if verdict is Verdict.UNKNOWN:
        return table.unknown
    return None


@dataclass(frozen=True)
class _Observation:
    purl: str | None
    path: str | None
    expression: str | None
    source: str  # "declared" | "detected"
    start_line: int | None = None  # solo per i finding su file (K-20)
    end_line: int | None = None


@dataclass(frozen=True)
class LicensePolicyResult:
    findings: list[Finding]
    warnings: list[Warning_] = field(default_factory=list)


def _printable(text: str) -> str:
    return "".join(c if c.isprintable() else "?" for c in text)


def evaluate_licenses(
    *,
    declared: Sequence[DeclaredLicense],
    detected: Sequence[Finding],
    licenses: Licenses | None,
    repository: str,
    commit: str | None,
    clock: Clock,
    levels: LicenseLevelTable = DEFAULT_LICENSE_LEVELS,
) -> LicensePolicyResult:
    """Findings della policy, ordinati per fingerprint; `detected` sono i finding di scancode."""
    if licenses is None:
        return LicensePolicyResult(
            [],
            [
                Warning_(
                    code="license-policy-absent",
                    message="Sezione `licenses` assente: policy licenze non valutata",
                )
            ],
        )
    warnings: list[Warning_] = []
    observations: list[_Observation] = []
    without_purl = 0
    for item in declared:
        if item.purl is None:
            without_purl += 1
            continue
        observations.append(_Observation(item.purl, None, item.expression, "declared"))
    if without_purl:
        warnings.append(
            Warning_(
                code="license-component-without-purl",
                message=f"{without_purl} componenti SBOM senza purl: licenza non valutata",
            )
        )
    for finding in detected:
        if finding.category is not Category.LICENSE or not finding.license_spdx:
            continue
        location = finding.location
        if location.purl:
            observations.append(_Observation(location.purl, None, finding.license_spdx, "detected"))
        elif location.path:
            observations.append(
                _Observation(
                    None,
                    location.path,
                    finding.license_spdx,
                    "detected",
                    location.start_line,
                    location.end_line or location.start_line,
                )
            )
    now = clock.now()
    grouped: dict[str, list[_Observation]] = {}
    for obs in observations:
        spdx = (obs.expression or "NOASSERTION")[:MAX_EXPRESSION]
        key = (
            fp.fingerprint_license_package(spdx=spdx, purl=obs.purl)
            if obs.purl
            else fp.fingerprint_license_file(path=obs.path or "", spdx=spdx)
        )
        grouped.setdefault(key, []).append(obs)
    findings: list[Finding] = []
    for key, group in sorted(grouped.items()):
        first = group[0]
        expression = first.expression
        verdict, terms = evaluate_expression(expression, licenses)
        level = _level(verdict, licenses, levels)
        if level is None:
            continue
        spdx = _printable((expression or "NOASSERTION")[:MAX_EXPRESSION])
        # Righe: non entrano nel fingerprint (percorso e licenza), quindi non lo cambiano (K-20).
        starts = [o.start_line for o in group if o.start_line is not None]
        ends = [o.end_line for o in group if o.end_line is not None]
        start_line = min(starts) if starts else None
        end_line = max([start_line, *ends]) if start_line is not None else None
        subject = _printable(first.purl or first.path or "")
        title = f"Licenza {spdx}"
        if verdict is Verdict.UNKNOWN:
            message = f"Licenza da verificare ({spdx}) per {subject}"
        elif verdict is Verdict.FORBIDDEN:
            message = f"Licenza vietata dalla policy ({spdx}) per {subject}"
        else:
            message = f"Licenza da approvare ({spdx}) per {subject}"
        findings.append(
            Finding(
                id=key,
                fingerprint=key,
                category=Category.LICENSE,
                rule_id=LICENSE_RULE_ID,
                tool=TOOL,
                tools=[TOOL],
                title=title,
                message=message[:4096],
                location=Location(
                    repository=repository,
                    commit=commit,
                    path=first.path,
                    purl=first.purl,
                    start_line=start_line,
                    end_line=end_line,
                ),
                license_spdx=spdx,
                evidence={
                    TOOL: {
                        "verdict": verdict.name.lower(),
                        "sources": sorted({o.source for o in group}),
                        "terms": [_printable(t) for t in terms],
                    }
                },
                level=level,
                level_source=LevelSource.POLICY,
                first_seen=now,
                last_seen=now,
            )
        )
    return LicensePolicyResult(findings, warnings)
