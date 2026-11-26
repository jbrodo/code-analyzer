"""Correlazione tra strumenti sugli stessi problemi (K-21, ADR-0026, ADR-0008).

checkov, hadolint e trivy segnalano in parte gli stessi problemi sugli stessi Dockerfile e
manifest. ADR-0008 non fonde finding di strumenti diversi, e resta così: fonderli cambierebbe i
fingerprint. Qui si assegna invece un **gruppo di correlazione**, un campo in più che non cambia
fingerprint, livello, punteggio né esito del gate.

Due finding sono nello stesso gruppo se hanno la stessa categoria, lo stesso file e la stessa
**chiave canonica**, e se i loro strumenti sono almeno due. La chiave viene da una tabella di dati
(`TABLE`): associa `(strumento, regola)` a un problema, per esempio «container eseguito come
root». Una regola senza voce non ha gruppo, e un finding che nessun altro strumento conferma non
ne ha, anche se la sua regola ha una voce.

La tabella parte dai problemi di `tests/fixtures/repos/iac-app` (F-02) e cresce con i dati di X-02.
È versionata: la versione sta nel report (`correlation_version`) e cambia a ogni modifica dei
dati, perché un gruppo assegnato con una tabella diversa non è confrontabile.
"""

import hashlib
from collections import defaultdict
from collections.abc import Iterable, Mapping, Sequence

from ca_core.models.finding import Finding
from ca_core.scoring.levels import level_rank

TABLE_VERSION = "1"
GROUP_PREFIX = "cg1:"  # il numero cambia solo se cambia il modo di costruire l'identificativo

# chiave canonica -> {strumento: regole}. Ogni regola compare una volta sola in tutta la tabella.
_PROBLEMS: Mapping[str, Mapping[str, tuple[str, ...]]] = {
    "dockerfile.latest-tag": {
        "trivy": ("DS-0001",),
        "checkov": ("CKV_DOCKER_7",),
        "hadolint": ("DL3007",),
    },
    "dockerfile.add-instead-of-copy": {
        "trivy": ("DS-0005",),
        "checkov": ("CKV_DOCKER_4",),
        "hadolint": ("DL3020",),
    },
    "dockerfile.sudo": {
        "trivy": ("DS-0010",),
        "checkov": ("CKV2_DOCKER_1",),
        "hadolint": ("DL3004",),
    },
    "dockerfile.root-user": {"trivy": ("DS-0002",), "checkov": ("CKV_DOCKER_3",)},
    "dockerfile.no-healthcheck": {"trivy": ("DS-0026",), "checkov": ("CKV_DOCKER_2",)},
    "dockerfile.cd-instead-of-workdir": {"trivy": ("DS-0013",), "hadolint": ("DL3003",)},
    "dockerfile.apt-recommends": {"trivy": ("DS-0029",), "hadolint": ("DL3015",)},
    "kubernetes.privileged": {"trivy": ("KSV-0017",), "checkov": ("CKV_K8S_16",)},
    "kubernetes.latest-tag": {"trivy": ("KSV-0013",), "checkov": ("CKV_K8S_14",)},
    "terraform.aws.ssh-open": {"trivy": ("AWS-0107",), "checkov": ("CKV_AWS_24",)},
    "terraform.aws.s3-public-access-block": {
        "trivy": ("AWS-0086",),
        "checkov": ("CKV2_AWS_6",),
    },
}


def _invert(problems: Mapping[str, Mapping[str, tuple[str, ...]]]) -> dict[tuple[str, str], str]:
    table: dict[tuple[str, str], str] = {}
    for key, tools in problems.items():
        for tool, rules in tools.items():
            for rule in rules:
                if (tool, rule) in table:
                    raise ValueError(f"regola in due problemi: {tool} {rule}")
                table[(tool, rule)] = key
    return table


TABLE: Mapping[tuple[str, str], str] = _invert(_PROBLEMS)


def canonical_key(tool: str, rule_id: str) -> str | None:
    return TABLE.get((tool, rule_id))


def group_id(category: str, path: str, key: str) -> str:
    digest = hashlib.sha256(f"{category}\x00{path}\x00{key}".encode()).hexdigest()
    return GROUP_PREFIX + digest[:16]


def _keys(finding: Finding) -> set[str]:
    return {k for t in finding.tools if (k := canonical_key(t, finding.rule_id)) is not None}


def assign_correlation(findings: Iterable[Finding]) -> list[Finding]:
    """Gli stessi finding, nello stesso ordine, con `correlation` dove due strumenti concordano."""
    items = list(findings)
    members: dict[tuple[str, str, str], list[int]] = defaultdict(list)
    tools: dict[tuple[str, str, str], set[str]] = defaultdict(set)
    for index, finding in enumerate(items):
        path = finding.location.path
        if path is None:
            continue
        for key in _keys(finding):
            slot = (finding.category.value, path, key)
            members[slot].append(index)
            tools[slot].update(finding.tools)
    out = list(items)
    for slot, indices in members.items():
        if len(tools[slot]) < 2:
            continue
        identifier = group_id(*slot)
        for index in indices:
            if out[index].correlation is None:
                out[index] = out[index].model_copy(update={"correlation": identifier})
    return out


def representatives(findings: Sequence[Finding]) -> list[Finding]:
    """Un finding per gruppo (il più grave, a parità il primo per fingerprint) e tutti gli altri.

    Per i campioni di G2.b (X-03) e per i commenti sulle PR (ADR-0027): un problema visto da tre
    strumenti compare una volta. L'ordine di ingresso si mantiene.
    """
    best: dict[str, Finding] = {}
    for finding in findings:
        group = finding.correlation
        if group is None:
            continue
        current = best.get(group)
        if current is None or _preferred(finding) < _preferred(current):
            best[group] = finding
    return [f for f in findings if f.correlation is None or best[f.correlation] is f]


def _preferred(finding: Finding) -> tuple[int, str]:
    return (level_rank(finding.level), finding.fingerprint)


def group_members(findings: Sequence[Finding]) -> dict[str, list[Finding]]:
    """Finding per gruppo, per mostrare «anche segnalato da» accanto al rappresentante."""
    groups: dict[str, list[Finding]] = defaultdict(list)
    for finding in findings:
        if finding.correlation is not None:
            groups[finding.correlation].append(finding)
    return dict(groups)
