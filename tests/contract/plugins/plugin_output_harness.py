"""Harness di contratto per l'output dei plugin (T-04, ADR-0003, ADR-0007, ADR-0012).

Convalida l'output di un adattatore, gia' scritto su file, contro gli schemi in `schemas/` e le
regole strutturali di K-10. Non importa `ca_core`: gli adattatori nelle immagini non lo importano
e il test deve vedere il contratto cosi' come lo vede un consumatore esterno. Le regole di K-10
sono quindi riscritte qui dalla scheda; un disallineamento con `ca_core.sarif.checks` si vede
confrontando l'esito sugli stessi campioni.

Ogni controllo restituisce un elenco di problemi (vuoto = conforme), mai un'eccezione sul
contenuto: il test decide cosa aspettarsi.
"""

import json
import re
from collections.abc import Iterator
from functools import cache
from pathlib import Path
from typing import Any

from jsonschema import Draft4Validator, Draft7Validator, Draft202012Validator
from referencing import Registry, Resource

ROOT = Path(__file__).resolve().parents[3]
VENDOR = ROOT / "schemas" / "vendor"
PROPERTIES_SCHEMA = ROOT / "schemas" / "plugin-sarif-properties.schema.json"
GRAPH_SCHEMA = ROOT / "schemas" / "graph.schema.json"
BUILTIN = ROOT / "packages" / "ca-plugins" / "src" / "ca_plugins" / "builtin"
SAMPLES = ROOT / "tests" / "fixtures" / "plugin-output"

ALLOWED_CYCLONEDX_VERSIONS = ("1.7",)
GITLEAKS = "gitleaks"
FORBIDDEN_FINGERPRINT_KEYS = frozenset({"email", "author", "commitMessage"})
_COMMIT = re.compile(r"[0-9a-f]{7,64}")
_SCHEME = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*:")
_MAX_PROBLEMS = 20


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def kind_of(path: Path) -> str:
    """Formato dall'estensione: `.sarif`, `.cdx.json`, `.graph.json`, altro = nativo del tool."""
    if path.name.endswith(".sarif"):
        return "sarif"
    if path.name.endswith(".graph.json"):
        return "graph"
    if path.name.endswith(".cdx.json"):
        return "cyclonedx"
    return "native"


@cache
def _sarif_validator() -> Draft4Validator:
    return Draft4Validator(load_json(VENDOR / "sarif-schema-2.1.0.json"))


@cache
def _bom_validator() -> Draft7Validator:
    """bom-1.7 con i `$ref` relativi risolti sui file fissati, senza rete."""
    resources = []
    for name in (
        "bom-1.7.schema.json",
        "spdx.schema.json",
        "jsf-0.82.schema.json",
        "cryptography-defs.schema.json",
    ):
        contents = load_json(VENDOR / name)
        resource = Resource.from_contents(contents)
        resources += [(contents["$id"], resource), (name, resource)]
    registry: Registry[Any] = Registry().with_resources(resources)
    return Draft7Validator(load_json(VENDOR / "bom-1.7.schema.json"), registry=registry)


@cache
def _graph_validator() -> Draft202012Validator:
    return Draft202012Validator(load_json(GRAPH_SCHEMA))


@cache
def _properties_validator() -> Draft202012Validator:
    return Draft202012Validator(load_json(PROPERTIES_SCHEMA))


def _where(error: Any) -> str:
    return "/" + "/".join(str(p) for p in error.absolute_path)


def _limited(problems: list[str]) -> list[str]:
    return problems[:_MAX_PROBLEMS]


def sarif_schema_problems(document: Any) -> list[str]:
    """SARIF 2.1.0 (schema OASIS fissato) e un solo `run`, come i campioni di V-04."""
    problems = [f"{_where(e)}: {e.message[:120]}" for e in _sarif_validator().iter_errors(document)]
    if not problems and len(document["runs"]) != 1:
        problems.append("/runs: atteso un solo run")
    return _limited(problems)


def _results(document: Any) -> Iterator[tuple[str, dict[str, Any]]]:
    for run_index, run in enumerate(document.get("runs") or ()):
        for index, result in enumerate(run.get("results") or ()):
            yield f"/runs/{run_index}/results/{index}", result


def properties_problems(document: Any) -> list[str]:
    """`results[].properties` contro `plugin-sarif-properties` (C-05). Assenti = conformi."""
    problems: list[str] = []
    for base, result in _results(document):
        if "properties" not in result:
            continue
        problems += [
            f"{base}/properties{_where(e)}: {e.message[:120]}"
            for e in _properties_validator().iter_errors(result["properties"])
        ]
    return _limited(problems)


def _walk(value: Any, path: tuple[str, ...] = ()) -> Iterator[tuple[tuple[str, ...], str, Any]]:
    """Ogni coppia chiave-valore a qualunque profondita', in liste e oggetti."""
    if isinstance(value, dict):
        for key, child in value.items():
            yield path, key, child
            yield from _walk(child, (*path, key))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            yield from _walk(child, (*path, str(index)))


def snippet_problems(document: Any) -> list[str]:
    """K-10: la chiave `snippet`, a qualunque profondita', fa fallire il plugin (ADR-0012)."""
    return _limited(
        [
            "/" + "/".join((*path, key))
            for path, key, _ in _walk(document)
            if key.casefold() == "snippet"
        ]
    )


def _first_uri(result: dict[str, Any]) -> str | None:
    for location in result.get("locations") or ():
        uri = ((location.get("physicalLocation") or {}).get("artifactLocation") or {}).get("uri")
        return uri if isinstance(uri, str) else None
    return None


def _is_redacted_gitleaks_message(result: dict[str, Any]) -> bool:
    message = result.get("message")
    if not isinstance(message, dict) or set(message) != {"text"}:
        return False
    text, rule_id, uri = message["text"], result.get("ruleId"), _first_uri(result)
    if not (isinstance(text, str) and isinstance(rule_id, str) and uri is not None):
        return False
    head = f"{rule_id} has detected secret for file {uri}"
    if text == f"{head}.":
        return True
    prefix = f"{head} at commit "
    return (
        text.startswith(prefix)
        and text.endswith(".")
        and _COMMIT.fullmatch(text[len(prefix) : -1]) is not None
    )


def gitleaks_problems(document: Any) -> list[str]:
    """K-10 per gitleaks: `message` del modello oscurato, niente dati personali nelle impronte."""
    problems: list[str] = []
    for base, result in _results(document):
        if not _is_redacted_gitleaks_message(result):
            problems.append(f"{base}/message")
        fingerprints = result.get("partialFingerprints") or {}
        problems += [
            f"{base}/partialFingerprints/{key}"
            for key in sorted(FORBIDDEN_FINGERPRINT_KEYS & set(fingerprints))
        ]
    return _limited(problems)


def uri_problems(document: Any) -> list[str]:
    """ADR-0007 (emendamento): `uri` relativo alla radice del workspace, senza `uriBaseId`."""
    problems: list[str] = []
    for path, key, value in _walk(document):
        if key != "artifactLocation" or not isinstance(value, dict):
            continue
        where = "/" + "/".join((*path, key))
        if "uriBaseId" in value:
            problems.append(f"{where}/uriBaseId")
        uri = value.get("uri")
        if not isinstance(uri, str):
            continue
        segments = uri.replace("\\", "/").split("/")
        if _SCHEME.match(uri) or uri.startswith(("/", "\\")) or ".." in segments:
            problems.append(f"{where}/uri")
    return _limited(problems)


def sarif_problems(document: Any, plugin: str) -> dict[str, list[str]]:
    """Esito per gruppo di controlli; se lo schema SARIF fallisce, gli altri non si eseguono."""
    schema = sarif_schema_problems(document)
    if schema:
        return {"schema": schema}
    report = {
        "properties": properties_problems(document),
        "snippet": snippet_problems(document),
        "uri": uri_problems(document),
    }
    if plugin == GITLEAKS:
        report["gitleaks"] = gitleaks_problems(document)
    return {name: found for name, found in report.items() if found}


def cyclonedx_problems(
    document: Any, allowed_versions: tuple[str, ...] = ALLOWED_CYCLONEDX_VERSIONS
) -> list[str]:
    """CycloneDX: versione dichiarata tra quelle ammesse e documento valido per lo schema."""
    unsupported = set(allowed_versions) - set(ALLOWED_CYCLONEDX_VERSIONS)
    if (
        unsupported
    ):  # in `schemas/vendor/` c'e' solo bom-1.7 (M-06): niente validazione per le altre
        raise ValueError(f"nessuno schema fissato per CycloneDX {sorted(unsupported)}")
    version = document.get("specVersion") if isinstance(document, dict) else None
    if version not in allowed_versions:
        return [f"/specVersion: {version!r} non ammessa ({', '.join(allowed_versions)})"]
    return _limited(
        [f"{_where(e)}: {e.message[:120]}" for e in _bom_validator().iter_errors(document)]
    )


def graph_problems(document: Any) -> list[str]:
    """Contratto `graph` (C-02), che rifiuta anche i percorsi con caratteri di controllo."""
    problems = [f"{_where(e)}: {e.message[:120]}" for e in _graph_validator().iter_errors(document)]
    return _limited(problems)


def plugin_of(path: Path) -> str:
    """Nome del plugin dal campione: `bandit.sarif` -> `bandit`, `syft.cdx.json` -> `syft`."""
    return path.name.split(".", 1)[0]


def check_output(path: Path) -> dict[str, list[str]]:
    """Esito per gruppo di controlli sul file `path`; vuoto = conforme. Tool nativi: errore."""
    kind = kind_of(path)
    document = load_json(path)
    if kind == "sarif":
        return sarif_problems(document, plugin_of(path))
    if kind == "cyclonedx":
        found = cyclonedx_problems(document)
        return {"cyclonedx": found} if found else {}
    if kind == "graph":
        found = graph_problems(document)
        return {"graph": found} if found else {}
    raise ValueError(f"{path.name}: formato nativo, non e' un output di plugin conforme")


def discover_adapter_outputs(builtin: Path = BUILTIN) -> list[Path]:
    """Output registrati degli adattatori: `builtin/<plugin>/fixtures/output/*.sarif|*.cdx.json`.

    Convenzione di T-04 per la regola 4 di AGENTS.md (ogni plugin porta le sue fixture): il nome
    del file inizia con il nome del plugin, come per i campioni di V-04.
    """
    if not builtin.is_dir():
        return []
    found: list[Path] = []
    for plugin_dir in sorted(p for p in builtin.iterdir() if p.is_dir()):
        output = plugin_dir / "fixtures" / "output"
        if output.is_dir():
            found += sorted(
                p
                for p in output.iterdir()
                if p.name.endswith((".sarif", ".cdx.json", ".graph.json"))
            )
    return found
