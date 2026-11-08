"""T-04: l'harness sui campioni reali di V-04 (`tests/fixtures/plugin-output/`).

Due letture dello stesso campione:
- tal quale: l'output grezzo dello scanner NON e' un output di plugin conforme, e il motivo e'
  registrato per nome (regressione dell'harness e documentazione di cosa deve fare l'adattatore);
- dopo un adattatore di prova (`conform`): le trasformazioni minime richieste da ADR-0007 e
  ADR-0012 bastano a renderlo conforme. Non e' l'adattatore reale, che spetta ai task P.
"""

import copy
import hashlib
import json
import re
from pathlib import Path
from typing import Any

import pytest
from plugin_output_harness import (
    SAMPLES,
    check_output,
    cyclonedx_problems,
    kind_of,
    load_json,
    plugin_of,
)

SARIF_SAMPLES = ("bandit", "gitleaks", "osv-scanner", "semgrep", "trivy")
CYCLONEDX_SAMPLES = ("syft", "trivy")
CONTRACT_PROPERTIES = {"aliases", "cvss", "tool_severity", "license_spdx", "purl", "category"}

# Gruppi di controlli che l'output grezzo non supera (V-04, ADR-0007, ADR-0012).
RAW_VERDICTS: dict[str, set[str]] = {
    "bandit.sarif": {"properties", "snippet", "uri"},  # issue_*; B105 mette il valore in snippet
    "gitleaks.sarif": {"properties", "snippet", "gitleaks"},  # `tags`; REDACTED; email e autore
    "osv-scanner.sarif": {"uri"},  # file:///workspace/...
    "semgrep.sarif": {"snippet", "uri"},  # snippet con il codice; uriBaseId
    "trivy.sarif": {"uri"},  # uriBaseId ROOTPATH
}


def sample(name: str) -> Path:
    return SAMPLES / name


def conform(document: dict[str, Any], plugin: str) -> dict[str, Any]:
    """Adattatore di prova: solo cio' che ADR-0007 e ADR-0012 chiedono, nulla di piu'."""
    doc = copy.deepcopy(document)

    def strip(value: Any) -> Any:
        if isinstance(value, dict):
            return {k: strip(v) for k, v in value.items() if k.casefold() != "snippet"}
        if isinstance(value, list):
            return [strip(v) for v in value]
        return value

    doc = strip(doc)
    for run in doc["runs"]:
        for result in run.get("results", []):
            for location in result.get("locations", []):
                artifact = location["physicalLocation"]["artifactLocation"]
                artifact.pop("uriBaseId", None)
                artifact.pop("index", None)
                artifact["uri"] = re.sub(r"^(file://)?/workspace/", "", artifact["uri"])
            props = {
                k: v for k, v in result.get("properties", {}).items() if k in CONTRACT_PROPERTIES
            }
            if plugin == "gitleaks":
                uri = result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
                props["category"] = "secret"
                props["secret_sha256"] = hashlib.sha256(
                    f"{result['ruleId']}:{uri}".encode()
                ).hexdigest()
                for key in ("email", "author", "commitMessage"):
                    result.get("partialFingerprints", {}).pop(key, None)
            if props:
                result["properties"] = props
            else:
                result.pop("properties", None)
    return doc


def write(tmp_path: Path, name: str, document: dict[str, Any]) -> Path:
    path = tmp_path / name
    path.write_text(json.dumps(document), encoding="utf-8")
    return path


@pytest.mark.parametrize("name", sorted(RAW_VERDICTS))
def test_raw_scanner_output_fails_exactly_the_documented_checks(name: str) -> None:
    assert set(check_output(sample(name))) == RAW_VERDICTS[name]


def test_every_sarif_sample_has_a_documented_verdict() -> None:
    on_disk = {p.name for p in SAMPLES.iterdir() if kind_of(p) == "sarif"}
    assert on_disk == set(RAW_VERDICTS)


@pytest.mark.parametrize("plugin", SARIF_SAMPLES)
def test_sarif_sample_passes_after_the_minimal_adaptation(plugin: str, tmp_path: Path) -> None:
    adapted = write(
        tmp_path, f"{plugin}.sarif", conform(load_json(sample(f"{plugin}.sarif")), plugin)
    )
    assert check_output(adapted) == {}


def test_adaptation_keeps_the_findings(tmp_path: Path) -> None:
    """Il passaggio di prova non cancella risultati: altrimenti 'conforme' sarebbe banale."""
    for plugin in SARIF_SAMPLES:
        raw = load_json(sample(f"{plugin}.sarif"))
        adapted = conform(raw, plugin)
        assert len(adapted["runs"][0]["results"]) == len(raw["runs"][0]["results"]) > 0


@pytest.mark.parametrize("plugin", CYCLONEDX_SAMPLES)
def test_cyclonedx_samples_are_valid_1_7(plugin: str) -> None:
    path = sample(f"{plugin}.cdx.json")
    assert kind_of(path) == "cyclonedx"
    assert load_json(path)["specVersion"] == "1.7"
    assert check_output(path) == {}


@pytest.mark.parametrize("plugin", CYCLONEDX_SAMPLES)
def test_cyclonedx_other_versions_are_rejected(plugin: str) -> None:
    document = load_json(sample(f"{plugin}.cdx.json"))
    assert cyclonedx_problems({**document, "specVersion": "1.6"})
    with pytest.raises(ValueError, match="nessuno schema fissato"):
        cyclonedx_problems(document, ("1.6", "1.7"))


@pytest.mark.parametrize("plugin", CYCLONEDX_SAMPLES)
def test_cyclonedx_non_conforming_document_is_rejected(plugin: str) -> None:
    document = load_json(sample(f"{plugin}.cdx.json"))
    broken = {**document, "components": [{"type": "no-such-type", "name": "x"}]}
    assert cyclonedx_problems(broken)


def test_scancode_native_output_is_not_a_plugin_output() -> None:
    path = sample("scancode.json")
    assert kind_of(path) == "native"
    assert "license_detections" in load_json(path)
    with pytest.raises(ValueError, match="nativo"):
        check_output(path)


def test_plugin_name_comes_from_the_file_name() -> None:
    assert plugin_of(Path("x/syft.cdx.json")) == "syft"
    assert plugin_of(Path("x/osv-scanner.sarif")) == "osv-scanner"
