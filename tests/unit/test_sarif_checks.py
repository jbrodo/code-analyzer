import copy
import json
from pathlib import Path
from typing import Any

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from ca_core.sarif import SarifError, SarifErrorCode, parse_sarif, structural_checks
from ca_core.sarif.checks import no_snippet
from ca_core.schema_validation import SchemaStore

ROOT = Path(__file__).resolve().parents[2]
SAMPLES = ROOT / "tests" / "fixtures" / "plugin-output"
NAMES = ["bandit.sarif", "semgrep.sarif", "gitleaks.sarif"]


@pytest.fixture(scope="module")
def store() -> SchemaStore:
    return SchemaStore(ROOT / "schemas" / "vendor")


def adapted(name: str) -> dict[str, Any]:
    """Il campione grezzo senza le `properties` dello scanner, come lo scrive l'adattatore."""
    document: dict[str, Any] = json.loads((SAMPLES / name).read_bytes())
    for run in document["runs"]:
        for result in run.get("results", []):
            result.pop("properties", None)
    return document


def strip(node: Any) -> None:
    if isinstance(node, dict):
        node.pop("snippet", None)
        for value in node.values():
            strip(value)
    elif isinstance(node, list):
        for item in node:
            strip(item)


def run(store: SchemaStore, plugin: str, document: dict[str, Any]) -> None:
    parse_sarif(json.dumps(document).encode(), store, checks=structural_checks(plugin))


def rejected(store: SchemaStore, plugin: str, document: dict[str, Any]) -> SarifError:
    with pytest.raises(SarifError) as info:
        run(store, plugin, document)
    assert info.value.code is SarifErrorCode.CHECK
    return info.value


def clean_gitleaks(store: SchemaStore) -> dict[str, Any]:
    document = adapted("gitleaks.sarif")
    strip(document)
    run(store, "gitleaks", document)
    return document


@pytest.mark.parametrize("name", NAMES)
def test_real_samples_with_snippet_are_rejected(store: SchemaStore, name: str) -> None:
    error = rejected(store, name.removesuffix(".sarif"), adapted(name))

    assert any("snippet" in d for d in error.details)


@pytest.mark.parametrize("name", NAMES)
def test_samples_without_snippet_pass(store: SchemaStore, name: str) -> None:
    document = adapted(name)
    strip(document)

    run(store, name.removesuffix(".sarif"), document)


def test_redacted_snippet_still_fails_for_any_plugin(store: SchemaStore) -> None:
    rejected(store, "trivy", adapted("gitleaks.sarif"))  # snippet: "REDACTED"


def test_snippet_key_in_other_case_or_property_bag_fails(store: SchemaStore) -> None:
    document = adapted("semgrep.sarif")
    strip(document)
    document["runs"][0]["properties"] = {"Snippet": {"text": "x"}}

    rejected(store, "semgrep", document)


@pytest.mark.parametrize("key", ["email", "author", "commitMessage"])
def test_gitleaks_personal_fingerprint_keys_fail(store: SchemaStore, key: str) -> None:
    document = clean_gitleaks(store)
    document["runs"][0]["results"][0]["partialFingerprints"] = {key: "x"}

    error = rejected(store, "gitleaks", document)

    assert any(f"partialFingerprints/{key}" in d for d in error.details)
    run(store, "semgrep", document)  # la regola vale solo per gitleaks


@pytest.mark.parametrize(
    "text",
    [
        "github-pat has detected secret for file conf.py at commit ab394a3.",
        "github-pat has detected secret for file conf.py.",  # cartella non git
    ],
)
def test_gitleaks_redacted_message_models_pass(store: SchemaStore, text: str) -> None:
    document = clean_gitleaks(store)
    document["runs"][0]["results"][0]["message"] = {"text": text}

    run(store, "gitleaks", document)


@pytest.mark.parametrize(
    "message",
    [
        {"text": "github-pat has detected secret for file conf.py at commit ab394a3. ghp_SECRET"},
        {"text": "github-pat found ghp_SECRET in conf.py"},
        {"text": "other-rule has detected secret for file conf.py at commit ab394a3."},
        {"text": "github-pat has detected secret for file x.py at commit ab394a3."},
        {"text": "github-pat has detected secret for file conf.py at commit ghp_SECRET."},
        {"text": "github-pat has detected secret for file conf.py.", "markdown": "ghp_SECRET"},
    ],
)
def test_gitleaks_message_off_model_fails(store: SchemaStore, message: dict[str, Any]) -> None:
    document = clean_gitleaks(store)
    document["runs"][0]["results"][0]["message"] = message

    error = rejected(store, "gitleaks", document)

    assert "ghp_SECRET" not in str(error) + "".join(error.details)
    run(store, "bandit", document)  # il modello vale solo per gitleaks


def test_gitleaks_without_location_fails(store: SchemaStore) -> None:
    document = copy.deepcopy(clean_gitleaks(store))
    del document["runs"][0]["results"][0]["locations"]

    rejected(store, "gitleaks", document)


json_values = st.recursive(
    st.none() | st.booleans() | st.integers(-5, 5) | st.text(max_size=5),
    lambda children: st.lists(children, max_size=3)
    | st.dictionaries(st.sampled_from(["snippet", "a", "text", "SNIPPET"]), children, max_size=3),
    max_leaves=12,
)


def has_snippet(node: Any) -> bool:
    if isinstance(node, dict):
        return any(k.casefold() == "snippet" or has_snippet(v) for k, v in node.items())
    return isinstance(node, list) and any(has_snippet(v) for v in node)


@settings(max_examples=100)
@given(extra=json_values)
def test_snippet_detection_matches_a_reference_walk(extra: Any) -> None:
    document = {"runs": [{"results": [{"properties": {"x": extra}}]}]}
    if has_snippet(document):
        with pytest.raises(SarifError):
            no_snippet(document)
    else:
        no_snippet(document)
