"""Plugin bandit (P-08) sull'immagine reale, con `OciExecutor` e il profilo completo. Opzionale.

`CA_TEST_DOCKER=1`; vedi `plugin_image_support.py` per `COSIGN` e `SYFT`. Costruisce
`localhost/ca-plugin-bandit:itest` (la build scarica le wheel e pip ne controlla gli hash: serve la
rete solo per la build, mai per l'esecuzione) e la rimuove a fine sessione.
"""

import json
from collections.abc import Iterator
from pathlib import Path

import pytest
import yaml
from plugin_image_support import (
    BUILTIN,
    HARNESS,
    REPOS,
    build_image,
    gate,
    needs_cosign,
    needs_docker,
    needs_syft,
    run_ok,
    run_plugin,
    run_signed,
    signed_image,
)

from ca_core.ports import RunOutcome

PLUGIN = "bandit"
TAG = "localhost/ca-plugin-bandit:itest"
SENTINEL = "sentinel-hunter2-4f9a"
pytestmark = needs_docker


@pytest.fixture(scope="module")
def image_id() -> Iterator[str]:
    yield from build_image(PLUGIN, TAG)


def findings(raw: bytes) -> set[tuple[str, str, int]]:
    document = json.loads(raw)
    assert HARNESS.sarif_problems(document, PLUGIN) == {}
    return {
        (
            r["ruleId"],
            r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],
            r["locations"][0]["physicalLocation"]["region"]["startLine"],
        )
        for r in document["runs"][0]["results"]
    }


def recorded(repo: str) -> set[tuple[str, str, int]]:
    return findings((BUILTIN / PLUGIN / f"fixtures/output/bandit.{repo}.sarif").read_bytes())


@pytest.mark.parametrize("repo", ["python-app", "js-ts-app"])
def test_full_profile_output_is_conforming_and_equals_the_recorded_one(
    image_id: str, tmp_path: Path, repo: str
) -> None:
    files = run_ok(PLUGIN, TAG, image_id, REPOS / repo, tmp_path)
    assert list(files) == ["results.sarif"]
    assert b"/workspace" not in files["results.sarif"]
    assert findings(files["results.sarif"]) == recorded(repo)


def test_expected_python_findings_are_found_and_the_skipped_rules_are_not(
    image_id: str, tmp_path: Path
) -> None:
    found = findings(run_ok(PLUGIN, TAG, image_id, REPOS / "python-app", tmp_path)["results.sarif"])
    expected = {
        (e["rule_id"], e["path"], e["start_line"])
        for e in yaml.safe_load((REPOS / "python-app/expected-findings.yaml").read_text())[
            "expected"
        ]
        if "bandit" in e["tools"]
    }
    assert expected <= found
    assert not {"B105", "B106", "B107"} & {rule for rule, _, _ in found}


def test_assert_is_reported_in_production_code_and_not_in_test_files(
    image_id: str, tmp_path: Path
) -> None:
    ws = tmp_path / "ws"
    (ws / "app").mkdir(parents=True)
    (ws / "tests").mkdir()
    (ws / "app/logic.py").write_text("def f(x):\n    assert x\n")
    (ws / "app/test_logic.py").write_text("def test_f():\n    assert True\n")
    (ws / "tests/helpers.py").write_text("def check(x):\n    assert x\n")
    found = findings(run_ok(PLUGIN, TAG, image_id, ws, tmp_path / "run")["results.sarif"])
    assert {(rule, uri) for rule, uri, _ in found if rule == "B101"} == {("B101", "app/logic.py")}


def test_hardcoded_secret_never_reaches_out_and_repository_config_is_ignored(
    image_id: str, tmp_path: Path
) -> None:
    ws = tmp_path / "ws"
    ws.mkdir()
    (ws / "app.py").write_text(
        f"import subprocess\nPASSWORD = '{SENTINEL}'\n"
        f"def f(c, password='{SENTINEL}'):\n    subprocess.call(c, shell=True)\n"
    )
    (ws / ".bandit").write_text("[bandit]\nskips: B602\n")  # config ostile: spegne il controllo
    (ws / "pyproject.toml").write_text('[tool.bandit]\nskips = ["B602"]\n')
    (ws / "ok.py").write_text("x = 1\n")
    (ws / "broken.py").write_text("def f(:\n")
    raw = run_ok(PLUGIN, TAG, image_id, ws, tmp_path / "w")["results.sarif"]
    assert SENTINEL.encode() not in raw
    rules = {rule for rule, _, _ in findings(raw)}
    assert "B602" in rules and not {"B105", "B106", "B107"} & rules


def test_plugin_fails_when_the_workspace_cannot_be_read(image_id: str, tmp_path: Path) -> None:
    result, files = run_plugin(PLUGIN, TAG, image_id, tmp_path / "missing", tmp_path)
    assert result.outcome is RunOutcome.FAILED and files == {}


def test_empty_workspace_is_a_valid_empty_sarif(image_id: str, tmp_path: Path) -> None:
    (tmp_path / "ws").mkdir()
    files = run_ok(PLUGIN, TAG, image_id, tmp_path / "ws", tmp_path / "w")
    assert findings(files["results.sarif"]) == set()


@needs_syft
def test_build_image_gate_checks_licenses_and_writes_the_image_sbom(tmp_path: Path) -> None:
    document = gate(PLUGIN, "localhost/ca-plugin-bandit:gate", tmp_path)
    names = {c.get("name") for c in document["components"]}
    assert document["specVersion"] == "1.7" and {"bandit", "sarif-om"} <= names


@needs_cosign
def test_signed_digest_is_verified_pulled_and_run(
    image_id: str, tmp_path_factory: pytest.TempPathFactory
) -> None:
    keys, work = tmp_path_factory.mktemp("keys"), tmp_path_factory.mktemp("w")  # fuori dal repo
    with signed_image(PLUGIN, "5061", "ca-p08-test", keys) as signed:
        raw = run_signed(PLUGIN, signed, REPOS / "python-app", work)
    assert findings(raw) == recorded("python-app")


def test_recorded_outputs_conform_to_the_contract() -> None:
    for path in (BUILTIN / PLUGIN / "fixtures/output").glob("bandit.*.sarif"):
        assert HARNESS.check_output(path) == {}
