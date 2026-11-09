"""Plugin gitleaks (P-07) sull'immagine reale, con `OciExecutor` e il profilo completo. Opzionale.

`CA_TEST_DOCKER=1`; vedi `plugin_image_support.py` per `COSIGN` e `SYFT`. La storia con i segreti
finti si genera con `tests/fixtures/builders/secrets_history.py` (F-04). I vettori di configurazione
git ostile sono in `test_gitleaks_hostile_repo.py`.
"""

import json
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
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
    secrets_history,
    signed_image,
)

from ca_core.ports import RunOutcome

PLUGIN = "gitleaks"
TAG = "localhost/ca-plugin-gitleaks:itest"
pytestmark = needs_docker


@pytest.fixture(scope="module")
def image_id() -> Iterator[str]:
    yield from build_image(PLUGIN, TAG)


def results(raw: bytes) -> list[dict[str, Any]]:
    document = json.loads(raw)
    assert HARNESS.sarif_problems(document, PLUGIN) == {}  # schema, snippet, uri, K-10, proprieta'
    found: list[dict[str, Any]] = document["runs"][0]["results"]
    return found


def keys(raw: bytes) -> set[tuple[str, str, str]]:
    return {
        (
            r["ruleId"],
            r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],
            r["properties"]["secret_sha256"],
        )
        for r in results(raw)
    }


def notes(raw: bytes) -> list[str]:
    runs = json.loads(raw)["runs"][0]
    return [
        n["message"]["text"]
        for inv in runs.get("invocations", [])
        for n in inv["toolExecutionNotifications"]
    ]


def test_history_secrets_are_found_hashed_and_never_written_out(
    image_id: str, tmp_path: Path
) -> None:
    history = secrets_history.build_history(tmp_path / "ws")
    files = run_ok(PLUGIN, TAG, image_id, history.path, tmp_path / "w")
    assert list(files) == ["results.sarif"]
    raw = files["results.sarif"]
    found = keys(raw)
    pat, gitlab = history.secrets["PAT"], history.secrets["GITLAB"]
    assert ("github-pat", "app/settings.py", pat.sha256) in found
    assert ("gitlab-pat", "deploy/.env", gitlab.sha256) in found  # solo nella storia
    assert {k[2] for k in found} == {pat.sha256, gitlab.sha256}
    text = raw.decode()
    for forbidden in (pat.value, gitlab.value, "fixture@example.invalid", "Fixture Author"):
        assert forbidden not in text
    for forbidden in ("snippet", "commitMessage", "email", "author", "REDACTED", "/workspace"):
        assert forbidden not in text
    assert notes(raw) == []
    recorded = (BUILTIN / PLUGIN / "fixtures/output/gitleaks.secrets-history.sarif").read_bytes()
    assert keys(recorded) == found  # gli SHA dei commit sono stabili: l'output registrato e' questo


def test_shallow_clone_finds_only_what_is_in_head_and_says_coverage_is_reduced(
    image_id: str, tmp_path: Path
) -> None:
    source = secrets_history.build_history(tmp_path / "src")
    clone = secrets_history.shallow_clone(source.path, tmp_path / "clone")
    raw = run_ok(PLUGIN, TAG, image_id, clone, tmp_path / "w")["results.sarif"]
    assert {r for r, _, _ in keys(raw)} == {"github-pat"}  # il segreto rimosso non e' piu' visibile
    assert notes(raw) == ["shallow clone: history coverage is reduced"]


@pytest.mark.parametrize("repo", ["python-app", "js-ts-app"])
def test_workspace_without_git_is_scanned_as_files_with_a_note(
    image_id: str, tmp_path: Path, repo: str
) -> None:
    raw = run_ok(PLUGIN, TAG, image_id, REPOS / repo, tmp_path)["results.sarif"]
    recorded = (BUILTIN / PLUGIN / f"fixtures/output/gitleaks.{repo}.sarif").read_bytes()
    assert keys(raw) == keys(recorded) == set()
    assert notes(raw) == ["no git history: only the files of the workspace were scanned"]


def test_plain_files_with_a_secret_are_found_without_git(image_id: str, tmp_path: Path) -> None:
    ws = tmp_path / "ws"
    ws.mkdir()
    secret = secrets_history.fake_secrets("plain")["PAT"]
    (ws / "conf.env").write_text(f"GITHUB_TOKEN={secret.value}\n")
    raw = run_ok(PLUGIN, TAG, image_id, ws, tmp_path / "w")["results.sarif"]
    assert keys(raw) == {("github-pat", "conf.env", secret.sha256)}
    assert secret.value not in raw.decode()


def test_unsupported_git_directory_fails_the_plugin(image_id: str, tmp_path: Path) -> None:
    ws = tmp_path / "ws"
    ws.mkdir()
    (ws / ".git").write_text("gitdir: /elsewhere\n")  # sottomodulo o worktree collegato
    result, files = run_plugin(PLUGIN, TAG, image_id, ws, tmp_path / "w")
    assert result.outcome is RunOutcome.FAILED and files == {}


def test_plugin_fails_when_the_workspace_cannot_be_read(image_id: str, tmp_path: Path) -> None:
    result, files = run_plugin(PLUGIN, TAG, image_id, tmp_path / "missing", tmp_path)
    assert result.outcome is RunOutcome.FAILED and files == {}


@needs_syft
def test_build_image_gate_checks_licenses_and_writes_the_image_sbom(tmp_path: Path) -> None:
    document = gate(PLUGIN, "localhost/ca-plugin-gitleaks:gate", tmp_path)
    assert document["specVersion"] == "1.7" and document["components"]


@needs_cosign
def test_signed_digest_is_verified_pulled_and_run(
    image_id: str, tmp_path_factory: pytest.TempPathFactory
) -> None:
    keys_dir, work = tmp_path_factory.mktemp("keys"), tmp_path_factory.mktemp("w")  # fuori dal repo
    history = secrets_history.build_history(tmp_path_factory.mktemp("h") / "ws")
    with signed_image(PLUGIN, "5064", "ca-p07-test", keys_dir) as signed:
        raw = run_signed(PLUGIN, signed, history.path, work)
    assert {k[0] for k in keys(raw)} == {"github-pat", "gitlab-pat"}
