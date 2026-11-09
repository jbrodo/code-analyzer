"""Plugin scancode (P-06) sull'immagine reale, con `OciExecutor` e il profilo completo. Opzionale.

`CA_TEST_DOCKER=1`; vedi `plugin_image_support.py` per `COSIGN` e `SYFT`. Costruisce
`localhost/ca-plugin-scancode:itest` (la build scarica le wheel e pip ne controlla gli hash).
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
    run,
    run_ok,
    run_plugin,
    run_signed,
    signed_image,
)

from ca_core.ports import RunOutcome

PLUGIN = "scancode"
TAG = "localhost/ca-plugin-scancode:itest"
pytestmark = needs_docker


@pytest.fixture(scope="module")
def image_id() -> Iterator[str]:
    yield from build_image(PLUGIN, TAG)


def found(raw: bytes) -> set[tuple[str, str]]:
    document = json.loads(raw)
    assert HARNESS.sarif_problems(document, PLUGIN) == {}
    return {
        (
            r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],
            r["properties"]["license_spdx"],
        )
        for r in document["runs"][0]["results"]
    }


def recorded(repo: str) -> set[tuple[str, str]]:
    return found((BUILTIN / PLUGIN / f"fixtures/output/scancode.{repo}.sarif").read_bytes())


@pytest.mark.parametrize("repo", ["python-app", "js-ts-app"])
def test_full_profile_output_is_conforming_and_has_the_expected_licenses(
    image_id: str, tmp_path: Path, repo: str
) -> None:
    files = run_ok(PLUGIN, TAG, image_id, REPOS / repo, tmp_path)
    assert list(files) == ["results.sarif"]
    raw = files["results.sarif"]
    assert b"/workspace" not in raw and b"workspace/" not in raw
    assert found(raw) == recorded(repo)
    expected = yaml.safe_load((REPOS / repo / "expected-findings.yaml").read_text())["expected"]
    paths = {p for p, _ in found(raw)}
    for item in expected:
        if item["category"] == "license" and "scancode" in item["tools"]:
            assert item["path"] in paths


def test_one_result_per_file_and_no_text_of_the_file(image_id: str, tmp_path: Path) -> None:
    ws = tmp_path / "ws"
    ws.mkdir()
    (ws / "a.py").write_text("# SPDX-License-Identifier: MIT\n# sentinel-text-4f9a\n")
    (ws / "b.py").write_text(
        "# SPDX-License-Identifier: GPL-3.0-only\n# SPDX-License-Identifier: MIT\n"
    )
    (ws / "tests").mkdir()
    (ws / "tests/c.py").write_text("# SPDX-License-Identifier: Apache-2.0\n")
    raw = run_ok(PLUGIN, TAG, image_id, ws, tmp_path / "w")["results.sarif"]
    assert [p for p, _ in sorted(found(raw))] == ["a.py", "b.py", "tests/c.py"]  # uno per file
    assert b"sentinel-text" not in raw and b"snippet" not in raw


def test_git_directory_is_not_scanned(image_id: str, tmp_path: Path) -> None:
    ws = tmp_path / "ws"
    (ws / ".git/objects").mkdir(parents=True)
    (ws / ".git/objects/x").write_text("SPDX-License-Identifier: GPL-2.0-only\n")
    (ws / "ok.txt").write_text("nothing\n")
    assert found(run_ok(PLUGIN, TAG, image_id, ws, tmp_path / "w")["results.sarif"]) == set()


def test_pluggy_in_the_image_is_below_1_7_and_scancode_starts(image_id: str) -> None:
    code = "import importlib.metadata as m; print(m.version('pluggy'))"
    version = run(
        "docker", "run", "--rm", "--entrypoint", "/opt/venv/bin/python", image_id, "-c", code
    )
    assert tuple(int(p) for p in version.split(".")[:2]) < (1, 7)
    scan = run(
        "docker", "run", "--rm", "--entrypoint", "/opt/venv/bin/scancode", image_id, "--version"
    )
    assert "32.5.0" in scan


def test_image_carries_notice_and_about_files(image_id: str) -> None:
    listing = run(
        "docker", "run", "--rm", "--entrypoint", "find", image_id, "/licenses/scancode",
        "-type", "f",
    )  # fmt: skip
    names = listing.split()
    assert "/licenses/scancode/NOTICE" in names
    assert sum(n.endswith(".ABOUT") for n in names) >= 10


def test_empty_workspace_is_a_valid_empty_sarif(image_id: str, tmp_path: Path) -> None:
    (tmp_path / "ws").mkdir()
    assert (
        found(run_ok(PLUGIN, TAG, image_id, tmp_path / "ws", tmp_path / "w")["results.sarif"])
        == set()
    )


def test_plugin_fails_when_the_workspace_cannot_be_read(image_id: str, tmp_path: Path) -> None:
    result, files = run_plugin(PLUGIN, TAG, image_id, tmp_path / "missing", tmp_path)
    assert result.outcome is RunOutcome.FAILED and files == {}


@needs_syft
def test_build_image_gate_checks_licenses_and_writes_the_image_sbom(tmp_path: Path) -> None:
    document = gate(PLUGIN, "localhost/ca-plugin-scancode:gate", tmp_path)
    names = {c.get("name") for c in document["components"]}
    assert document["specVersion"] == "1.7" and "scancode-toolkit" in names


@needs_cosign
def test_signed_digest_is_verified_pulled_and_run(
    image_id: str, tmp_path_factory: pytest.TempPathFactory
) -> None:
    keys, work = tmp_path_factory.mktemp("keys"), tmp_path_factory.mktemp("w")  # fuori dal repo
    with signed_image(PLUGIN, "5063", "ca-p06-test", keys) as signed:
        raw = run_signed(PLUGIN, signed, REPOS / "js-ts-app", work)
    assert found(raw) == recorded("js-ts-app")
