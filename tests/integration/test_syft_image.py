"""Plugin syft (P-01) sull'immagine reale, con `OciExecutor` e il profilo completo. Opzionale.

Si attiva con `CA_TEST_DOCKER=1`. Costruisce `localhost/ca-plugin-syft:itest` (la build scarica il
tarball di syft e ne controlla l'SHA-256: serve la rete solo per la build, mai per l'esecuzione) e
la rimuove a fine sessione. Due prove in più:
- `SYFT=/percorso/syft` (1.57.0): `deploy/docker/build-image.sh` (licenze e SBOM dell'immagine);
- `COSIGN=/percorso/cosign` (v3.1.4): firma con `sign-local.sh` su un registry locale 127.0.0.1,
  verifica reale con `CosignVerifier` ed esecuzione del digest verificato. La chiave è generata in
  una cartella temporanea fuori dal repository (password vuota, non protegge nulla) e cancellata;
  la firma non passa mai dal log di trasparenza pubblico.
"""

import importlib.util
import json
import os
import re
import shutil
import subprocess
import sys
from collections.abc import Iterator
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest
import yaml

from ca_core.models import PackagedPluginManifest
from ca_core.ports import PluginRunRequest, RunOutcome, ScanAborted, Signature
from ca_plugins.runner import OciExecutor, OutputReader
from ca_plugins.signature import CosignVerifier

ROOT = Path(__file__).resolve().parents[2]
PLUGIN = ROOT / "packages/ca-plugins/src/ca_plugins/builtin/syft"
REPOS = ROOT / "tests/fixtures/repos"
TAG = "localhost/ca-plugin-syft:itest"
COSIGN = os.environ.get("COSIGN", "")
SYFT_BIN = os.environ.get("SYFT", "")
PORT = os.environ.get("CA_TEST_REGISTRY_PORT", "5058")
PROJECT = "ca-p01-test"
COMPOSE = ROOT / "deploy/compose/registry.yaml"

pytestmark = pytest.mark.skipif(
    os.environ.get("CA_TEST_DOCKER") != "1" or shutil.which("docker") is None,
    reason="richiede un daemon Docker: CA_TEST_DOCKER=1",
)
needs_cosign = pytest.mark.skipif(
    not COSIGN or not os.access(COSIGN, os.X_OK),
    reason="richiede cosign v3.1.4 verificato: COSIGN=/percorso/cosign",
)
needs_syft = pytest.mark.skipif(
    not SYFT_BIN or not os.access(SYFT_BIN, os.X_OK),
    reason="richiede syft 1.57.0: SYFT=/percorso/syft",
)


def load_harness() -> ModuleType:
    path = ROOT / "tests/contract/plugins/plugin_output_harness.py"
    spec = importlib.util.spec_from_file_location("plugin_output_harness", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules.setdefault("plugin_output_harness", module)
    spec.loader.exec_module(module)
    return module


HARNESS = load_harness()


def run(*args: str, env: dict[str, str] | None = None) -> str:
    return subprocess.run(
        args,
        capture_output=True,
        text=True,
        check=True,
        timeout=600,
        env={**os.environ, **(env or {})},
    ).stdout.strip()


def leftovers() -> list[str]:
    return run("docker", "ps", "-aq", "--filter", "label=code-analyzer.executor=1").split()


def manifest(image: str) -> PackagedPluginManifest:
    data: dict[str, Any] = yaml.safe_load((PLUGIN / "plugin.yaml").read_text())
    data["image"] = image
    return PackagedPluginManifest.model_validate(data)


def purls(document: dict[str, Any]) -> set[str]:
    return {c["purl"] for c in document["components"] if "purl" in c}


def recorded(repo: str) -> dict[str, Any]:
    result: dict[str, Any] = json.loads(
        (PLUGIN / "fixtures/output" / f"syft.{repo}.cdx.json").read_text()
    )
    return result


@pytest.fixture(scope="module")
def image_id() -> Iterator[str]:
    run("docker", "build", "-q", "-t", TAG, str(PLUGIN))
    yield run("docker", "image", "inspect", "--format", "{{.Id}}", TAG)
    subprocess.run(["docker", "rmi", "-f", TAG], capture_output=True, check=False)


def checked_run(executor: OciExecutor, image: str, workspace: Path) -> tuple[dict[str, Any], str]:
    request = PluginRunRequest(manifest=manifest(image), workspace=str(workspace), config=None)
    result = executor.run(request)
    assert result.outcome is RunOutcome.OK, result.detail
    assert result.output_dir is not None
    reader = OutputReader()
    assert reader.list_files(result.output_dir) == ["sbom.cdx.json"]
    raw = reader.read_file(result.output_dir, "sbom.cdx.json", request.manifest.outputs.max_bytes)
    executor.release(result.output_dir)
    return json.loads(raw), raw.decode()


@pytest.mark.parametrize("repo", ["js-ts-app", "python-app"])
def test_full_profile_produces_valid_cyclonedx_1_7(
    image_id: str, tmp_path: Path, repo: str
) -> None:
    with OciExecutor(work_dir=str(tmp_path), image_ref=lambda _: image_id) as executor:
        document, text = checked_run(
            executor, f"localhost/ca-plugin-syft:itest@{image_id}", REPOS / repo
        )
    assert leftovers() == []
    assert document["specVersion"] == "1.7"
    assert HARNESS.cyclonedx_problems(document) == []
    assert "/workspace" not in text
    assert document["metadata"]["component"]["name"] == "."
    assert purls(document) == purls(recorded(repo)) != set()


def test_plugin_fails_when_syft_cannot_read_the_workspace(image_id: str, tmp_path: Path) -> None:
    request = PluginRunRequest(
        manifest=manifest(f"localhost/ca-plugin-syft:itest@{image_id}"),
        workspace=str(tmp_path / "missing"),
        config=None,
    )
    with OciExecutor(work_dir=str(tmp_path), image_ref=lambda _: image_id) as executor:
        assert executor.run(request).outcome is RunOutcome.FAILED
    assert leftovers() == []


def test_empty_workspace_is_a_valid_sbom(image_id: str, tmp_path: Path) -> None:
    (tmp_path / "ws").mkdir()
    with OciExecutor(work_dir=str(tmp_path), image_ref=lambda _: image_id) as executor:
        document, _ = checked_run(
            executor, f"localhost/ca-plugin-syft:itest@{image_id}", tmp_path / "ws"
        )
    assert HARNESS.cyclonedx_problems(document) == []
    assert not document.get("components")


@needs_syft
def test_build_image_gate_checks_licenses_and_writes_the_image_sbom(tmp_path: Path) -> None:
    sbom = run(
        str(ROOT / "deploy/docker/build-image.sh"),
        str(PLUGIN),
        "localhost/ca-plugin-syft:gate",
        str(tmp_path),
        env={"SYFT": SYFT_BIN},
    ).splitlines()[-1]
    try:
        document = json.loads(Path(sbom).read_text())
        assert document["specVersion"] == "1.7"
        assert any(c.get("name") == "github.com/anchore/syft" for c in document["components"])
    finally:
        subprocess.run(
            ["docker", "rmi", "-f", "localhost/ca-plugin-syft:gate"], capture_output=True
        )


@pytest.fixture(scope="module")
def signed(tmp_path_factory: pytest.TempPathFactory) -> Iterator[dict[str, Any]]:
    keys = tmp_path_factory.mktemp("keys")  # fuori dal repository
    env = {"CA_REGISTRY_PORT": PORT, "COSIGN": COSIGN, "CA_KEY_DIR": str(keys)}
    up = ["docker", "compose", "-p", PROJECT, "-f", str(COMPOSE)]
    name = "ca-plugins/syft"
    try:
        run(*up, "up", "-d", "--wait", env=env)
        ref = run(str(ROOT / "deploy/docker/sign-local.sh"), str(PLUGIN), name, "1.0.0", env=env)
        ref = ref.splitlines()[-1]
        digest = ref.split("@")[1]
        other = tmp_path_factory.mktemp("otherkeys")
        subprocess.run(
            [COSIGN, "generate-key-pair"],
            cwd=other,
            env={**os.environ, "COSIGN_PASSWORD": ""},
            check=True,
            capture_output=True,
        )
        yield {
            "image": f"127.0.0.1:{PORT}/{name}:1.0.0@{digest}",
            "ref": ref,
            "pub": keys / "cosign.pub",
            "other_pub": other / "cosign.pub",
        }
    finally:
        subprocess.run([*up, "down", "--volumes"], env={**os.environ, **env}, check=False)
        subprocess.run(
            ["docker", "rmi", "-f", f"127.0.0.1:{PORT}/{name}:1.0.0"],
            capture_output=True,
            check=False,
        )
        shutil.rmtree(keys, ignore_errors=True)


def verifier(pub: Path) -> CosignVerifier:
    return CosignVerifier(public_key=str(pub), cosign=COSIGN, allow_http_registry=True, timeout=60)


@needs_cosign
def test_signed_digest_is_verified_pulled_and_run(signed: dict[str, Any], tmp_path: Path) -> None:
    subprocess.run(["docker", "rmi", "-f", signed["ref"]], capture_output=True, check=False)
    tmp_path.joinpath("w").mkdir()
    with OciExecutor(work_dir=str(tmp_path / "w"), verifier=verifier(signed["pub"])) as executor:
        request = PluginRunRequest(
            manifest=manifest(signed["image"]), workspace=str(REPOS / "js-ts-app"), config=None
        )
        result = executor.run(request)
        assert result.outcome is RunOutcome.OK, result.detail
        assert result.signature is Signature.VERIFIED
        assert result.output_dir is not None
        raw = OutputReader().read_file(result.output_dir, "sbom.cdx.json", 16_777_216)
    document = json.loads(raw)
    assert HARNESS.cyclonedx_problems(document) == []
    assert b"/workspace" not in raw
    assert purls(document) == purls(recorded("js-ts-app"))
    assert leftovers() == []


@needs_cosign
def test_wrong_key_starts_no_container(signed: dict[str, Any], tmp_path: Path) -> None:
    with OciExecutor(work_dir=str(tmp_path), verifier=verifier(signed["other_pub"])) as executor:
        with pytest.raises(ScanAborted):
            executor.run(
                PluginRunRequest(
                    manifest=manifest(signed["image"]),
                    workspace=str(REPOS / "js-ts-app"),
                    config=None,
                )
            )
    assert leftovers() == []
    assert re.fullmatch(r"127\.0\.0\.1:\d+/ca-plugins/syft@sha256:[0-9a-f]{64}", signed["ref"])
