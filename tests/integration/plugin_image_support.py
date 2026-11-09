"""Supporto comune alle prove sulle immagini reali dei plugin (P-06..P-10). Non e' un test.

Come `test_syft_image.py`: `CA_TEST_DOCKER=1` per Docker, `COSIGN=/percorso/cosign` (v3.1.4) per la
firma, `SYFT=/percorso/syft` (1.57.0) per `build-image.sh`. La firma passa solo da `sign-local.sh`
su un registry su 127.0.0.1, con una chiave generata in una cartella temporanea fuori dal
repository, password vuota, cancellata a fine prova: non protegge nulla e non tocca il log di
trasparenza.
"""

import importlib.util
import json
import os
import shutil
import subprocess
import sys
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest
import yaml

from ca_core.models import PackagedPluginManifest
from ca_core.ports import PluginRunRequest, PluginRunResult, RunOutcome
from ca_plugins.runner import OciExecutor, OutputReader
from ca_plugins.signature import CosignVerifier

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tests/fixtures/builders"))  # storie git finte (F-04)
BUILTIN = ROOT / "packages/ca-plugins/src/ca_plugins/builtin"
REPOS = ROOT / "tests/fixtures/repos"
COSIGN = os.environ.get("COSIGN", "")
SYFT_BIN = os.environ.get("SYFT", "")
COMPOSE = ROOT / "deploy/compose/registry.yaml"

needs_docker = pytest.mark.skipif(
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


import secrets_history as secrets_history  # noqa: E402

HARNESS = load_harness()


def run(*args: str, env: dict[str, str] | None = None, cwd: Path | None = None) -> str:
    return subprocess.run(
        args,
        capture_output=True,
        text=True,
        check=True,
        timeout=900,
        env={**os.environ, **(env or {})},
        cwd=cwd,
    ).stdout.strip()


def leftovers() -> list[str]:
    return run("docker", "ps", "-aq", "--filter", "label=code-analyzer.executor=1").split()


def manifest(plugin: str, image: str, **resources: Any) -> PackagedPluginManifest:
    data: dict[str, Any] = yaml.safe_load((BUILTIN / plugin / "plugin.yaml").read_text())
    data["image"] = image
    data["resources"] = {**data["resources"], **resources}
    return PackagedPluginManifest.model_validate(data)


def build_image(plugin: str, tag: str) -> Iterator[str]:
    """Generatore per una fixture di modulo: costruisce, restituisce l'ID e rimuove l'immagine."""
    run("docker", "build", "-q", "-t", tag, str(BUILTIN / plugin))
    yield run("docker", "image", "inspect", "--format", "{{.Id}}", tag)
    subprocess.run(["docker", "rmi", "-f", tag], capture_output=True, check=False)


def run_plugin(
    plugin: str,
    tag: str,
    image_id: str,
    workspace: Path | str,
    work_dir: Path,
    *,
    config: str | None = None,
    **resources: Any,
) -> tuple[PluginRunResult, dict[str, bytes]]:
    """Esegue con `OciExecutor` (profilo completo), legge `/out` con `OutputReader`, rilascia."""
    request = PluginRunRequest(
        manifest=manifest(plugin, f"{tag}@{image_id}", **resources),
        workspace=str(workspace),
        config=config,
    )
    files: dict[str, bytes] = {}
    work_dir.mkdir(parents=True, exist_ok=True)
    with OciExecutor(work_dir=str(work_dir), image_ref=lambda _: image_id) as executor:
        result = executor.run(request)
        if result.output_dir is not None:
            reader = OutputReader()
            for name in reader.list_files(result.output_dir):
                files[name] = reader.read_file(
                    result.output_dir, name, request.manifest.outputs.max_bytes
                )
            executor.release(result.output_dir)
    assert leftovers() == []
    return result, files


def run_ok(*args: Any, **kwargs: Any) -> dict[str, bytes]:
    result, files = run_plugin(*args, **kwargs)
    assert result.outcome is RunOutcome.OK, result.detail
    return files


def verifier(pub: Path) -> CosignVerifier:
    return CosignVerifier(public_key=str(pub), cosign=COSIGN, allow_http_registry=True, timeout=60)


@contextmanager
def signed_image(plugin: str, port: str, project: str, keys: Path) -> Iterator[dict[str, Any]]:
    """Firma `plugin` con `sign-local.sh` su un registry locale; restituisce immagine e chiave."""
    env = {"CA_REGISTRY_PORT": port, "COSIGN": COSIGN, "CA_KEY_DIR": str(keys)}
    up = ["docker", "compose", "-p", project, "-f", str(COMPOSE)]
    name = f"ca-plugins/{plugin}"
    try:
        run(*up, "up", "-d", "--wait", env=env)
        ref = run(
            str(ROOT / "deploy/docker/sign-local.sh"), str(BUILTIN / plugin), name, "1.0.0", env=env
        ).splitlines()[-1]
        yield {
            "image": f"127.0.0.1:{port}/{name}:1.0.0@{ref.split('@')[1]}",
            "ref": ref,
            "pub": keys / "cosign.pub",
        }
    finally:
        subprocess.run([*up, "down", "--volumes"], env={**os.environ, **env}, check=False)
        subprocess.run(
            ["docker", "rmi", "-f", f"127.0.0.1:{port}/{name}:1.0.0"],
            capture_output=True,
            check=False,
        )
        shutil.rmtree(keys, ignore_errors=True)


def run_signed(plugin: str, signed: dict[str, Any], workspace: Path, work_dir: Path) -> bytes:
    """Verifica la firma con `CosignVerifier`, scarica il digest ed esegue: ritorna `/out`."""
    subprocess.run(["docker", "rmi", "-f", signed["ref"]], capture_output=True, check=False)
    request = PluginRunRequest(
        manifest=manifest(plugin, signed["image"]), workspace=str(workspace), config=None
    )
    with OciExecutor(work_dir=str(work_dir), verifier=verifier(signed["pub"])) as executor:
        result = executor.run(request)
        assert result.outcome is RunOutcome.OK, result.detail
        assert result.signature is not None and result.signature.value == "verified"
        assert result.output_dir is not None
        reader = OutputReader()
        (name,) = reader.list_files(result.output_dir)
        raw = reader.read_file(result.output_dir, name, request.manifest.outputs.max_bytes)
        executor.release(result.output_dir)
    assert leftovers() == []
    return raw


def gate(plugin: str, tag: str, sbom_dir: Path) -> dict[str, Any]:
    """`build-image.sh` (licenze + SBOM dell'immagine, con SYFT): ritorna l'SBOM letto."""
    sbom = run(
        str(ROOT / "deploy/docker/build-image.sh"),
        str(BUILTIN / plugin),
        tag,
        str(sbom_dir),
        env={"SYFT": SYFT_BIN},
    ).splitlines()[-1]
    try:
        result: dict[str, Any] = json.loads(Path(sbom).read_text())
        return result
    finally:
        subprocess.run(["docker", "rmi", "-f", tag], capture_output=True, check=False)
