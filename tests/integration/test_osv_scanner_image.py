"""Plugin osv-scanner (P-02, P-03) sull'immagine reale, con `OciExecutor` e il profilo completo.

Opzionale: `CA_TEST_DOCKER=1`. Costruisce `localhost/ca-plugin-osv-scanner:itest` (la build scarica
il binario e ne controlla l'SHA-256: la rete serve solo alla build) e la rimuove a fine sessione.
Le prove di scansione non usano la rete: il database e' uno snapshot gia' scaricato, passato con
`CA_TEST_OSV_FEEDS=/cartella` (contiene `osv-scalibr/npm/all.zip` e `osv-scalibr/PyPI/all.zip`) e
montato in sola lettura dal runner, con `network: none`. Altre prove:
- `SYFT=/percorso/syft` (1.57.0): `deploy/docker/build-image.sh` (licenze e SBOM dell'immagine);
- `COSIGN=/percorso/cosign` (v3.1.4): firma con `sign-local.sh` su un registry locale 127.0.0.1,
  verifica reale con `CosignVerifier` ed esecuzione del digest verificato; la chiave e' generata in
  una cartella temporanea fuori dal repository e cancellata, la firma non va sul log pubblico;
- `CA_TEST_NETWORK=1`: `sync_feeds` reale per PyPI (circa 36 MB da osv-vulnerabilities.storage).
"""

import importlib.util
import json
import os
import re
import shutil
import subprocess
import sys
import zipfile
from collections.abc import Iterator
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest
import yaml

from ca_core.models import PackagedPluginManifest
from ca_core.ports import (
    FeedsSyncRequest,
    PluginRunRequest,
    PluginRunResult,
    RunOutcome,
    ScanAborted,
    Signature,
)
from ca_plugins.runner import OciExecutor, OutputReader
from ca_plugins.signature import CosignVerifier

ROOT = Path(__file__).resolve().parents[2]
PLUGIN = ROOT / "packages/ca-plugins/src/ca_plugins/builtin/osv_scanner"
REPOS = ROOT / "tests/fixtures/repos"
TAG = "localhost/ca-plugin-osv-scanner:itest"
COSIGN = os.environ.get("COSIGN", "")
SYFT_BIN = os.environ.get("SYFT", "")
FEEDS = os.environ.get("CA_TEST_OSV_FEEDS", "")
PORT = os.environ.get("CA_TEST_REGISTRY_PORT", "5061")
PROJECT = "ca-p03-test"
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
needs_feeds = pytest.mark.skipif(
    not FEEDS or not (Path(FEEDS) / "osv-scalibr/npm/all.zip").is_file(),
    reason="richiede uno snapshot gia' scaricato: CA_TEST_OSV_FEEDS=/cartella",
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
        timeout=900,
        env={**os.environ, **(env or {})},
    ).stdout.strip()


def leftovers() -> list[str]:
    return run("docker", "ps", "-aq", "--filter", "label=code-analyzer.executor=1").split()


def manifest(image: str) -> PackagedPluginManifest:
    data: dict[str, Any] = yaml.safe_load((PLUGIN / "plugin.yaml").read_text())
    data["image"] = image
    return PackagedPluginManifest.model_validate(data)


def recorded(repo: str) -> dict[str, Any]:
    result: dict[str, Any] = json.loads(
        (PLUGIN / "fixtures/output" / f"osv-scanner.{repo}.sarif").read_text()
    )
    return result


def keys(document: dict[str, Any]) -> set[tuple[str, str, str]]:
    return {
        (
            r["ruleId"],
            r["properties"]["purl"],
            r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],
        )
        for r in document["runs"][0]["results"]
    }


@pytest.fixture(scope="module")
def image_id() -> Iterator[str]:
    run("docker", "build", "-q", "-t", TAG, str(PLUGIN))
    yield run("docker", "image", "inspect", "--format", "{{.Id}}", TAG)
    subprocess.run(["docker", "rmi", "-f", TAG], capture_output=True, check=False)


def execute(
    image: str, workspace: Path, work: Path, feeds: str | None
) -> tuple[PluginRunResult, dict[str, Any] | None]:
    request = PluginRunRequest(
        manifest=manifest(image), workspace=str(workspace), feeds_snapshot=feeds
    )
    with OciExecutor(work_dir=str(work), image_ref=lambda _: image.split("@")[1]) as executor:
        result = executor.run(request)
        if result.outcome is not RunOutcome.OK:
            return result, None
        assert result.output_dir is not None
        reader = OutputReader()
        assert reader.list_files(result.output_dir) == ["results.sarif"]
        raw = reader.read_file(
            result.output_dir, "results.sarif", request.manifest.outputs.max_bytes
        )
        executor.release(result.output_dir)
    assert b"/workspace" not in raw
    return result, json.loads(raw)


@needs_feeds
@pytest.mark.parametrize("repo", ["js-ts-app", "python-app"])
def test_full_profile_with_readonly_feeds_reports_the_fixture_cves(
    image_id: str, tmp_path: Path, repo: str
) -> None:
    result, document = execute(f"{TAG}@{image_id}", REPOS / repo, tmp_path, FEEDS)
    assert result.outcome is RunOutcome.OK, result.detail  # network: none, /feeds in sola lettura
    assert leftovers() == []
    assert document is not None
    assert HARNESS.sarif_problems(document, "osv-scanner") == {}
    expected = yaml.safe_load((REPOS / repo / "expected-findings.yaml").read_text())["expected"]
    wanted = {e["cve"] for e in expected if e["category"] == "dependency"}
    assert {r["ruleId"] for r in document["runs"][0]["results"]} >= wanted
    assert keys(document) == keys(recorded(repo))


@needs_feeds
def test_feeds_mount_is_readonly_and_osv_scanner_never_needs_to_write_there(image_id: str) -> None:
    probe = subprocess.run(
        ["docker", "run", "--rm", "--network", "none", "--user", "65534:65534",
         "--mount", f"type=bind,src={FEEDS},dst=/feeds,readonly",
         "--entrypoint", "python", image_id, "-c",
         "open('/feeds/probe', 'w')"],
        capture_output=True, text=True, check=False,
    )  # fmt: skip
    assert probe.returncode != 0 and "Read-only file system" in probe.stderr
    assert not (Path(FEEDS) / "probe").exists()


@needs_feeds
def test_missing_ecosystem_database_fails_the_plugin(image_id: str, tmp_path: Path) -> None:
    snapshot = tmp_path / "snap"
    (snapshot / "osv-scalibr/npm").mkdir(parents=True)
    with zipfile.ZipFile(snapshot / "osv-scalibr/npm/all.zip", "w") as archive:
        archive.writestr("x.json", "{}")  # solo npm; python-app ha bisogno di PyPI
    result, document = execute(f"{TAG}@{image_id}", REPOS / "python-app", tmp_path, str(snapshot))
    assert (result.outcome, result.exit_code, document) == (RunOutcome.FAILED, 3, None)
    assert leftovers() == []


def test_empty_snapshot_fails_and_no_packages_is_an_empty_outcome(
    image_id: str, tmp_path: Path
) -> None:
    (tmp_path / "ws").mkdir()
    (tmp_path / "empty").mkdir()
    result, document = execute(
        f"{TAG}@{image_id}", tmp_path / "ws", tmp_path, str(tmp_path / "empty")
    )
    assert result.outcome is RunOutcome.OK and document is not None  # exit 128: nessun pacchetto
    assert document["runs"][0]["results"] == []
    result, document = execute(
        f"{TAG}@{image_id}", REPOS / "js-ts-app", tmp_path, str(tmp_path / "empty")
    )
    assert (result.outcome, document) == (RunOutcome.FAILED, None)  # `could not load db`


@pytest.mark.skipif(
    os.environ.get("CA_TEST_NETWORK") != "1", reason="scarica da internet: CA_TEST_NETWORK=1"
)
def test_sync_downloads_the_closed_list_with_network_and_no_workspace(
    image_id: str, tmp_path: Path
) -> None:
    data = manifest(f"{TAG}@{image_id}").model_dump(mode="json")
    data["feeds"]["sync_command"] = [
        *data["feeds"]["sync_command"][:3],
        "PyPI",
    ]  # solo PyPI (36 MB)
    data["feeds"]["ecosystems"] = ["PyPI"]
    snapshot = tmp_path / "snap"
    snapshot.mkdir()
    snapshot.chmod(0o777)
    request = FeedsSyncRequest(
        manifest=PackagedPluginManifest.model_validate(data),
        snapshot_dir=str(snapshot),
        max_bytes=1024**3,
    )
    with OciExecutor(work_dir=str(tmp_path), image_ref=lambda _: image_id) as executor:
        result = executor.sync_feeds(request)
    assert result.outcome is RunOutcome.OK, result.detail
    assert zipfile.is_zipfile(snapshot / "osv-scalibr/PyPI/all.zip")
    assert [p.name for p in snapshot.rglob("*") if p.is_file()] == ["all.zip"]
    assert leftovers() == []


@needs_syft
def test_build_image_gate_checks_licenses_and_writes_the_image_sbom(tmp_path: Path) -> None:
    sbom = run(
        str(ROOT / "deploy/docker/build-image.sh"),
        str(PLUGIN),
        "localhost/ca-plugin-osv-scanner:gate",
        str(tmp_path),
        env={"SYFT": SYFT_BIN},
    ).splitlines()[-1]
    try:
        document = json.loads(Path(sbom).read_text())
        assert document["specVersion"] == "1.7"
        assert any("osv-scanner" in str(c.get("name")) for c in document["components"])
    finally:
        subprocess.run(
            ["docker", "rmi", "-f", "localhost/ca-plugin-osv-scanner:gate"], capture_output=True
        )


@pytest.fixture(scope="module")
def signed(tmp_path_factory: pytest.TempPathFactory) -> Iterator[dict[str, Any]]:
    keydir = tmp_path_factory.mktemp("keys")  # fuori dal repository
    env = {"CA_REGISTRY_PORT": PORT, "COSIGN": COSIGN, "CA_KEY_DIR": str(keydir)}
    up = ["docker", "compose", "-p", PROJECT, "-f", str(COMPOSE)]
    name = "ca-plugins/osv-scanner"
    try:
        run(*up, "up", "-d", "--wait", env=env)
        ref = run(str(ROOT / "deploy/docker/sign-local.sh"), str(PLUGIN), name, "1.0.0", env=env)
        ref = ref.splitlines()[-1]
        other = tmp_path_factory.mktemp("otherkeys")
        subprocess.run(
            [COSIGN, "generate-key-pair"],
            cwd=other,
            env={**os.environ, "COSIGN_PASSWORD": ""},
            check=True,
            capture_output=True,
        )
        yield {
            "image": f"127.0.0.1:{PORT}/{name}:1.0.0@{ref.split('@')[1]}",
            "ref": ref,
            "pub": keydir / "cosign.pub",
            "other_pub": other / "cosign.pub",
        }
    finally:
        subprocess.run([*up, "down", "--volumes"], env={**os.environ, **env}, check=False)
        subprocess.run(
            ["docker", "rmi", "-f", f"127.0.0.1:{PORT}/{name}:1.0.0"],
            capture_output=True,
            check=False,
        )
        shutil.rmtree(keydir, ignore_errors=True)


def verifier(pub: Path) -> CosignVerifier:
    return CosignVerifier(public_key=str(pub), cosign=COSIGN, allow_http_registry=True, timeout=60)


@needs_cosign
@needs_feeds
def test_signed_digest_is_verified_pulled_and_run(signed: dict[str, Any], tmp_path: Path) -> None:
    subprocess.run(["docker", "rmi", "-f", signed["ref"]], capture_output=True, check=False)
    request = PluginRunRequest(
        manifest=manifest(signed["image"]), workspace=str(REPOS / "js-ts-app"), feeds_snapshot=FEEDS
    )
    with OciExecutor(work_dir=str(tmp_path), verifier=verifier(signed["pub"])) as executor:
        result = executor.run(request)
        assert result.outcome is RunOutcome.OK, result.detail
        assert result.signature is Signature.VERIFIED
        assert result.output_dir is not None
        raw = OutputReader().read_file(result.output_dir, "results.sarif", 4_194_304)
    document = json.loads(raw)
    assert HARNESS.sarif_problems(document, "osv-scanner") == {}
    assert keys(document) == keys(recorded("js-ts-app"))
    assert leftovers() == []


@needs_cosign
def test_wrong_key_starts_no_container(signed: dict[str, Any], tmp_path: Path) -> None:
    with OciExecutor(work_dir=str(tmp_path), verifier=verifier(signed["other_pub"])) as executor:
        with pytest.raises(ScanAborted):
            executor.run(
                PluginRunRequest(
                    manifest=manifest(signed["image"]), workspace=str(REPOS / "js-ts-app")
                )
            )
    assert leftovers() == []
    assert re.fullmatch(
        r"127\.0\.0\.1:\d+/ca-plugins/osv-scanner@sha256:[0-9a-f]{64}", signed["ref"]
    )
