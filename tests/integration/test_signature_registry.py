"""R-04 contro un registry locale reale e `cosign` v3.1.4 (V-06). Opzionale.

Si attiva con `CA_TEST_DOCKER=1` e `COSIGN=/percorso/cosign` (versione e hash fissati da
`deploy/docker/sign-local.sh`, che firma). Avvia `deploy/compose/registry.yaml` su 127.0.0.1 con
un nome di progetto proprio, firma con una chiave generata in una cartella temporanea (fuori dal
repository, password vuota, non protegge nulla) e rimuove registry, immagini e chiavi a fine
sessione. Nessun log di trasparenza pubblico: la firma passa solo da `sign-local.sh`.
"""

import json
import os
import re
import shutil
import subprocess
from collections.abc import Iterator
from pathlib import Path

import pytest

from ca_core.models import PackagedPluginManifest
from ca_core.ports import PluginRunRequest, RunOutcome, ScanAborted, Signature
from ca_plugins.runner import OciExecutor
from ca_plugins.signature import CosignVerifier

ROOT = Path(__file__).resolve().parents[2]
FAKE = ROOT / "tests" / "fixtures" / "plugins" / "fake"
COMPOSE = ROOT / "deploy" / "compose" / "registry.yaml"
SIGN = ROOT / "deploy" / "docker" / "sign-local.sh"
PORT = os.environ.get("CA_TEST_REGISTRY_PORT", "5057")
DEAD_PORT = "5999"
PROJECT = "ca-r04-test"
COSIGN = os.environ.get("COSIGN", "")

pytestmark = [
    pytest.mark.skipif(
        os.environ.get("CA_TEST_DOCKER") != "1" or shutil.which("docker") is None,
        reason="richiede un daemon Docker: CA_TEST_DOCKER=1",
    ),
    pytest.mark.skipif(
        not COSIGN or not os.access(COSIGN, os.X_OK),
        reason="richiede cosign v3.1.4 verificato: COSIGN=/percorso/cosign",
    ),
]


def run(*args: str, env: dict[str, str] | None = None) -> str:
    full = {**os.environ, **(env or {})}
    return subprocess.run(
        args, capture_output=True, text=True, check=True, timeout=300, env=full
    ).stdout.strip()


@pytest.fixture(scope="module")
def keys(tmp_path_factory: pytest.TempPathFactory) -> Path:
    return tmp_path_factory.mktemp("keys")  # fuori dal repository


@pytest.fixture(scope="module")
def other_pub(tmp_path_factory: pytest.TempPathFactory) -> Path:
    d = tmp_path_factory.mktemp("otherkeys")
    subprocess.run(
        [COSIGN, "generate-key-pair"],
        cwd=d,
        env={**os.environ, "COSIGN_PASSWORD": ""},
        check=True,
        capture_output=True,
    )
    return d / "cosign.pub"


@pytest.fixture(scope="module")
def refs(keys: Path) -> Iterator[dict[str, str]]:
    env = {"CA_REGISTRY_PORT": PORT, "COSIGN": COSIGN}
    up = ["docker", "compose", "-p", PROJECT, "-f", str(COMPOSE)]
    images: list[str] = []
    try:
        run(*up, "up", "-d", "--wait", env=env)
        signed = run(str(SIGN), str(FAKE), "ca-r04-signed", env={**env, "CA_KEY_DIR": str(keys)})
        signed = signed.splitlines()[-1]
        unsigned_tag = f"127.0.0.1:{PORT}/ca-r04-unsigned:t"
        images += [f"127.0.0.1:{PORT}/ca-r04-signed:local", unsigned_tag]
        run("docker", "build", "-q", "--label", "r04=unsigned", "-t", unsigned_tag, str(FAKE))
        pushed = run("docker", "push", unsigned_tag)
        digest = re.search(r"digest: (sha256:[0-9a-f]{64})", pushed)
        assert digest
        yield {
            "signed": signed,
            "unsigned": f"127.0.0.1:{PORT}/ca-r04-unsigned@{digest.group(1)}",
            "dead": signed.replace(f":{PORT}/", f":{DEAD_PORT}/"),
        }
    finally:
        subprocess.run([*up, "down", "--volumes"], env={**os.environ, **env}, check=False)
        subprocess.run(["docker", "rmi", "-f", *images], capture_output=True, check=False)
        shutil.rmtree(keys, ignore_errors=True)


def manifest(ref: str) -> PackagedPluginManifest:
    data = json.loads((FAKE / "plugin.yaml").read_text())
    name, digest = ref.split("@")
    data["image"] = f"{name}:t@{digest}"
    return PackagedPluginManifest.model_validate(data)


def verifier(pub: Path, **kw: object) -> CosignVerifier:
    return CosignVerifier(
        public_key=str(pub),
        cosign=COSIGN,
        allow_http_registry=True,
        timeout=60,
        **kw,  # type: ignore[arg-type]
    )


def test_valid_signature(refs: dict[str, str], keys: Path) -> None:
    assert verifier(keys / "cosign.pub")(manifest(refs["signed"]), refs["signed"]) is (
        Signature.VERIFIED
    )


def test_wrong_key(refs: dict[str, str], other_pub: Path) -> None:
    with pytest.raises(ScanAborted):
        verifier(other_pub)(manifest(refs["signed"]), refs["signed"])


def test_unsigned_image(refs: dict[str, str], keys: Path) -> None:
    with pytest.raises(ScanAborted):
        verifier(keys / "cosign.pub")(manifest(refs["unsigned"]), refs["unsigned"])


def test_unreachable_registry(refs: dict[str, str], keys: Path) -> None:
    with pytest.raises(ScanAborted):
        verifier(keys / "cosign.pub")(manifest(refs["dead"]), refs["dead"])


def leftovers() -> list[str]:
    return run("docker", "ps", "-aq", "--filter", "label=code-analyzer.executor=1").split()


def test_run_executes_the_verified_digest_after_pull(
    refs: dict[str, str], keys: Path, tmp_path: Path
) -> None:
    ref = refs["signed"]
    subprocess.run(["docker", "rmi", "-f", ref], capture_output=True, check=False)  # forza il pull
    ws = tmp_path / "ws"
    ws.mkdir()
    (ws / "app.py").write_text("print(1)\n")
    cfg = tmp_path / "config.json"
    cfg.write_text(json.dumps({"behavior": "success"}))
    cfg.chmod(0o600)
    with OciExecutor(work_dir=str(tmp_path / "w"), verifier=verifier(keys / "cosign.pub")) as ex:
        (tmp_path / "w").mkdir(exist_ok=True)
        result = ex.run(
            PluginRunRequest(manifest=manifest(ref), workspace=str(ws), config=str(cfg))
        )
    assert result.outcome is RunOutcome.OK, result.detail
    assert result.signature is Signature.VERIFIED
    assert leftovers() == []


def test_failed_verification_starts_no_container(
    refs: dict[str, str], other_pub: Path, tmp_path: Path
) -> None:
    (tmp_path / "ws").mkdir()
    with OciExecutor(work_dir=str(tmp_path), verifier=verifier(other_pub)) as ex:
        with pytest.raises(ScanAborted):
            ex.run(
                PluginRunRequest(
                    manifest=manifest(refs["signed"]), workspace=str(tmp_path / "ws"), config=None
                )
            )
    assert leftovers() == []
