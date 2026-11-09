# ruff: noqa: F401, F811  (le fixture di t03_support si importano e si usano come argomenti)
"""T-03: firma assente o errata, registry irraggiungibile: nessun container, exit 2 (ADR-0005).

Contro un registry locale reale (`deploy/compose/registry.yaml`, solo 127.0.0.1) e cosign v3.1.4.
Si attiva con `CA_TEST_DOCKER=1` e `COSIGN=/percorso/cosign`. La firma passa solo da
`deploy/docker/sign-local.sh` (chiave di test in una cartella temporanea fuori dal repository,
password vuota, cancellata a fine sessione; nessun log di trasparenza pubblico, nessun registry
esterno). "Nessun container creato" si prova con `docker events`, non con l'elenco finale: un
container creato e subito rimosso non si vedrebbe. "Nessun pull" si prova con l'assenza
dell'immagine dal daemon dopo il fallimento.
"""

import json
import os
import re
import shutil
import socket
import stat
import subprocess
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from t03_support import CONTAINER_PREFIX, FAKE, ROOT, RUN_ID, Lab, ex, lab, needs_docker, work

from ca_cli.composition import build_context
from ca_core.ports import RunOutcome, ScanAborted, Signature
from ca_plugins.runner import OciExecutor, OutputReader
from ca_plugins.signature import CosignVerifier

COMPOSE = ROOT / "deploy" / "compose" / "registry.yaml"
SIGN = ROOT / "deploy" / "docker" / "sign-local.sh"


def _free_port() -> str:
    """Una porta libera su loopback (`registry.yaml` si pubblica su CA_REGISTRY_PORT)."""
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return str(probe.getsockname()[1])


PORT = os.environ.get("CA_TEST_T03_REGISTRY_PORT") or _free_port()
DEAD_PORT = _free_port()  # nessuno ascolta: il registry "irraggiungibile"
PROJECT = f"ca-t03-{RUN_ID}"
COSIGN = os.environ.get("COSIGN", "")

pytestmark = [
    needs_docker,
    pytest.mark.skipif(
        not COSIGN or not os.access(COSIGN, os.X_OK),
        reason="richiede cosign v3.1.4 verificato: COSIGN=/percorso/cosign",
    ),
]


def sh(*args: str, env: dict[str, str] | None = None) -> str:
    return subprocess.run(
        args,
        capture_output=True,
        text=True,
        check=True,
        timeout=300,
        env={**os.environ, **(env or {})},
    ).stdout.strip()


@pytest.fixture(scope="module")
def keys(tmp_path_factory: pytest.TempPathFactory) -> Path:
    return tmp_path_factory.mktemp("t03keys")  # fuori dal repository


@pytest.fixture(scope="module")
def other_pub(tmp_path_factory: pytest.TempPathFactory) -> Path:
    d = tmp_path_factory.mktemp("t03otherkeys")
    subprocess.run(
        [COSIGN, "generate-key-pair"],
        cwd=d,
        env={**os.environ, "COSIGN_PASSWORD": ""},
        check=True,
        capture_output=True,
    )
    return d / "cosign.pub"


@pytest.fixture(scope="module")
def refs(lab: Lab, keys: Path) -> Iterator[dict[str, str]]:
    env = {"CA_REGISTRY_PORT": PORT, "COSIGN": COSIGN}
    up = ["docker", "compose", "-p", PROJECT, "-f", str(COMPOSE)]
    images: list[str] = []
    try:
        sh(*up, "up", "-d", "--wait", env=env)
        signed = sh(
            str(SIGN), str(FAKE), f"ca-t03-signed-{RUN_ID}", env={**env, "CA_KEY_DIR": str(keys)}
        )
        signed = signed.splitlines()[-1]
        unsigned_tag = f"127.0.0.1:{PORT}/ca-t03-unsigned-{RUN_ID}:t"
        images += [f"127.0.0.1:{PORT}/ca-t03-signed-{RUN_ID}:local", unsigned_tag]
        sh("docker", "build", "-q", "--label", "t03=unsigned", "-t", unsigned_tag, str(FAKE))
        digest = re.search(r"digest: (sha256:[0-9a-f]{64})", sh("docker", "push", unsigned_tag))
        assert digest
        yield {
            "signed": signed,
            "unsigned": f"127.0.0.1:{PORT}/ca-t03-unsigned-{RUN_ID}@{digest.group(1)}",
            "dead": signed.replace(f":{PORT}/", f":{DEAD_PORT}/"),
        }
    finally:
        subprocess.run([*up, "down", "--volumes"], env={**os.environ, **env}, check=False)
        subprocess.run(["docker", "rmi", "-f", *images], capture_output=True, check=False)
        shutil.rmtree(keys, ignore_errors=True)


def verifier(pub: Path | None, **kw: Any) -> CosignVerifier:
    return CosignVerifier(
        public_key=str(pub) if pub else None,
        cosign=kw.pop("cosign", COSIGN),
        allow_http_registry=True,
        timeout=60,
        **kw,
    )


def local(ref: str) -> bool:
    return subprocess.run(["docker", "image", "inspect", ref], capture_output=True).returncode == 0


def forget(ref: str) -> None:
    subprocess.run(["docker", "rmi", "-f", ref], capture_output=True, check=False)


def created_since(since: float) -> list[str]:
    """Nomi dei container `ca-fake-t03-<id>-*` creati dopo `since` (eventi del daemon)."""
    out = subprocess.run(
        [
            "docker",
            "events",
            "--since",
            f"{since:.6f}",
            "--until",
            f"{time.time() + 1:.6f}",
            "--filter",
            "type=container",
            "--filter",
            "event=create",
            "--format",
            "{{.Actor.Attributes.name}}",
        ],  # fmt: skip
        capture_output=True,
        text=True,
        check=True,
        timeout=60,
    ).stdout.split()
    return [name for name in out if name.startswith(CONTAINER_PREFIX)]


def attempt(lab: Lab, work: Path, tmp_path: Path, ref: str, verify: Any) -> float:
    """Esegue con il verificatore dato; ritorna il momento di partenza (per gli eventi)."""
    since = time.time()
    with OciExecutor(work_dir=str(work), verifier=verify) as ex:
        with pytest.raises(ScanAborted) as info:
            ex.run(lab.request(tmp_path / "r", "success", image=_tagged(ref)))
    assert info.value.exit_code == 2
    return since


def _tagged(ref: str) -> str:
    name, digest = ref.split("@")
    return f"{name}:t@{digest}"


def test_positive_control_valid_signature_runs_the_verified_digest(
    lab: Lab, refs: dict[str, str], keys: Path, work: Path, tmp_path: Path
) -> None:
    ref = refs["signed"]
    forget(ref)  # si parte senza l'immagine: il pull deve avvenire dopo la verifica
    since = time.time()
    creates: list[list[str]] = []

    class Spy(OciExecutor):
        def _cli(self, *args: str, timeout: float = 60) -> subprocess.CompletedProcess[bytes]:
            if args and args[0] == "create":
                creates.append(list(args))
            return super()._cli(*args, timeout=timeout)

    with Spy(work_dir=str(work), verifier=verifier(keys / "cosign.pub")) as ex:
        result = ex.run(lab.request(tmp_path / "r", "report", image=_tagged(ref)))
        assert result.outcome is RunOutcome.OK, result.detail
        assert result.signature is Signature.VERIFIED
        assert result.output_dir
        ex.release(result.output_dir)
    assert len(created_since(since)) == 1
    # il container e' creato dal digest verificato, mai da un tag
    # custodia di /out e plugin: ogni container nasce dallo stesso digest verificato, mai da un tag
    images = [a for c in creates for a in c if "@sha256:" in a and not a.startswith("type=")]
    assert len(creates) == 2 and len(images) == 2
    assert all(i.endswith(ref.split("@")[1]) and ":t@" not in i for i in images)


@pytest.mark.parametrize("case", ["unsigned", "wrong-key", "dead-registry"])
def test_failed_verification_aborts_before_any_container_or_pull(
    lab: Lab,
    refs: dict[str, str],
    keys: Path,
    other_pub: Path,
    work: Path,
    tmp_path: Path,
    case: str,
) -> None:
    ref = {
        "unsigned": refs["unsigned"],
        "wrong-key": refs["signed"],
        "dead-registry": refs["dead"],
    }[case]
    pub = other_pub if case == "wrong-key" else keys / "cosign.pub"
    forget(ref)
    since = attempt(lab, work, tmp_path, ref, verifier(pub))
    assert created_since(since) == []
    assert not local(ref)  # nessun pull dell'immagine non verificata
    assert list(work.iterdir()) == []  # la verifica precede anche le directory di lavoro


@pytest.mark.parametrize(
    "case", ["no-key", "key-file-missing", "no-cosign", "cosign-wrong-version"]
)
def test_unverifiable_setup_aborts_before_any_container(
    lab: Lab, refs: dict[str, str], keys: Path, work: Path, tmp_path: Path, case: str
) -> None:
    ref = refs["signed"]
    pub: Path | None = keys / "cosign.pub"
    cosign = COSIGN
    if case == "no-key":
        pub = None
    elif case == "key-file-missing":
        pub = tmp_path / "missing.pub"
    elif case == "no-cosign":
        cosign = str(tmp_path / "no-such-cosign")
    else:  # un "cosign" di un'altra versione non e' accettato
        fake = tmp_path / "cosign"
        fake.write_text("#!/bin/sh\necho 'GitVersion:    v0.0.1'\n")
        fake.chmod(stat.S_IRWXU)
        cosign = str(fake)
    forget(ref)
    since = attempt(lab, work, tmp_path, ref, verifier(pub, cosign=cosign))
    assert created_since(since) == []
    assert not local(ref)


def test_batch_with_one_unsigned_image_starts_no_container_at_all(
    lab: Lab, refs: dict[str, str], keys: Path, work: Path, tmp_path: Path
) -> None:
    """`run_many`: le firme di tutto il lotto si verificano prima del primo container."""
    forget(refs["unsigned"])
    since = time.time()
    batch = [
        lab.request(tmp_path / "a", "success", image=_tagged(refs["signed"])),
        lab.request(tmp_path / "b", "success", image=_tagged(refs["unsigned"])),
        lab.request(tmp_path / "c", "success", image=_tagged(refs["signed"])),
    ]
    with OciExecutor(work_dir=str(work), verifier=verifier(keys / "cosign.pub")) as ex:
        with pytest.raises(ScanAborted) as info:
            ex.run_many(batch)
    assert info.value.exit_code == 2
    assert created_since(since) == []
    assert not local(refs["unsigned"])
    assert list(work.iterdir()) == []


def test_composition_root_without_key_aborts_with_exit_2(
    lab: Lab, refs: dict[str, str], work: Path, tmp_path: Path
) -> None:
    """Il cablaggio reale della CLI (`build_context`) senza chiave: exit 2, nessun container."""
    context = build_context(environ={})
    since = time.time()
    with pytest.raises(ScanAborted) as info:
        context.executor.run(lab.request(tmp_path / "r", "success", image=_tagged(refs["signed"])))
    assert info.value.exit_code == 2
    assert created_since(since) == []


def test_composition_root_with_the_key_runs_signed_and_rejects_unsigned(
    lab: Lab, refs: dict[str, str], keys: Path, tmp_path: Path
) -> None:
    context = build_context(
        public_key=str(keys / "cosign.pub"), cosign=COSIGN, allow_http_registry=True, environ={}
    )
    ok = context.executor.run(lab.request(tmp_path / "a", "success", image=_tagged(refs["signed"])))
    assert (ok.outcome, ok.signature) == (RunOutcome.OK, Signature.VERIFIED)
    forget(refs["unsigned"])
    since = time.time()
    with pytest.raises(ScanAborted):
        context.executor.run(
            lab.request(tmp_path / "b", "success", image=_tagged(refs["unsigned"]))
        )
    assert created_since(since) == []
    assert lab.containers() == []


def test_unsigned_is_possible_only_with_the_environment_flag_and_is_reported_as_skipped(
    lab: Lab, refs: dict[str, str], keys: Path, tmp_path: Path
) -> None:
    for value in ("true", "0", "", "yes", " 1"):
        context = build_context(
            public_key=str(keys / "cosign.pub"),
            cosign=COSIGN,
            allow_http_registry=True,
            environ={"CA_INSECURE_ALLOW_UNSIGNED": value},
        )
        forget(refs["unsigned"])
        with pytest.raises(ScanAborted):
            context.executor.run(
                lab.request(tmp_path / "x", "success", image=_tagged(refs["unsigned"]))
            )
    context = build_context(
        public_key=str(keys / "cosign.pub"),
        cosign=COSIGN,
        allow_http_registry=True,
        environ={"CA_INSECURE_ALLOW_UNSIGNED": "1"},
    )
    result = context.executor.run(
        lab.request(tmp_path / "y", "report", image=_tagged(refs["unsigned"]))
    )
    assert (result.outcome, result.signature) == (RunOutcome.OK, Signature.SKIPPED)
    assert result.output_dir
    json.loads(OutputReader().read_file(result.output_dir, "report.json", 1 << 20))
    assert lab.containers() == []
