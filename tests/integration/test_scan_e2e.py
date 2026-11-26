"""L-04: `code-analyzer scan` e `gate` come processi reali, col plugin finto firmato. Opzionale.

Si attiva con `CA_TEST_DOCKER=1` e `COSIGN=/percorso/cosign` (v3.1.4 verificato). L'immagine del
plugin finto è costruita, spinta su un registry locale (solo 127.0.0.1, porta libera) e firmata
con `deploy/docker/sign-local.sh`: chiave di test in una cartella temporanea fuori dal repository,
password vuota. Il processo figlio è `python -c` che chiama `ca_cli.main.main` con la chiave da
`CA_COSIGN_PUBLIC_KEY` e `allow_http_registry=True` (il registry locale è HTTP: l'opzione è di chi
cabla, non esiste da riga di comando) e il manifest del plugin finto al posto di quelli del
pacchetto (nessun plugin reale in `builtin/`). A fine sessione si rimuovono registry, immagini e
chiavi; ogni test verifica che non resti alcun container del plugin.
"""

import json
import os
import re
import shutil
import socket
import subprocess
import sys
import uuid
from collections.abc import Iterator
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
FAKE = ROOT / "tests" / "fixtures" / "plugins" / "fake"
SIGN = ROOT / "deploy" / "docker" / "sign-local.sh"
COMPOSE = ROOT / "deploy" / "compose" / "registry.yaml"
COSIGN = os.environ.get("COSIGN", "")
RUN_ID = uuid.uuid4().hex[:8]
PLUGIN = f"fake-e2e-{RUN_ID}"  # i container si chiamano ca-<plugin>-<uuid>

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

# Il processo figlio: stesso comando dell'utente, con le sole due cablature che la riga di comando
# non offre (registry HTTP locale, manifest del plugin finto). Argomenti: manifest, poi `argv`.
# Nessuna rete (regola 7 di AGENTS.md): senza trasporto per EPSS e KEV, e ogni connessione di
# questo processo fuori dal loopback fallisce, come in `tests/e2e/_cli_child.py`.
CHILD = """
import dataclasses, json, socket, sys
from ca_cli.composition import build_context
from ca_cli.main import main
from ca_core.models import PackagedPluginManifest
_connect = socket.socket.connect
def guarded(self, address):
    if self.family == socket.AF_UNIX or (
        isinstance(address, tuple) and address and address[0] in ("127.0.0.1", "::1")
    ):
        return _connect(self, address)
    raise OSError(f"E2E: connessione di rete non consentita verso {address!r}")
socket.socket.connect = guarded
manifest = PackagedPluginManifest.model_validate(json.load(open(sys.argv[1])))
context = dataclasses.replace(
    build_context(allow_http_registry=True), manifests=lambda: [manifest], enrichment_fetcher=None
)
sys.exit(main(sys.argv[2:], context=context))
"""


def sh(*args: str, env: dict[str, str] | None = None) -> str:
    return subprocess.run(
        args,
        capture_output=True,
        text=True,
        check=True,
        timeout=300,
        env={**os.environ, **(env or {})},
    ).stdout.strip()


def leftovers() -> list[str]:
    return sh("docker", "ps", "-aq", "--filter", f"name=ca-{PLUGIN}-").split()


def free_port() -> str:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return str(probe.getsockname()[1])


class Lab:
    def __init__(self, ref: str, pub: Path, other_pub: Path, tmp: Path) -> None:
        data = json.loads((FAKE / "plugin.yaml").read_text())
        data["name"] = PLUGIN
        data["categories"] = ["sast"]  # `quality` non ha ancora un kind in Fase 1 (K-05)
        data["image"] = ref.replace("@", ":local@")  # il manifest chiede tag e digest
        self.manifest = tmp / "manifest.json"
        self.manifest.write_text(json.dumps(data))
        self.pub, self.other_pub = pub, other_pub

    def run(
        self, tmp: Path, *args: str, pub: Path | None = None
    ) -> subprocess.CompletedProcess[str]:
        env = {
            **os.environ,
            "COSIGN": COSIGN,
            "CA_COSIGN_PUBLIC_KEY": str(pub or self.pub),
            "XDG_CACHE_HOME": str(tmp / "xdg-cache"),  # mai la cache dell'utente
        }
        env.pop("CA_INSECURE_ALLOW_UNSIGNED", None)
        return subprocess.run(
            [sys.executable, "-c", CHILD, str(self.manifest), *args],
            capture_output=True,
            text=True,
            timeout=600,
            env=env,
            cwd=tmp,
        )


@pytest.fixture(scope="module")
def lab(tmp_path_factory: pytest.TempPathFactory) -> Iterator[Lab]:
    keys = tmp_path_factory.mktemp("e2ekeys")  # fuori dal repository
    other = tmp_path_factory.mktemp("e2eotherkeys")
    tmp = tmp_path_factory.mktemp("e2elab")
    # Il plugin finto emette un `uri` assoluto con `uriBaseId`, che K-05 rifiuta (ADR-0007):
    # copia di prova con il solo `uri` corretto. Il fixture originale non si tocca.
    context = tmp / "context"
    shutil.copytree(FAKE, context, ignore=shutil.ignore_patterns("__pycache__", "test_*"))
    script = context / "fake_plugin.py"
    source = script.read_text()
    patched = source.replace('"/workspace/app.py"', '"app.py"').replace(
        '                                "uriBaseId": "%SRCROOT%",\n', ""
    )
    assert patched.count("uriBaseId") == source.count("uriBaseId") - 1 and patched != source
    script.write_text(patched)
    port = free_port()
    env = {"CA_REGISTRY_PORT": port, "COSIGN": COSIGN}
    up = ["docker", "compose", "-p", f"ca-e2e-{RUN_ID}", "-f", str(COMPOSE)]
    name = f"ca-e2e-signed-{RUN_ID}"
    try:
        sh(*up, "up", "-d", "--wait", env=env)
        ref = sh(str(SIGN), str(context), name, env={**env, "CA_KEY_DIR": str(keys)}).splitlines()[
            -1
        ]
        subprocess.run(
            [COSIGN, "generate-key-pair"],
            cwd=other,
            env={**os.environ, "COSIGN_PASSWORD": ""},
            check=True,
            capture_output=True,
        )
        yield Lab(ref, keys / "cosign.pub", other / "cosign.pub", tmp)
    finally:
        subprocess.run([*up, "down", "--volumes"], env={**os.environ, **env}, check=False)
        digest = re.search(r"@sha256:[0-9a-f]{64}", locals().get("ref", ""))
        refs = [f"127.0.0.1:{port}/{name}:local"]
        if digest:
            refs.append(f"127.0.0.1:{port}/{name}{digest.group(0)}")
        subprocess.run(["docker", "rmi", "-f", *refs], capture_output=True, check=False)
        for leftover in leftovers():
            subprocess.run(["docker", "rm", "-f", leftover], capture_output=True, check=False)
        shutil.rmtree(keys, ignore_errors=True)
        shutil.rmtree(other, ignore_errors=True)


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    path = tmp_path / "repo"
    path.mkdir()
    (path / "app.py").write_text("print(1)\n")
    return path


def test_scan_and_gate_as_real_processes(lab: Lab, repo: Path, tmp_path: Path) -> None:
    out = tmp_path / "out"
    done = lab.run(tmp_path, "scan", str(repo), "--output-dir", str(out), "--format", "json")
    assert done.returncode == 0, done.stderr
    report = json.loads(done.stdout)
    assert sorted(p.name for p in out.iterdir()) == [
        "code-analyzer.report.json",
        "code-analyzer.sarif",
    ]
    assert json.loads((out / "code-analyzer.report.json").read_text()) == report
    (run,) = report["plugins"]
    assert (run["name"], run["outcome"], run["signature"], run["failure"]) == (
        PLUGIN,
        "ok",
        "verified",
        None,
    )
    assert run["isolation"] in ("gvisor", "hardened-container")
    assert report["status"] == "complete"
    assert leftovers() == []

    gate = lab.run(tmp_path, "gate", "--report", str(out / "code-analyzer.report.json"))
    assert gate.returncode in (0, 1), gate.stderr  # dipende dai finding del plugin finto


def test_wrong_key_exits_2_without_report_or_traceback(
    lab: Lab, repo: Path, tmp_path: Path
) -> None:
    out = tmp_path / "out"
    done = lab.run(tmp_path, "scan", str(repo), "--output-dir", str(out), pub=lab.other_pub)
    assert done.returncode == 2
    assert not out.exists() and "Traceback" not in done.stderr
    assert leftovers() == []


def test_min_isolation_gvisor_exits_2_before_any_container(
    lab: Lab, repo: Path, tmp_path: Path
) -> None:
    if "runsc" in sh("docker", "info", "--format", "{{json .Runtimes}}"):
        pytest.skip("runsc presente: il requisito sarebbe soddisfatto")
    out = tmp_path / "out"
    done = lab.run(
        tmp_path, "scan", str(repo), "--output-dir", str(out), "--min-isolation", "gvisor"
    )
    assert done.returncode == 2 and not out.exists()
    assert "isolamento richiesto" in done.stderr and "Traceback" not in done.stderr
    assert leftovers() == []


def test_umask_077_clone_is_partial_with_only_the_count_and_gate_exits_2(
    lab: Lab, tmp_path: Path
) -> None:
    """A-02 (ADR-0004, R-09): un clone con `umask 077` non è leggibile da 65534. Il plugin gira ma
    il report è `partial` con il solo conteggio; `chmod -R o+rX` lo riporta a `complete`."""
    repo = tmp_path / "repo"
    old = os.umask(0o077)
    try:
        (repo / "src").mkdir(parents=True)
        (repo / "src" / "TOP-SECRET-NAME.py").write_text("print(1)\n")
        (repo / "app.py").write_text("print(2)\n")
    finally:
        os.umask(old)
    out = tmp_path / "out"
    done = lab.run(tmp_path, "scan", str(repo), "--output-dir", str(out), "--format", "json")
    assert done.returncode == 0, done.stderr
    report = json.loads(done.stdout)
    assert report["status"] == "partial"
    (warning,) = (w for w in report["warnings"] if w["code"] == "workspace-unreadable")
    assert (
        warning["message"] == "4 percorsi non leggibili dai plugin: analisi incompleta"
    )  # radice, src e 2 file
    assert warning["message"] in done.stderr
    assert report["plugins"][0]["outcome"] == "ok"
    for text in (done.stdout, done.stderr, (out / "code-analyzer.report.json").read_text()):
        assert "TOP-SECRET-NAME" not in text
    path = str(out / "code-analyzer.report.json")
    assert lab.run(tmp_path, "gate", "--report", path).returncode == 2
    subprocess.run(["chmod", "-R", "o+rX", str(repo)], check=True)
    again = lab.run(tmp_path, "scan", str(repo), "--output-dir", str(out), "--format", "json")
    assert json.loads(again.stdout)["status"] == "complete"
    assert leftovers() == []
    dangling = sh(
        "docker", "volume", "ls", "-q", "--filter", "dangling=true",
        "--filter", "label=code-analyzer.executor=1",
    )  # fmt: skip
    assert dangling == ""
