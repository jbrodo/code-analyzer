"""Infrastruttura di T-03: il confine host-plugin provato con un daemon Docker reale.

Non e' un `conftest.py`: ne esiste gia' uno in `tests/contract` e `import conftest` si confonde.
Le fixture si importano nei moduli di test.

Si attiva con `CA_TEST_DOCKER=1` (i test sul registry anche con `COSIGN=/percorso/cosign`);
senza, i test che servono il daemon saltano con un motivo esplicito. I test sui lettori
(`OutputReader`, `LocalSourceReader`) non richiedono Docker e girano sempre.

Pulizia: l'immagine `localhost/ca-fake-plugin:t03` e' rimossa a fine sessione; ogni test verifica
che non resti alcun container `ca-fake-t03-<id>-*`. Un plugin ostile puo' lasciare sull'host
alberi di proprieta' di `65534` che l'host non sa rimuovere (vedi i test su `/out`): `scrub` li
elimina con un container root effimero, senza rete, sull'immagine di prova.
"""

import json
import os
import shutil
import subprocess
import uuid
from collections.abc import Iterator, Sequence
from pathlib import Path
from typing import Any

import pytest

from ca_core.models import PackagedPluginManifest
from ca_core.ports import PluginRunRequest
from ca_plugins.runner import OciExecutor

ROOT = Path(__file__).resolve().parents[3]
FAKE = ROOT / "tests" / "fixtures" / "plugins" / "fake"
# Identificativo di sessione: piu' sessioni possono girare insieme sullo stesso daemon (un'altra
# `pytest` completa, un altro agente) senza toccare immagini, container, registry l'una dell'altra.
RUN_ID = uuid.uuid4().hex[:8]
IMAGE_NAME = "localhost/ca-fake-plugin"
TAG = f"{IMAGE_NAME}:t03-{RUN_ID}"
MANIFEST_NAME = f"fake-t03-{RUN_ID}"  # i container si chiamano ca-fake-t03-<id>-<uuid>
CONTAINER_PREFIX = f"ca-{MANIFEST_NAME}-"

HAVE_DOCKER = os.environ.get("CA_TEST_DOCKER") == "1" and shutil.which("docker") is not None
needs_docker = pytest.mark.skipif(
    not HAVE_DOCKER, reason="richiede un daemon Docker: CA_TEST_DOCKER=1"
)


class Lab:
    """Daemon, immagine di prova e costruzione delle richieste."""

    def __init__(self) -> None:
        self.docker("build", "-q", "-t", TAG, str(FAKE))
        self.image_id = self.docker("image", "inspect", "--format", "{{.Id}}", TAG)

    @staticmethod
    def docker(*args: str, check: bool = True, timeout: int = 300) -> str:
        done = subprocess.run(
            ["docker", *args], capture_output=True, text=True, check=check, timeout=timeout
        )
        return done.stdout.strip()

    def containers(self) -> list[str]:
        # plugin e custodie di `/out` (stessa immagine): lo stesso daemon serve altri processi
        return self.docker("ps", "-aq", "--filter", f"ancestor={self.image_id}").split()

    def image_env(self) -> dict[str, str]:
        raw = json.loads(self.docker("image", "inspect", "--format", "{{json .Config.Env}}", TAG))
        return dict(item.split("=", 1) for item in raw)

    def manifest(
        self, image: str | None = None, *, report: bool = False, **resources: Any
    ) -> PackagedPluginManifest:
        """`report`: dichiara `/out/report.json` come secondo output, l'unico modo perché la sonda
        del plugin finto arrivi all'host: i file non dichiarati non si copiano (ADR-0004)."""
        data = json.loads((FAKE / "plugin.yaml").read_text())
        if report:
            data["outputs"].update(cyclonedx="/out/report.json", cyclonedx_version="1.7")
        data["name"] = MANIFEST_NAME
        data["image"] = image or f"{TAG}@{self.image_id}"
        data["resources"].update(resources)
        return PackagedPluginManifest.model_validate(data)

    def request(
        self,
        base: Path,
        behavior: str,
        *,
        workspace_files: dict[str, str] | None = None,
        timeout: str = "10s",
        image: str | None = None,
        **params: Any,
    ) -> PluginRunRequest:
        base.mkdir(parents=True, exist_ok=True)
        workspace = base / "ws"
        workspace.mkdir(exist_ok=True)
        for name, content in (workspace_files or {"app.py": "print(1)\n"}).items():
            (workspace / name).write_text(content)
        config = base / "config.json"
        config.write_text(json.dumps({"behavior": behavior, **params}))
        config.chmod(0o600)  # il runner lo copia leggibile da 65534
        return PluginRunRequest(
            manifest=self.manifest(
                image,
                report=behavior == "report" or bool(params.get("report")),
                timeout=timeout,
            ),
            workspace=str(workspace),
            config=str(config),
        )

    def executor(self, work_dir: Path, **kwargs: Any) -> OciExecutor:
        work_dir.mkdir(parents=True, exist_ok=True)
        # L'immagine locale non ha digest di registry: si esegue il suo ID immutabile.
        return OciExecutor(work_dir=str(work_dir), image_ref=lambda _: self.image_id, **kwargs)

    def scrub(self, path: Path) -> None:
        """Rimuove il contenuto di `path` come root in un container effimero (solo test)."""
        if not path.exists():
            return
        subprocess.run(
            [
                "docker",
                "run",
                "--rm",
                "--pull",
                "never",
                "--network",
                "none",
                "--user",
                "0",
                "--entrypoint",
                "sh",
                "-v",
                f"{path}:/scrub",
                self.image_id,
                "-c",
                "chmod -R u+rwx /scrub 2>/dev/null; rm -rf /scrub/* /scrub/.[!.]*",
            ],  # fmt: skip
            capture_output=True,
            check=False,
            timeout=120,
        )
        shutil.rmtree(path, ignore_errors=True)


@pytest.fixture(scope="session")
def lab() -> Iterator[Lab]:
    if not HAVE_DOCKER:
        pytest.skip("richiede un daemon Docker: CA_TEST_DOCKER=1")
    instance = Lab()
    yield instance
    subprocess.run(["docker", "rmi", "-f", TAG], capture_output=True, check=False)


@pytest.fixture
def work(lab: Lab, tmp_path: Path) -> Iterator[Path]:
    """Radice di lavoro dell'esecutore; a fine test niente container e niente residui root."""
    base = tmp_path / "w"
    base.mkdir()
    yield base
    lab.scrub(base)
    assert lab.containers() == [], "container del runner rimasti"


@pytest.fixture
def ex(lab: Lab, work: Path) -> Iterator[OciExecutor]:
    with lab.executor(work) as executor:
        yield executor


def run_dirs(work: Path) -> Sequence[Path]:
    """Directory `run-*` ancora presenti sotto la radice privata dell'esecutore."""
    return sorted(work.glob("ca-oci-*/run-*"))
