"""I-04: il pacchetto costruito da `package-cli.sh` funziona da solo, senza le cablature di prova.

Lancia `bin/code-analyzer` dell'installazione pulita, fuori dal repository: nessun `_cli_child.py`,
manifest e registry sono quelli del pacchetto. `UV_OFFLINE`: dipendenze dalla cache di uv.

I-01: dallo stesso pacchetto si costruisce l'immagine CLI, che scansiona la fixture con i plugin
come container fratelli (ADR-0004, M-11). Serve il socket del daemon in `/var/run/docker.sock`.
"""

import json
import os
import subprocess
from pathlib import Path

import pytest

from .e2e_lab import (
    COSIGN,
    DEPLOY,
    SYFT,
    Fleet,
    container_leftovers,
    copy_fixture,
    e2e_marks,
    make_feeds_cache,
    needs_feeds,
    sh,
)

pytestmark = [*e2e_marks, needs_feeds]
PLUGINS = 7


SOCKET = Path("/var/run/docker.sock")


@pytest.fixture(scope="module")
def package(fleet: Fleet, work: Path) -> tuple[Path, dict[str, str]]:
    """Uscita di `package-cli.sh` e immagini firmate, una volta per i due test."""
    fleet.add_builtin("syft")  # avvia il registry locale e crea le chiavi di prova
    out = work / "package"
    sh(
        str(DEPLOY / "package-cli.sh"), str(out),
        env={**fleet.env, "SYFT": SYFT, "UV_OFFLINE": "1"},
    )  # fmt: skip
    images = dict(line.split() for line in (out / "images.txt").read_text().splitlines())
    assert len(images) == PLUGINS and all("@sha256:" in image for image in images.values())
    return out, images


def test_packaged_cli_scans_a_fixture_with_its_own_manifests(
    work: Path, package: tuple[Path, dict[str, str]]
) -> None:
    out, images = package

    xdg = work / "package-xdg"
    digests = {name: image.rsplit("@", 1)[1] for name, image in images.items()}
    make_feeds_cache(xdg / "code-analyzer" / "feeds", digests)
    root = copy_fixture("python-app", work / "package-repo", license_policy=True)
    reports = work / "package-out"
    env = {
        **os.environ,
        "COSIGN": COSIGN,
        "CA_COSIGN_PUBLIC_KEY": str(out / "cosign.pub"),
        "XDG_CACHE_HOME": str(xdg),
    }

    def cli(*argv: str) -> subprocess.CompletedProcess[str]:
        command = [str(out / "venv/bin/code-analyzer"), *argv]
        return subprocess.run(
            command, capture_output=True, text=True, env=env, cwd=work, timeout=900
        )

    scan = cli("scan", str(root), "--offline", "--output-dir", str(reports))
    assert scan.returncode == 0, scan.stderr[-2000:]
    report = json.loads((reports / "code-analyzer.report.json").read_text())
    assert report["status"] == "complete"
    assert len(report["plugins"]) == PLUGINS
    assert all(p["outcome"] == "ok" and p["signature"] == "verified" for p in report["plugins"])
    assert cli("gate", "--report", str(reports / "code-analyzer.report.json")).returncode == 1

    bom = work / "package-bom.json"
    assert cli("sbom", str(root), "--output", str(bom)).returncode == 0
    assert json.loads(bom.read_text())["specVersion"] == "1.7"


def test_cli_image_scans_with_sibling_plugin_containers(
    fleet: Fleet, work: Path, package: tuple[Path, dict[str, str]]
) -> None:
    out, images = package
    tag = f"localhost/ca-e2e-cli:{fleet.project}"
    sh(
        str(DEPLOY / "cli/build-cli-image.sh"), str(out), tag, str(work / "cli-sbom"),
        env={"SYFT": SYFT, "UV_OFFLINE": "1"},
    )  # fmt: skip
    fleet.refs.append(tag)  # rimossa alla chiusura della flotta

    cache = work / "image-cache"
    make_feeds_cache(cache, {name: image.rsplit("@", 1)[1] for name, image in images.items()})
    root = copy_fixture("python-app", work / "image-repo", license_policy=True)
    scratch, reports, other = work / "image-work", work / "image-out", work / "image-other"
    for folder in (scratch, reports, other):
        folder.mkdir(mode=0o700)

    def image(*argv: str, host_workspace: Path = root) -> subprocess.CompletedProcess[str]:
        command = [
            "docker", "run", "--rm",
            "--user", f"{os.getuid()}:{os.getgid()}",
            "--group-add", str(SOCKET.stat().st_gid),
            "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
            "--read-only", "--tmpfs", "/tmp",
            "--network", "host",  # il registry di prova e' su loopback
            "-v", f"{SOCKET}:{SOCKET}",
            "-v", f"{root}:/ca/workspace:ro",
            "-v", f"{scratch}:/ca/work",
            "-v", f"{cache}:/ca/cache",
            "-v", f"{reports}:/ca/output",
            "-v", f"{out / 'cosign.pub'}:/ca/keys/cosign.pub:ro",
            "-e", "CA_COSIGN_PUBLIC_KEY=/ca/keys/cosign.pub",
            "-e", f"CA_HOST_WORKSPACE={host_workspace}",
            "-e", f"CA_HOST_WORK={scratch}",
            "-e", f"CA_HOST_CACHE={cache}",
            tag, *argv,
        ]  # fmt: skip
        return subprocess.run(command, capture_output=True, text=True, timeout=900)

    scan = image("scan", "--offline")
    assert scan.returncode == 0, scan.stderr[-2000:]
    report = json.loads((reports / "code-analyzer.report.json").read_text())
    assert report["status"] == "complete"
    assert len(report["plugins"]) == PLUGINS
    assert all(p["outcome"] == "ok" and p["signature"] == "verified" for p in report["plugins"])
    assert any(f["category"] == "dependency" for f in report["findings"])  # feed montati
    assert image("gate").returncode == 1  # legge il report da /ca/output
    assert list(scratch.iterdir()) == []  # radice di lavoro ripulita
    assert not list(cache.glob(".ca-probe-*"))

    # Il daemon monterebbe un'altra directory: la scansione si annulla prima di ogni plugin.
    (reports / "code-analyzer.report.json").unlink()
    wrong = image("scan", "--offline", host_workspace=other)
    assert wrong.returncode == 2 and "non corrispondono" in wrong.stderr
    assert not (reports / "code-analyzer.report.json").exists()
    assert container_leftovers() == []
