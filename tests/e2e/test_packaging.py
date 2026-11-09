"""I-04: il pacchetto costruito da `package-cli.sh` funziona da solo, senza le cablature di prova.

Lancia `bin/code-analyzer` dell'installazione pulita, fuori dal repository: nessun `_cli_child.py`,
manifest e registry sono quelli del pacchetto. `UV_OFFLINE`: dipendenze dalla cache di uv.
"""

import json
import os
import subprocess
from pathlib import Path

from .e2e_lab import (
    COSIGN,
    DEPLOY,
    SYFT,
    Fleet,
    copy_fixture,
    e2e_marks,
    make_feeds_cache,
    needs_feeds,
    sh,
)

pytestmark = [*e2e_marks, needs_feeds]
PLUGINS = 7


def test_packaged_cli_scans_a_fixture_with_its_own_manifests(fleet: Fleet, work: Path) -> None:
    fleet.add_builtin("syft")  # avvia il registry locale e crea le chiavi di prova
    out = work / "package"
    sh(
        str(DEPLOY / "package-cli.sh"), str(out),
        env={**fleet.env, "SYFT": SYFT, "UV_OFFLINE": "1"},
    )  # fmt: skip
    images = dict(line.split() for line in (out / "images.txt").read_text().splitlines())
    assert len(images) == PLUGINS and all("@sha256:" in image for image in images.values())

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
