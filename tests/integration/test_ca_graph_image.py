"""Plugin ca-graph (G-11) sull'immagine reale: il churn dalla storia git, con il profilo completo.

`CA_TEST_DOCKER=1`; vedi `plugin_image_support.py` per `COSIGN` e `SYFT`. La storia si costruisce
qui con date fisse; il workspace è montato in sola lettura e la git dir ombra sta nel tmpfs.
"""

import json
import os
import shutil
import subprocess
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from plugin_image_support import BUILTIN, ROOT, gate, needs_syft, run, run_ok

from ca_core.models.graph import Graph

PLUGIN = "ca_graph"  # la cartella del plugin; il nome nel manifest è `ca-graph`
STAGE = ROOT / "deploy/docker/stage-context.sh"
TAG = "localhost/ca-plugin-ca-graph:itest"
HEAD_DAY = datetime(2026, 1, 1, 12, 0, tzinfo=UTC)
pytestmark = pytest.mark.skipif(
    os.environ.get("CA_TEST_DOCKER") != "1", reason="richiede Docker (CA_TEST_DOCKER=1)"
)


@pytest.fixture(scope="module")
def image_id() -> Iterator[str]:
    """Il contesto di build include `ca_graph/` da `packages/ca-graph`: lo prepara lo script."""
    staged = run(str(STAGE), str(BUILTIN / PLUGIN)).splitlines()[-1]
    try:
        run("docker", "build", "-q", "-t", TAG, staged)
        yield run("docker", "image", "inspect", "--format", "{{.Id}}", TAG)
    finally:
        subprocess.run(["docker", "rmi", "-f", TAG], capture_output=True, check=False)
        if Path(staged) != BUILTIN / PLUGIN:
            shutil.rmtree(staged, ignore_errors=True)


def git(repo: Path, *argv: str, days: float | None = None) -> None:
    env = {
        **os.environ,
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_AUTHOR_NAME": "t",
        "GIT_AUTHOR_EMAIL": "t@example.invalid",
        "GIT_COMMITTER_NAME": "t",
        "GIT_COMMITTER_EMAIL": "t@example.invalid",
    }
    if days is not None:
        env["GIT_AUTHOR_DATE"] = env["GIT_COMMITTER_DATE"] = (
            HEAD_DAY - timedelta(days=days)
        ).isoformat()
    subprocess.run(["git", "-C", str(repo), *argv], env=env, check=True, capture_output=True)


def build_history(root: Path) -> Path:
    root.mkdir(parents=True)
    git(root, "init", "-q", "-b", "main")
    steps = [
        (200, {"app/a.py": "import app.b\n", "app/b.py": "x = 1\n", "app/c.py": ""}),
        (5, {"app/a.py": "import app.b\n# 2\n"}),
        (0, {"app/a.py": "import app.b\n# 3\n", "app/b.py": "x = 2\n"}),
    ]
    for days, files in steps:
        for name, text in files.items():
            (root / name).parent.mkdir(parents=True, exist_ok=True)
            (root / name).write_text(text)
        git(root, "add", "-A")
        git(root, "commit", "-q", "-m", "c", days=days)
    return root


def graph_of(image_id: str, workspace: Path, work: Path) -> dict[str, Any]:
    files = run_ok(PLUGIN, TAG, image_id, workspace, work)
    assert list(files) == ["graph.json"]
    document: dict[str, Any] = json.loads(files["graph.json"])
    Graph.model_validate(document)  # il contratto, anche con il churn
    return document


def test_churn_is_computed_in_the_container_from_the_shadow_git_dir(
    image_id: str, tmp_path: Path
) -> None:
    document = graph_of(image_id, build_history(tmp_path / "ws"), tmp_path / "w")
    churn = {m["path"]: m["churn"] for m in document["modules"]}
    assert churn == {"app/a.py": 2, "app/b.py": 1, "app/c.py": 0}
    assert document["history"]["status"] == "completa"
    assert document["history"]["head_time"] == HEAD_DAY.isoformat()


def test_a_hostile_git_config_changes_nothing_and_executes_nothing(
    image_id: str, tmp_path: Path
) -> None:
    ws = build_history(tmp_path / "ws")
    with (ws / ".git" / "config").open("a") as config:
        config.write(
            "[core]\n\tfsmonitor = /bin/false\n\tpager = /bin/false\n[alias]\n\tlog = !false\n"
        )
    document = graph_of(image_id, ws, tmp_path / "w")
    assert document["history"]["status"] == "completa"
    assert {m["path"]: m["churn"] for m in document["modules"]}["app/a.py"] == 2


def test_a_shallow_clone_has_no_churn_and_says_so(image_id: str, tmp_path: Path) -> None:
    source = build_history(tmp_path / "src")
    clone = tmp_path / "clone"
    subprocess.run(
        ["git", "clone", "-q", "--depth", "1", f"file://{source}", str(clone)],
        check=True,
        env={**os.environ, "GIT_CONFIG_GLOBAL": os.devnull},
    )
    document = graph_of(image_id, clone, tmp_path / "w")
    assert document["history"]["status"] == "superficiale"
    assert all("churn" not in m for m in document["modules"])


def test_a_workspace_without_git_has_absent_history(image_id: str, tmp_path: Path) -> None:
    ws = tmp_path / "ws"
    (ws / "app").mkdir(parents=True)
    (ws / "app" / "a.py").write_text("x = 1\n")
    document = graph_of(image_id, ws, tmp_path / "w")
    assert document["history"]["status"] == "assente"
    assert all("churn" not in m for m in document["modules"])


@needs_syft
def test_build_image_gate_checks_licenses_and_writes_the_image_sbom(tmp_path: Path) -> None:
    document = gate(PLUGIN, "localhost/ca-plugin-ca-graph:gate", tmp_path)
    assert document["specVersion"] == "1.7" and document["components"]
