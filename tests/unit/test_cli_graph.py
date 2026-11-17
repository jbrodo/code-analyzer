"""G-10 nella CLI: `scan` aggancia il passo `build_graph` e scrive il grafo come artefatto."""

import json
import shutil
from pathlib import Path
from typing import Any

import pytest
from test_cli_scan_gate import Env, manifest

from ca_core.fakes import FakePluginExecutor
from ca_graph.treesitter.extract import extract_graph

ROOT = Path(__file__).resolve().parents[2]
FIXTURE = ROOT / "tests/fixtures/repos/graph-python"
GRAPH_OUTPUT = {"graph": "/out/graph.json", "max_bytes": 10**8}


def graph_plugin() -> Any:
    return manifest("ca-graph", languages=[], categories=["architecture"], outputs=GRAPH_OUTPUT)


def run(env: Env, graph_bytes: bytes | None, plugins: list[Any]) -> dict[str, Any]:
    if graph_bytes is not None:
        (env.plugin_out / "graph.json").write_bytes(graph_bytes)
    executor = FakePluginExecutor({p.name: env.ok() for p in plugins})
    assert env.scan(env.context(executor, plugins)) == 0
    return json.loads((env.out / "code-analyzer.report.json").read_text())


def graph_json() -> bytes:
    return json.dumps(extract_graph(str(FIXTURE))).encode()


def test_the_graph_plugin_gives_architecture_findings_and_a_graph_artifact(tmp_path: Path) -> None:
    env = Env(tmp_path)
    shutil.copytree(FIXTURE, env.repo, dirs_exist_ok=True)
    report = run(env, graph_json(), [graph_plugin()])
    architecture = [f for f in report["findings"] if f["category"] == "architecture"]
    assert {f["rule_id"] for f in architecture} >= {"ca.arch.cyclic-dependency"}
    assert {f["level"] for f in architecture} == {"basso"}
    assert {f["level_source"] for f in architecture} == {"default"}
    assert report["status"] == "complete"
    artifact = json.loads((env.out / "code-analyzer.graph.json").read_text())
    assert artifact["packages"] and artifact["modules"][0]["metrics"] is not None


def test_a_graph_that_does_not_conform_makes_the_scan_partial_with_a_health_finding(
    tmp_path: Path,
) -> None:
    env = Env(tmp_path)
    report = run(env, b'{"version": 1}', [graph_plugin()])
    assert report["status"] == "partial"
    health = [f for f in report["findings"] if f["category"] == "health"]
    assert [f["tool"] for f in health] == ["ca-graph"]
    failed = next(p for p in report["plugins"] if p["name"] == "ca-graph")
    assert failed["outcome"] == "failed" and "grafo" in failed["failure"]
    assert not (env.out / "code-analyzer.graph.json").exists()
    assert not [f for f in report["findings"] if f["category"] == "architecture"]


def test_without_the_graph_plugin_nothing_changes(tmp_path: Path) -> None:
    env = Env(tmp_path)
    report = run(env, None, [manifest("bandit")])
    assert not [f for f in report["findings"] if f["category"] == "architecture"]
    assert not (env.out / "code-analyzer.graph.json").exists()


def test_paths_excluded_by_the_configuration_leave_the_graph(tmp_path: Path) -> None:
    env = Env(tmp_path)
    shutil.copytree(FIXTURE, env.repo, dirs_exist_ok=True)
    (env.repo / ".code-analyzer.yml").write_text("version: 1\npaths:\n  exclude: [shop/billing]\n")
    report = run(env, graph_json(), [graph_plugin()])
    assert "ca.arch.cyclic-dependency" not in {f["rule_id"] for f in report["findings"]}
    artifact = json.loads((env.out / "code-analyzer.graph.json").read_text())
    assert not any(m["path"].startswith("shop/billing") for m in artifact["modules"])


def test_table_output_still_works_with_the_graph(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    env = Env(tmp_path)
    shutil.copytree(FIXTURE, env.repo, dirs_exist_ok=True)
    (env.plugin_out / "graph.json").write_bytes(graph_json())
    plugins = [graph_plugin()]
    executor = FakePluginExecutor({"ca-graph": env.ok()})
    assert env.scan(env.context(executor, plugins), "--format", "table") == 0
    assert "plugin ca-graph" in capsys.readouterr().out
