"""C-04 nella CLI: configurazione effettiva per intero e tipo di scansione nel report."""

import json
from pathlib import Path
from typing import Any

from test_cli_scan_gate import Env, manifest

from ca_core.fakes import FakePluginExecutor
from ca_core.models import CodeAnalyzerConfig


def scan(tmp_path: Path, config: str | None) -> dict[str, Any]:
    env = Env(tmp_path)
    if config is not None:
        (env.repo / ".code-analyzer.yml").write_text(config)
    executor = FakePluginExecutor({"bandit": env.ok()})
    assert env.scan(env.context(executor, [manifest("bandit")])) == 0
    return json.loads((env.out / "code-analyzer.report.json").read_text())


def test_the_report_carries_the_whole_effective_configuration(tmp_path: Path) -> None:
    config = (
        "version: 1\ngate:\n  mode: new-findings-only\n  block_on: [critico]\n"
        "paths:\n  exclude: [dist]\nlicenses:\n  forbidden: [X-1]\n"
    )
    report = scan(tmp_path, config)
    effective = report["effective_config"]
    assert effective["gate"]["block_on"] == ["critico"] and effective["paths"]["exclude"] == [
        "dist"
    ]
    assert effective["licenses"]["forbidden"] == ["X-1"]
    CodeAnalyzerConfig.model_validate(effective)  # e' una configurazione valida, riusabile


def test_without_a_configuration_file_the_effective_one_is_the_default_and_the_scan_is_full(
    tmp_path: Path,
) -> None:
    report = scan(tmp_path, None)
    assert report["effective_config"]["version"] == 1
    assert report.get("scan", {"kind": "full"})["kind"] == "full"
    assert "baseline" not in report or report["baseline"] is None
