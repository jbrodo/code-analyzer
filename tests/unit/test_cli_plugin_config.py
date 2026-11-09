"""`inputs.config` (ADR-0014): `plugins.semgrep.rules` arriva al solo plugin che lo dichiara."""

import json
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from test_cli_scan_gate import Env, manifest

from ca_core.fakes import FakePluginExecutor
from ca_core.ports import PluginRunRequest, PluginRunResult

OPTIONAL = {"workspace": "readonly", "sbom": "none", "config": "optional"}


class Capturing(FakePluginExecutor):
    """Legge il file durante l'esecuzione: dopo `scan` non esiste piu'."""

    def __init__(self, results: dict[str, PluginRunResult]) -> None:
        super().__init__(results)
        self.seen: dict[str, Any] = {}
        self.paths: list[str] = []

    def run_many(self, requests: Sequence[PluginRunRequest]) -> list[PluginRunResult]:
        for request in requests:
            if request.config is not None:
                self.paths.append(request.config)
                self.seen[request.manifest.name] = json.loads(Path(request.config).read_text())
        return super().run_many(requests)


def scan(env: Env, config: str) -> Capturing:
    (env.repo / "regole.yaml").write_text("rules: []\n")
    (env.repo / ".code-analyzer.yml").write_text(config)
    executor = Capturing({"semgrep": env.ok(), "bandit": env.ok()})
    plugins = [manifest("semgrep", inputs=OPTIONAL), manifest("bandit")]
    assert env.scan(env.context(executor, plugins)) == 0
    return executor


def test_semgrep_rules_reach_only_semgrep_and_the_file_is_removed(tmp_path: Path) -> None:
    executor = scan(Env(tmp_path), "version: 1\nplugins:\n  semgrep:\n    rules: [regole.yaml]\n")
    assert executor.seen == {"semgrep": {"rules": ["regole.yaml"]}}
    assert not Path(executor.paths[0]).exists()


def test_without_rules_no_config_is_mounted(tmp_path: Path) -> None:
    assert scan(Env(tmp_path), "version: 1\n").seen == {}
