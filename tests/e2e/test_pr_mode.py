"""T-04: E2E della modalità PR (ADR-0025) sul repository di F-06, con il plugin bandit firmato.

Processi veri (`_cli_child.py`) e immagine vera di bandit dal registry locale, come T-05. Il
repository si genera a ogni sessione (`pr_repository.py`): un branch base e due PR, con un finding
per ciascuno stato (nuovo, esistente, spostato di riga, in un file rinominato, risolto) e una PR che
prova a indebolire il gate da `.code-analyzer.yml`.

La baseline è la scansione completa del commit base, come la produce la CI (ADR-0025), copiata
fuori dal repository analizzato. Le durate finiscono nel riepilogo della sessione (X-05 le misura
sui pilota, non qui).
"""

import json
import shutil
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pr_repository as prr  # tests/fixtures/builders, nel path da e2e_lab
import pytest

from .conftest import DURATIONS
from .e2e_lab import CliResult, Fleet, e2e_marks

pytestmark = e2e_marks

PLUGINS = ["bandit"]
REPORT = "code-analyzer.report.json"


@dataclass
class PrLab:
    fleet: Fleet
    repo: prr.PrRepository
    work: Path
    baseline: Path

    def checkout(self, commit: str, name: str) -> Path:
        return prr.export(self.repo, commit, self.work / name)

    def scan(self, root: Path, name: str, *extra: str) -> CliResult:
        out = self.work / f"out-{name}"
        result = self.fleet.scan(root, out, "--offline", *extra, plugins=PLUGINS)
        DURATIONS[f"T-04 {name}"] = result.seconds
        return result

    def pr_scan(self, commit: str, name: str, *extra: str) -> CliResult:
        root = self.checkout(commit, name)
        flags = ["--pr", "--base", self.repo.base, "--baseline", str(self.baseline)]
        return self.scan(root, name, *flags, *extra)

    def gate(self, result: CliResult, *flags: str) -> CliResult:
        assert result.out_dir is not None
        report = str(result.out_dir / REPORT)
        return self.fleet.run(self.work, "gate", "--report", report, *flags, plugins=PLUGINS)


@pytest.fixture(scope="module")
def lab(fleet: Fleet, tmp_path_factory: pytest.TempPathFactory) -> Iterator[PrLab]:
    fleet.add_builtin("bandit")
    work = tmp_path_factory.mktemp("t04")
    repo = prr.build_pr_repository(work / "source")
    lab = PrLab(fleet, repo, work, work / "baseline" / REPORT)
    base = lab.scan(lab.checkout(repo.base, "base"), "base")
    assert base.returncode == 0, base.stderr
    assert base.report["status"] == "complete", base.report["plugins"]
    lab.baseline.parent.mkdir()
    assert base.out_dir is not None
    shutil.copy(base.out_dir / REPORT, lab.baseline)
    yield lab


@pytest.fixture(scope="module")
def pr(lab: PrLab) -> CliResult:
    result = lab.pr_scan(lab.repo.pr_head, "pr", "--pull-request", "7")
    assert result.returncode == 0, result.stderr
    return result


def by_rule(report: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {f["rule_id"]: f for f in report["findings"] if f["tool"] == "bandit"}


def codes(report: dict[str, Any]) -> set[str]:
    return {w["code"] for w in report["warnings"]}


def test_the_base_scan_finds_every_problem_of_the_base(lab: PrLab) -> None:
    report = json.loads(lab.baseline.read_text())
    expected = {e.rule_id for e in prr.EXPECTED if e.base_path is not None}
    assert set(by_rule(report)) == expected


def test_each_finding_has_the_state_of_the_fixture(pr: CliResult) -> None:
    report = pr.report
    assert report["status"] == "complete"
    assert report["scan"] == {
        "kind": "pr",
        "base_commit": report["scan"]["base_commit"],
        "pull_request": 7,
    }
    assert report["baseline"]["status"] == "valid"
    found = by_rule(report)
    for item in prr.EXPECTED:
        if item.state == "resolved":
            assert item.rule_id not in found, item.name
            continue
        finding = found[item.rule_id]
        assert finding["baseline_state"] == item.state, item.name
        assert finding["location"]["path"] == item.pr_path, item.name


def test_the_counts_match_the_fixture(pr: CliResult) -> None:
    baseline = pr.report["baseline"]
    states = [e.state for e in prr.EXPECTED]
    assert baseline["new"] == states.count("new")
    assert baseline["existing"] == states.count("existing")
    assert len(baseline["resolved"]) == states.count("resolved")


def test_the_moved_and_renamed_findings_keep_their_lines(pr: CliResult) -> None:
    found = by_rule(pr.report)
    for item in prr.EXPECTED:
        if item.name in ("moved", "renamed"):
            text = prr.PR_TREE[item.pr_path]  # type: ignore[index]
            assert found[item.rule_id]["location"]["start_line"] == prr.line_of(text, item.needle)


def test_the_new_findings_only_gate_blocks_on_the_new_finding_only(
    lab: PrLab, pr: CliResult
) -> None:
    assert pr.report["gate"]["effective_mode"] == "new-findings-only"
    found = by_rule(pr.report)
    new = next(e for e in prr.EXPECTED if e.state == "new")
    new_level = found[new.rule_id]["level"]
    # Con le soglie della configurazione del base il finding nuovo non blocca se non è alto o
    # critico; gli esistenti non bloccano mai, qualunque sia il loro livello.
    assert lab.gate(pr).returncode == (1 if new_level in ("critico", "alto") else 0)
    every_level = lab.gate(pr, "--fail-on", "critico,alto,medio,basso")
    assert every_level.returncode == 1, every_level.stdout
    existing_levels = {found[e.rule_id]["level"] for e in prr.EXPECTED if e.state == "existing"}
    assert existing_levels & {"critico", "alto"}  # c'erano esistenti gravi, e non hanno bloccato


def test_the_sarif_carries_the_baseline_state(pr: CliResult) -> None:
    """ADR-0025: `updated` per un esistente che ha cambiato posizione, `absent` per un risolto."""
    assert pr.out_dir is not None
    results = json.loads((pr.out_dir / "code-analyzer.sarif").read_text())["runs"][0]["results"]
    states = {r["ruleId"]: r["baselineState"] for r in results if r["ruleId"].startswith("B")}
    sarif_state = {"new": "new", "resolved": "absent"}
    expected = {
        e.rule_id: sarif_state.get(e.state) or ("updated" if e.name in ("moved", "renamed")
                                               else "unchanged")
        for e in prr.EXPECTED
    }  # fmt: skip
    assert states == expected
    assert len(pr.report["baseline"]["updated"]) == 2


def test_a_pr_cannot_weaken_the_gate_from_its_configuration(lab: PrLab, pr: CliResult) -> None:
    weakened = lab.pr_scan(lab.repo.weaken_head, "weaken")
    assert weakened.returncode == 0, weakened.stderr
    report = weakened.report
    assert "config-changed-in-pr" in codes(report)
    assert report["gate"]["effective_mode"] == "new-findings-only"
    assert report["effective_config"]["paths"]["exclude"] == []
    runs = [(p["name"], p["outcome"]) for p in report["plugins"]]
    assert runs == [("bandit", "ok")]  # la PR non lo spegne
    new = next(e for e in prr.EXPECTED if e.state == "new")
    assert by_rule(report)[new.rule_id]["baseline_state"] == "new"  # file non escluso
    for flags in ((), ("--fail-on", "critico,alto,medio,basso")):
        assert lab.gate(weakened, *flags).returncode == lab.gate(pr, *flags).returncode


def test_a_baseline_of_another_commit_is_rejected(lab: PrLab) -> None:
    root = lab.checkout(lab.repo.pr_head, "wrong-base")
    result = lab.scan(root, "wrong-base", "--pr", "--base", lab.repo.main_head,
                      "--baseline", str(lab.baseline))  # fmt: skip
    assert result.returncode == 0, result.stderr
    baseline = result.report["baseline"]
    assert (baseline["status"], baseline["reason"]) == ("rejected", "baseline-commit-mismatch")
    assert result.report["gate"]["effective_mode"] == "all"


def test_the_durations_are_recorded(pr: CliResult) -> None:
    assert pr.seconds > 0
    assert "T-04 pr" in DURATIONS
