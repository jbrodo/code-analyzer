"""K-18 e L-01: `scan --pr --base --baseline` e il gate sui finding nuovi (ADR-0025)."""

import json
import shutil
from pathlib import Path
from typing import Any

import pytest
from test_cli_scan_gate import REPORT, Env, load, sarif_doc

from ca_cli.main import main
from ca_core.fakes import FakePluginExecutor

BASE = "a" * 40
HEAD = "b" * 40
ALL_LEVELS = "[critico, alto, medio, basso]"
CONFIG = f"version: 1\ngate:\n  mode: new-findings-only\n  block_on: {ALL_LEVELS}\n"


@pytest.fixture
def env(tmp_path: Path) -> Env:
    return Env(tmp_path)


def with_git(env: Env, sha: str) -> None:
    git = env.repo / ".git"
    git.mkdir(exist_ok=True)
    (git / "HEAD").write_text(sha + "\n")


def sarif_with(*rules: str) -> bytes:
    document = json.loads(sarif_doc())
    first = document["runs"][0]["results"][0]
    document["runs"][0]["results"] = [
        {**first, "ruleId": rule, "properties": {"tool_severity": "HIGH"}} for rule in rules
    ]
    return json.dumps(document).encode()


def run_scan(env: Env, *flags: str, rules: tuple[str, ...] = ("B602",)) -> int:
    (env.plugin_out / "results.sarif").write_bytes(sarif_with(*rules))
    executor = FakePluginExecutor({"bandit": env.ok()})
    return env.scan(env.context(executor), *flags)


def make_baseline(env: Env, config: str = CONFIG) -> Path:
    """Scansione completa del commit base; il report si sposta fuori dal repository."""
    (env.repo / ".code-analyzer.yml").write_text(config)
    with_git(env, BASE)
    assert run_scan(env) == 0
    target = env.tmp / "baseline" / "report.json"
    target.parent.mkdir()
    shutil.copy(env.out / REPORT, target)
    shutil.rmtree(env.out)
    with_git(env, HEAD)
    return target


def pr(env: Env, baseline: Path | None, *extra: str, rules: tuple[str, ...] = ("B602",)) -> int:
    flags = ["--pr", "--base", BASE, *extra]
    if baseline is not None:
        flags += ["--baseline", str(baseline)]
    return run_scan(env, *flags, rules=rules)


def gate(env: Env, *flags: str) -> int:
    return main(["gate", "--report", str(env.out / REPORT), *flags])


def codes(report: dict[str, Any]) -> list[str]:
    return [w["code"] for w in report["warnings"]]


def test_a_pr_with_the_same_findings_passes_the_new_findings_only_gate(env: Env) -> None:
    baseline = make_baseline(env)
    assert pr(env, baseline, "--pull-request", "12") == 0
    report = load(env)
    assert report["scan"] == {"kind": "pr", "base_commit": BASE, "pull_request": 12}
    assert report["baseline"]["status"] == "valid" and report["baseline"]["source"] == "ci-artifact"
    assert (report["baseline"]["new"], report["baseline"]["existing"]) == (0, 1)
    assert report["gate"]["effective_mode"] == "new-findings-only"
    assert [f["baseline_state"] for f in report["findings"]] == ["existing"]
    assert "new-findings-only-as-all" not in codes(report)
    assert gate(env) == 0


def test_a_new_finding_blocks_and_an_existing_one_does_not(env: Env) -> None:
    baseline = make_baseline(env)
    assert pr(env, baseline, rules=("B602", "B603")) == 0
    report = load(env)
    states = {f["rule_id"]: f["baseline_state"] for f in report["findings"]}
    assert states == {"B602": "existing", "B603": "new"}
    assert gate(env) == 1


def test_a_fixed_finding_is_resolved_and_the_gate_passes(env: Env) -> None:
    baseline = make_baseline(env)
    assert pr(env, baseline, rules=()) == 0
    report = load(env)
    assert report["findings"] == [] and len(report["baseline"]["resolved"]) == 1
    assert gate(env) == 0


def test_the_sarif_carries_the_baseline_state(env: Env) -> None:
    baseline = make_baseline(env)
    assert pr(env, baseline, rules=("B602", "B603")) == 0
    results = json.loads((env.out / "code-analyzer.sarif").read_text())["runs"][0]["results"]
    assert {r["ruleId"]: r["baselineState"] for r in results} == {
        "B602": "unchanged",
        "B603": "new",
    }


def test_without_a_baseline_everything_counts_and_the_scan_says_so(env: Env) -> None:
    (env.repo / ".code-analyzer.yml").write_text(CONFIG)
    with_git(env, HEAD)
    assert pr(env, None) == 0
    report = load(env)
    assert {"baseline-missing", "pr-config-from-head", "new-findings-only-as-all"} <= set(
        codes(report)
    )
    assert report["baseline"] == {**report["baseline"], "status": "missing"}
    assert report["gate"]["effective_mode"] == "all"
    assert all("baseline_state" not in f or f["baseline_state"] is None for f in report["findings"])
    assert gate(env) == 1


def test_a_pr_cannot_weaken_the_gate_by_editing_the_configuration(env: Env) -> None:
    """ADR-0025 §5: il file della PR si legge solo per confrontarlo."""
    baseline = make_baseline(env)
    (env.repo / ".code-analyzer.yml").write_text(
        "version: 1\ngate:\n  mode: all\n  block_on: []\npaths:\n  exclude: ['*.py']\n"
    )
    assert pr(env, baseline, rules=("B602", "B603")) == 0
    report = load(env)
    assert "config-changed-in-pr" in codes(report)
    assert report["gate"]["effective_mode"] == "new-findings-only"
    assert report["effective_config"]["paths"]["exclude"] == []
    assert [f["baseline_state"] for f in report["findings"]] == ["existing", "new"]
    assert gate(env) == 1


def test_fail_on_stays_the_strongest_threshold(env: Env) -> None:
    baseline = make_baseline(env)
    assert pr(env, baseline) == 0
    assert gate(env, "--fail-on", "") == 0
    assert gate(env, "--fail-on", "alto,critico,medio,basso") == 0  # nessun nuovo: passa lo stesso


@pytest.mark.parametrize("inside", ["report.json", "sub/report.json"])
def test_a_baseline_inside_the_repository_is_refused_but_the_scan_goes_on(
    env: Env, inside: str
) -> None:
    baseline = make_baseline(env)
    target = env.repo / inside
    target.parent.mkdir(exist_ok=True)
    shutil.copy(baseline, target)
    target.chmod(0o644)  # i plugin girano come altro utente: un file privato sarebbe un avviso
    assert pr(env, target) == 0
    report = load(env)
    assert report["baseline"]["status"] == "rejected"
    assert report["baseline"]["reason"] == "baseline-inside-workspace"
    assert {"baseline-inside-workspace", "pr-config-from-head"} <= set(codes(report))
    assert gate(env) == 1


def test_a_baseline_of_another_commit_is_rejected(env: Env) -> None:
    baseline = make_baseline(env)
    assert run_scan(env, "--pr", "--base", "c" * 40, "--baseline", str(baseline)) == 0
    assert load(env)["baseline"]["reason"] == "baseline-commit-mismatch"


def test_a_baseline_source_is_recorded_as_given(env: Env) -> None:
    baseline = make_baseline(env)
    assert pr(env, baseline, "--baseline-source", "base-scan") == 0
    assert load(env)["baseline"]["source"] == "base-scan"


def test_a_full_scan_has_no_baseline_and_new_findings_only_counts_everything(env: Env) -> None:
    (env.repo / ".code-analyzer.yml").write_text(CONFIG)
    assert run_scan(env) == 0
    report = load(env)
    assert report["scan"]["kind"] == "full" and report.get("baseline") is None
    assert "new-findings-only-as-all" in codes(report)
    assert gate(env) == 1


@pytest.mark.parametrize(
    "flags",
    [
        ["--pr"],
        ["--base", BASE],
        ["--baseline", "x.json"],
        ["--pull-request", "3"],
        ["--pr", "--base", "abc"],
        ["--pr", "--base", BASE.upper()],
        ["--pr", "--base", BASE, "--pull-request", "0"],
        ["--pr", "--base", BASE, "--pull-request", "-1"],
        ["--pr", "--base", BASE, "--pull-request", "x"],
        ["--pr", "--base", BASE, "--pull-request", "99999999999"],
        ["--pr", "--base", BASE, "--baseline-source", "email"],
    ],
)
def test_pr_flags_are_checked_before_anything_runs(env: Env, flags: list[str]) -> None:
    with pytest.raises(SystemExit) as info:
        env.scan(env.context(FakePluginExecutor({})), *flags)
    assert info.value.code == 2 and not env.out.exists()
