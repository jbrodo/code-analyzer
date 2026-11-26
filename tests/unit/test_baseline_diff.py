"""K-16 (lettura della baseline) e K-17 (confronto con la baseline), ADR-0025."""

from pathlib import Path
from typing import Any

import pytest
from builders import finding, plugin, report

from ca_core.fakes import InMemorySourceReader
from ca_core.models import CodeAnalyzerConfig
from ca_core.models.finding import BaselineState, Category, Level
from ca_core.models.scan_report import (
    BaselineSourceKind,
    BaselineStatus,
    PluginRun,
    ScanReport,
)
from ca_core.pipeline.baseline import MAX_BASELINE_BYTES, load_baseline
from ca_core.pipeline.diff_baseline import diff_baseline
from ca_core.ports import BaselineLookup, BaselineOutcome
from ca_core.sarif import aggregate_sarif
from ca_core.schema_validation import SchemaStore

BASE = "a" * 40
WORKSPACE = "/work/repo"
LOCATION = "/ci/base/report.json"
KEY = "sha256:" + "9" * 64
HEAD = CodeAnalyzerConfig.model_validate({"version": 1})


def base_report(findings: list | None = None, **kv: Any) -> ScanReport:
    data: dict[str, Any] = {
        "repository": {"name": "repo", "commit": BASE, "history": "full"},
        "effective_config": {"version": 1, "paths": {"exclude": ["dist"]}},
    }
    return report(findings, **{**data, **kv})


def reader_with(content: bytes | ScanReport, location: str = LOCATION) -> InMemorySourceReader:
    data = content if isinstance(content, bytes) else content.model_dump_json().encode()
    directory, _, name = location.rpartition("/")
    return InMemorySourceReader({directory: {name: data}})


def found(location: str = LOCATION) -> BaselineLookup:
    return BaselineLookup(
        outcome=BaselineOutcome.FOUND, location=location, source=BaselineSourceKind.CI_ARTIFACT
    )


def load(content: bytes | ScanReport, *, lookup: BaselineLookup | None = None, **kw: Any):
    return load_baseline(
        lookup or found(),
        base_commit=kw.pop("base_commit", BASE),
        workspace=kw.pop("workspace", WORKSPACE),
        head_config=kw.pop("head_config", HEAD),
        reader=reader_with(content),
        **kw,
    )


def codes(loaded: Any) -> list[str]:
    return [w.code for w in loaded.warnings]


# --- K-16 --------------------------------------------------------------------------------------


def test_a_valid_baseline_brings_its_own_configuration() -> None:
    loaded = load(base_report())
    assert loaded.status is BaselineStatus.VALID and loaded.source is BaselineSourceKind.CI_ARTIFACT
    assert loaded.config.paths.exclude == ["dist"]
    assert codes(loaded) == ["config-changed-in-pr"]
    assert loaded.warnings[0].subject == "paths"  # solo le sezioni cambiate, mai i valori


def test_an_identical_configuration_gives_no_warning() -> None:
    same = CodeAnalyzerConfig.model_validate({"version": 1, "paths": {"exclude": ["dist"]}})
    assert codes(load(base_report(), head_config=same)) == []


@pytest.mark.parametrize("lookup", [None, BaselineLookup(outcome=BaselineOutcome.MISSING)])
def test_without_a_baseline_the_pr_configuration_applies_and_the_scan_goes_on(
    lookup: BaselineLookup | None,
) -> None:
    loaded = load_baseline(
        lookup, base_commit=BASE, workspace=WORKSPACE, head_config=HEAD, reader=reader_with(b"")
    )
    assert loaded.status is BaselineStatus.MISSING and loaded.config is HEAD
    assert codes(loaded) == ["baseline-missing", "pr-config-from-head"]


@pytest.mark.parametrize(
    ("location", "reason"),
    [
        ("/work/repo/base.json", "baseline-inside-workspace"),
        ("/work/repo/sub/../base.json", "baseline-inside-workspace"),
        ("/work/repo/../repo/base.json", "baseline-inside-workspace"),
    ],
)
def test_a_baseline_inside_the_analysed_directory_is_refused_unread(
    location: str, reason: str
) -> None:
    class Boom(InMemorySourceReader):
        def read_file(self, root: str, path: str, max_bytes: int) -> bytes:
            raise AssertionError("non va letta")

    loaded = load_baseline(
        found(location), base_commit=BASE, workspace=WORKSPACE, head_config=HEAD, reader=Boom()
    )
    assert (loaded.status, loaded.reason) == (BaselineStatus.REJECTED, reason)
    assert loaded.config is HEAD and "pr-config-from-head" in codes(loaded)


def test_a_sibling_directory_with_the_same_prefix_is_not_inside() -> None:
    location = "/work/repo2/base.json"
    loaded = load_baseline(
        found(location),
        base_commit=BASE,
        workspace=WORKSPACE,
        head_config=HEAD,
        reader=reader_with(base_report(), location),
    )
    assert loaded.status is BaselineStatus.VALID


@pytest.mark.parametrize(
    ("content", "reason"),
    [
        (b"", "baseline-invalid"),
        (b"{not json", "baseline-invalid"),
        (b'{"version": 1}', "baseline-invalid"),
        (b"[]", "baseline-invalid"),
    ],
)
def test_a_file_that_is_not_a_valid_report_is_rejected(content: bytes, reason: str) -> None:
    loaded = load(content)
    assert (loaded.status, loaded.reason) == (BaselineStatus.REJECTED, reason)


def test_an_unreadable_or_oversized_file_is_rejected() -> None:
    assert load(base_report(), lookup=found("/ci/other/none.json")).reason == "baseline-unreadable"
    assert load(base_report(), max_bytes=10).reason == "baseline-unreadable"
    assert MAX_BASELINE_BYTES > 10_000_000


def test_a_baseline_of_another_commit_is_rejected() -> None:
    assert load(base_report(), base_commit="b" * 40).reason == "baseline-commit-mismatch"
    no_commit = base_report(repository={"name": "repo", "history": "absent"})
    assert load(no_commit).reason == "baseline-commit-mismatch"


def test_a_pr_report_is_not_a_baseline() -> None:
    pr = base_report(scan={"kind": "pr", "base_commit": "c" * 40})
    assert load(pr).reason == "baseline-not-full"


def test_a_partial_baseline_is_valid_with_a_warning_naming_the_failed_plugins() -> None:
    failed = plugin("trivy", outcome="failed", failure="timeout")
    loaded = load(base_report(status="partial", plugins=[plugin(), failed]))
    assert loaded.status is BaselineStatus.VALID and "baseline-partial" in codes(loaded)
    assert next(w for w in loaded.warnings if w.code == "baseline-partial").subject == "trivy"


def test_a_baseline_without_configuration_falls_back_to_the_pr_one() -> None:
    loaded = load(base_report(effective_config=None))
    assert loaded.status is BaselineStatus.VALID and loaded.config is HEAD
    assert codes(loaded) == ["baseline-without-config"]


# --- K-17 --------------------------------------------------------------------------------------


def run(*names: str, failed: tuple[str, ...] = ()) -> list[PluginRun]:
    runs = [plugin(n) for n in names] + [
        plugin(n, outcome="failed", failure="timeout") for n in failed
    ]
    return [PluginRun.model_validate(r) for r in runs]


def diff(before: list, now: list, current: list[PluginRun] | None = None, **kv: Any):
    loaded = load(base_report(before, **kv))
    assert loaded.status is BaselineStatus.VALID
    return diff_baseline(now, current or run("bandit"), loaded)


def states(result: Any) -> dict[str, BaselineState | None]:
    return {f.rule_id: f.baseline_state for f in result.findings}


def test_new_existing_and_resolved_by_fingerprint() -> None:
    kept, fixed, added = finding("k"), finding("f"), finding("n")
    result = diff([kept, fixed], [kept, added])
    assert states(result) == {"r-k": BaselineState.EXISTING, "r-n": BaselineState.NEW}
    b = result.baseline
    assert (b.status, b.commit, b.new, b.existing, b.not_evaluated) == (
        BaselineStatus.VALID,
        BASE,
        1,
        1,
        0,
    )
    assert [(r.fingerprint, r.rule_id, r.path) for r in b.resolved] == [
        (fixed.fingerprint, "r-f", "app/run.py")
    ]


def test_a_finding_moved_to_another_line_of_the_same_file_is_existing_and_updated() -> None:
    old = finding("m")
    moved = old.model_copy(update={"location": old.location.model_copy(update={"start_line": 40})})
    result = diff([old], [moved])
    assert states(result) == {"r-m": BaselineState.EXISTING}
    assert result.baseline.updated == [old.fingerprint] and result.findings[0].previous_path is None


def test_a_level_change_is_updated_but_stays_existing() -> None:
    result = diff([finding("l", level=Level.MEDIUM)], [finding("l", level=Level.CRITICAL)])
    assert result.baseline.updated == [finding("l").fingerprint]
    assert result.baseline.new == 0 and result.baseline.existing == 1


def test_an_unchanged_finding_is_not_updated() -> None:
    result = diff([finding("u", level=Level.LOW)], [finding("u", level=Level.LOW)])
    assert result.baseline.updated == []


def test_a_failed_plugin_makes_its_baseline_findings_not_evaluated_instead_of_resolved() -> None:
    gone_semgrep = finding("s", tool="semgrep")
    gone_bandit = finding("b", tool="bandit")
    result = diff(
        [gone_semgrep, gone_bandit],
        [],
        run("bandit", failed=("semgrep",)),
        plugins=[plugin("bandit"), plugin("semgrep")],
    )
    assert [r.rule_id for r in result.baseline.resolved] == ["r-b"]
    assert result.baseline.not_evaluated == 1


def test_policy_findings_depend_on_every_plugin() -> None:
    policy = finding("p", tool="ca-core", category=Category.LICENSE)
    ok = diff([policy], [], run("bandit", "syft"), plugins=[plugin("bandit"), plugin("syft")])
    assert [r.rule_id for r in ok.baseline.resolved] == ["r-p"]
    bad = diff(
        [policy], [], run("bandit", failed=("syft",)), plugins=[plugin("bandit"), plugin("syft")]
    )
    assert bad.baseline.resolved == [] and bad.baseline.not_evaluated == 1


def test_a_plugin_that_did_not_run_now_is_not_evaluated() -> None:
    both = [plugin("bandit"), plugin("semgrep")]
    result = diff([finding("x", tool="semgrep")], [], run("bandit"), plugins=both)
    assert result.baseline.resolved == [] and result.baseline.not_evaluated == 1


def moved_pair(key: str | None = KEY, new_path: str = "app/new.py", **kw: Any):
    old = finding("r", path="app/old.py", pathless_key=key)
    new = finding("r", path=new_path, pathless_key=key, **kw)
    return old, new.model_copy(update={"fingerprint": "sha256:" + "5" * 64, "id": "x"})


def test_a_renamed_file_pairs_the_resolved_and_the_new_one() -> None:
    old, new = moved_pair()
    result = diff([old], [new])
    f = result.findings[0]
    assert (f.baseline_state, f.previous_path) == (BaselineState.EXISTING, "app/old.py")
    b = result.baseline
    assert (b.new, b.existing, b.resolved) == (0, 1, []) and b.updated == [new.fingerprint]


@pytest.mark.parametrize("case", ["no-key", "same-path", "two-new", "two-old", "path-none"])
def test_the_second_pass_pairs_only_unambiguous_cases_on_different_paths(case: str) -> None:
    old, new = moved_pair(None if case == "no-key" else KEY)
    olds, news = [old], [new]
    if case == "same-path":
        news = [new.model_copy(update={"location": old.location})]
    if case == "two-new":
        news.append(new.model_copy(update={"fingerprint": "sha256:" + "6" * 64, "id": "y"}))
    if case == "two-old":
        olds.append(old.model_copy(update={"fingerprint": "sha256:" + "7" * 64, "id": "z"}))
    if case == "path-none":
        news = [new.model_copy(update={"location": new.location.model_copy(update={"path": None})})]
    result = diff(olds, news)
    assert all(f.baseline_state is BaselineState.NEW for f in result.findings)
    assert result.baseline.existing == 0 and len(result.baseline.resolved) == len(olds)


def test_an_unevaluable_old_finding_is_never_paired() -> None:
    old = finding("r", tool="semgrep", path="app/old.py", pathless_key=KEY)
    new = finding("r", tool="semgrep", path="app/new.py", pathless_key=KEY)
    new = new.model_copy(update={"fingerprint": "sha256:" + "5" * 64, "id": "x"})
    result = diff([old], [new], run(failed=("semgrep",)), plugins=[plugin("semgrep")])
    assert result.findings[0].baseline_state is BaselineState.NEW
    assert result.baseline.not_evaluated == 1


@pytest.mark.parametrize("status", [BaselineStatus.MISSING, BaselineStatus.REJECTED])
def test_without_a_valid_baseline_no_finding_has_a_state(status: BaselineStatus) -> None:
    lookup = None if status is BaselineStatus.MISSING else found("/work/repo/b.json")
    loaded = load_baseline(
        lookup, base_commit=BASE, workspace=WORKSPACE, head_config=HEAD, reader=reader_with(b"")
    )
    result = diff_baseline([finding("a")], run("bandit"), loaded)
    assert result.findings[0].baseline_state is None
    assert result.baseline.status is status and result.baseline.new == 0


def test_the_diff_result_forms_a_valid_pr_report() -> None:
    kept, fixed, added = finding("k"), finding("f"), finding("n")
    result = diff([kept, fixed], [kept, added])
    full = report(
        result.findings,
        scan={"kind": "pr", "base_commit": BASE},
        baseline=result.baseline.model_dump(mode="json"),
    )
    assert ScanReport.model_validate_json(full.model_dump_json()) == full


# --- SARIF aggregato ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def store() -> SchemaStore:
    return SchemaStore(Path(__file__).resolve().parents[2] / "schemas" / "vendor")


def test_the_aggregate_sarif_carries_the_baseline_state_and_the_absent_results(
    store: SchemaStore,
) -> None:
    import json

    kept, fixed, added = finding("k"), finding("f"), finding("n", level=Level.HIGH)
    moved = kept.model_copy(update={"location": kept.location.model_copy(update={"start_line": 9})})
    result = diff([kept, fixed], [moved, added])
    full = report(
        result.findings,
        scan={"kind": "pr", "base_commit": BASE},
        baseline=result.baseline.model_dump(mode="json"),
    )
    results = json.loads(aggregate_sarif(full, store))["runs"][0]["results"]
    by_rule = {r["ruleId"]: r for r in results}
    assert by_rule["r-k"]["baselineState"] == "updated"
    assert by_rule["r-n"]["baselineState"] == "new"
    absent = by_rule["r-f"]
    assert absent["baselineState"] == "absent" and "properties" not in absent
    assert absent["partialFingerprints"]["codeAnalyzer/v1"] == fixed.fingerprint


def test_without_a_baseline_the_sarif_has_no_baseline_state(store: SchemaStore) -> None:
    import json

    results = json.loads(aggregate_sarif(report([finding("a")]), store))["runs"][0]["results"]
    assert all("baselineState" not in r for r in results)


def test_an_unchanged_existing_finding_is_unchanged_in_the_sarif(store: SchemaStore) -> None:
    import json

    same = finding("k")
    result = diff([same], [same])
    full = report(
        result.findings,
        scan={"kind": "pr", "base_commit": BASE},
        baseline=result.baseline.model_dump(mode="json"),
    )
    (only,) = json.loads(aggregate_sarif(full, store))["runs"][0]["results"]
    assert only["baselineState"] == "unchanged"
