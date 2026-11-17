"""L-04 (`scan`) e L-05 (`gate`) con porte finte e disco reale in `tmp_path`. Nessun Docker."""

import copy
import json
from pathlib import Path
from typing import Any

import pytest

from ca_cli.composition import Context, vendor_schema_store
from ca_cli.main import main
from ca_core.fakes import FakePluginExecutor, FixedClock
from ca_core.models import PackagedPluginManifest
from ca_core.models.plugin_manifest import _EXAMPLE as BASE
from ca_core.ports import (
    FeedsSyncRequest,
    Isolation,
    PluginRunResult,
    RunOutcome,
    ScanAborted,
    Signature,
)
from ca_plugins.runner import RuntimeUnavailable
from ca_plugins.source import LocalSourceReader

DIGEST = "sha256:" + "a" * 64
REPORT = "code-analyzer.report.json"
SARIF = "code-analyzer.sarif"
FEEDS = {
    "sync_command": ["sync"],
    "ecosystems": ["PyPI"],
    "mount": "/feeds",
    "sync_timeout": "60s",
}


def manifest(name: str = "bandit", **kv: Any) -> PackagedPluginManifest:
    data = {
        **copy.deepcopy(BASE),
        "name": name,
        "image": f"registry.invalid/ca/{name}:1.0.0@{DIGEST}",
        "languages": [],
        **kv,
    }
    return PackagedPluginManifest.model_validate(data)


def sarif_doc() -> bytes:
    region = {"startLine": 1, "startColumn": 1, "endLine": 1, "endColumn": 5}
    result = {
        "ruleId": "B602",
        "message": {"text": "m"},
        "level": "warning",
        "locations": [
            {"physicalLocation": {"artifactLocation": {"uri": "app.py"}, "region": region}}
        ],
        "properties": {"tool_severity": "HIGH"},
    }
    run = {"tool": {"driver": {"name": "bandit"}}, "results": [result]}
    return json.dumps({"version": "2.1.0", "runs": [run]}).encode()


class SyncingExecutor(FakePluginExecutor):
    def sync_feeds(self, request: FeedsSyncRequest) -> PluginRunResult:
        self.syncs.append(request)
        (Path(request.snapshot_dir) / "db.json").write_text("{}")
        return self.ok(request.snapshot_dir)


class Env:
    def __init__(self, tmp: Path) -> None:
        self.repo = tmp / "repo"
        self.repo.mkdir()
        (self.repo / "app.py").write_text("import os\n")
        self.out = tmp / "reports"
        self.tmp = tmp
        self.plugin_out = tmp / "plugin-out"
        self.plugin_out.mkdir()
        (self.plugin_out / "results.sarif").write_bytes(sarif_doc())

    def context(
        self,
        executor: FakePluginExecutor,
        manifests: list[PackagedPluginManifest] | None = None,
    ) -> Context:
        chosen = [manifest()] if manifests is None else manifests
        return Context(
            executor=executor,
            source=LocalSourceReader(),
            clock=FixedClock(),
            manifests=lambda: chosen,
            schemas=vendor_schema_store,
            feeds_cache=self.tmp / "cache",
        )

    def ok(self) -> PluginRunResult:
        return FakePluginExecutor.ok(str(self.plugin_out))

    def scan(self, context: Context, *flags: str) -> int:
        argv = ["scan", str(self.repo), "--output-dir", str(self.out), *flags]
        return main(argv, context=context)


@pytest.fixture
def env(tmp_path: Path) -> Env:
    return Env(tmp_path)


def load(env: Env) -> dict[str, Any]:
    data: dict[str, Any] = json.loads((env.out / REPORT).read_text())
    return data


def test_scan_writes_both_artifacts_and_only_those(
    env: Env, capsys: pytest.CaptureFixture[str]
) -> None:
    executor = FakePluginExecutor({"bandit": env.ok()})
    assert env.scan(env.context(executor)) == 0
    assert sorted(p.name for p in env.out.iterdir()) == [REPORT, SARIF]  # niente scan-report.json
    report = load(env)
    assert report["status"] == "complete" and report["repository"]["history"] == "absent"
    assert [f["rule_id"] for f in report["findings"]] == ["B602"]
    assert "finding: 1" in capsys.readouterr().out


def test_format_only_governs_stdout(env: Env, capsys: pytest.CaptureFixture[str]) -> None:
    executor = FakePluginExecutor({"bandit": env.ok()})
    assert env.scan(env.context(executor), "--format", "json") == 0
    out = capsys.readouterr().out
    assert json.loads(out) == load(env) and (env.out / SARIF).is_file()
    assert env.scan(env.context(executor), "--format", "sarif") == 0
    assert json.loads(capsys.readouterr().out)["version"] == "2.1.0"
    assert (env.out / REPORT).is_file()


def test_failed_plugin_is_partial_exit_0_and_gate_says_2(env: Env) -> None:
    failed = PluginRunResult(
        outcome=RunOutcome.FAILED,
        exit_code=3,
        isolation=Isolation.HARDENED_CONTAINER,
        signature=Signature.VERIFIED,
        duration_seconds=0,
        output_dir=None,
    )
    assert env.scan(env.context(FakePluginExecutor({"bandit": failed}))) == 0
    report = load(env)
    assert report["status"] == "partial"
    assert [f["category"] for f in report["findings"]] == ["health"]
    gate = ["gate", "--report", str(env.out / REPORT)]
    assert main(gate) == 2
    assert main([*gate, "--allow-partial"]) == 0  # health non è un livello bloccante


def test_no_plugin_run_is_partial_with_warning(env: Env) -> None:
    assert env.scan(env.context(FakePluginExecutor(), manifests=[])) == 0
    report = load(env)
    assert report["status"] == "partial"
    assert "no-plugin-run" in [w["code"] for w in report["warnings"]]


def test_min_isolation_stops_before_any_container(
    env: Env, capsys: pytest.CaptureFixture[str]
) -> None:
    executor = FakePluginExecutor({"bandit": env.ok()})
    assert env.scan(env.context(executor), "--min-isolation", "gvisor") == 2
    assert executor.runs == [] and not env.out.exists()
    err = capsys.readouterr().err
    assert "isolamento richiesto" in err and "Traceback" not in err
    gvisor = FakePluginExecutor({"bandit": env.ok()}, isolation=Isolation.GVISOR)
    assert env.scan(env.context(gvisor), "--min-isolation", "gvisor") == 0


def test_repository_cannot_set_isolation_or_images(env: Env) -> None:
    for key in ("min_isolation", "image", "network", "signature"):
        (env.repo / ".code-analyzer.yml").write_text(f"version: 1\n{key}: x\n")
        executor = FakePluginExecutor({"bandit": env.ok()})
        assert env.scan(env.context(executor)) == 2
        assert executor.runs == [] and not env.out.exists()


@pytest.mark.parametrize("error", [ScanAborted("firma"), RuntimeUnavailable("nessun runtime")])
def test_aborts_exit_2_without_report_or_traceback(
    env: Env, error: Exception, capsys: pytest.CaptureFixture[str]
) -> None:
    def boom(_request: object) -> PluginRunResult:
        raise error

    executor = FakePluginExecutor({"bandit": boom})
    assert env.scan(env.context(executor)) == 2
    assert not env.out.exists()
    assert "Traceback" not in capsys.readouterr().err


def test_missing_directory_exits_2(env: Env) -> None:
    ctx = env.context(FakePluginExecutor())
    assert main(["scan", str(env.tmp / "nope"), "--output-dir", str(env.out)], context=ctx) == 2
    assert not env.out.exists()


def test_config_disable_exclude_and_inert_sections(env: Env) -> None:
    (env.repo / ".code-analyzer.yml").write_text(
        "version: 1\nplugins:\n  disable: [bandit]\nscoring:\n  variant: A\nagents: {}\n"
    )
    executor = FakePluginExecutor({"bandit": env.ok()})
    assert env.scan(env.context(executor)) == 0
    report = load(env)
    assert report["disabled_plugins"] == ["bandit"] and report["plugins"] == []
    assert report["inert_sections"] == ["agents"] and executor.runs == []


def test_git_commit_and_history_from_files_only(env: Env) -> None:
    sha = "ab" * 20
    git = env.repo / ".git"
    (git / "refs" / "heads").mkdir(parents=True)
    (git / "HEAD").write_text("ref: refs/heads/main\n")
    (git / "refs" / "heads" / "main").write_text(sha + "\n")
    assert env.scan(env.context(FakePluginExecutor({"bandit": env.ok()}))) == 0
    repo = load(env)["repository"]
    assert (repo["commit"], repo["history"]) == (sha, "full")
    (git / "shallow").write_text(sha + "\n")
    (git / "HEAD").write_text("ref: refs/../../etc/passwd\n")  # ref ostile: nessun commit
    assert env.scan(env.context(FakePluginExecutor({"bandit": env.ok()}))) == 0
    repo = load(env)["repository"]
    assert (repo["commit"], repo["history"]) == (None, "shallow")


def test_feeds_snapshot_is_passed_and_recorded(env: Env) -> None:
    plugin = manifest("osv", feeds=FEEDS)
    executor = SyncingExecutor({"osv": env.ok()})
    assert env.scan(env.context(executor, [plugin])) == 0
    assert len(executor.syncs) == 1 and executor.runs[0].feeds_snapshot is not None
    feed = load(env)["plugins"][0]["feed"]
    assert feed["origin"] == "public" and feed["sync_failed"] is False
    # secondo lancio: snapshot fresco, nessuna nuova sincronizzazione
    assert env.scan(env.context(executor, [plugin])) == 0
    assert len(executor.syncs) == 1


def test_offline_without_snapshot_fails_plugin_without_container(env: Env) -> None:
    executor = SyncingExecutor({"osv": env.ok()})
    assert env.scan(env.context(executor, [manifest("osv", feeds=FEEDS)]), "--offline") == 0
    assert executor.runs == [] and executor.syncs == []
    report = load(env)
    assert report["status"] == "partial" and report["plugins"][0]["outcome"] == "failed"
    assert [f["category"] for f in report["findings"]] == ["health"]


def test_offline_uses_stale_snapshot_with_warning(env: Env) -> None:
    plugin = manifest("osv", feeds=FEEDS)
    executor = SyncingExecutor({"osv": env.ok()})
    ctx = env.context(executor, [plugin])
    assert env.scan(ctx) == 0
    ctx = Context(
        executor=executor,
        source=ctx.source,
        clock=FixedClock(FixedClock().now().replace(year=2027)),
        manifests=ctx.manifests,
        schemas=ctx.schemas,
        feeds_cache=ctx.feeds_cache,
    )
    assert env.scan(ctx, "--offline") == 0
    report = load(env)
    assert "feeds-stale" in [w["code"] for w in report["warnings"]]
    assert len(executor.syncs) == 1 and report["plugins"][0]["outcome"] == "ok"


# --- gate ---------------------------------------------------------------------------------------


def test_gate_exit_codes_and_fail_on(env: Env, capsys: pytest.CaptureFixture[str]) -> None:
    env.scan(env.context(FakePluginExecutor({"bandit": env.ok()})))
    gate = ["gate", "--report", str(env.out / REPORT)]
    capsys.readouterr()
    assert main(gate) == 1  # B602 con tool_severity HIGH: livello alto, bloccante di default
    assert "bloccante" in capsys.readouterr().out
    assert main([*gate, "--fail-on", "critico"]) == 0
    assert main([*gate, "--fail-on", ""]) == 0
    assert main([*gate, "--fail-on", "alto,critico"]) == 1


def test_gate_prints_report_warnings_on_stderr_without_changing_the_exit(
    env: Env, capsys: pytest.CaptureFixture[str]
) -> None:
    """D2-09: una copertura ridotta resta visibile nel log anche a gate superato."""
    env.scan(env.context(FakePluginExecutor({"bandit": env.ok()})))
    path = env.out / REPORT
    report = json.loads(path.read_text())
    report["warnings"] = [
        {"code": "plugin-feeds-ecosystem-missing", "message": "m", "subject": "osv-scanner"},
        {"code": "plugin-feeds-ecosystem-missing", "message": "n", "subject": "osv-scanner"},
        {"code": "exception-expired", "message": "m", "subject": "testo \x1b[31mlibero"},
    ]
    path.write_text(json.dumps(report))
    capsys.readouterr()

    assert main(["gate", "--report", str(path), "--fail-on", ""]) == 0

    captured = capsys.readouterr()
    assert captured.err.splitlines() == [
        "avviso del report: exception-expired",
        "avviso del report: plugin-feeds-ecosystem-missing (osv-scanner) x2",
    ]
    assert "avviso del report" not in captured.out and "libero" not in captured.err


def test_gate_rejects_bad_input_with_exit_2(env: Env, tmp_path: Path) -> None:
    assert main(["gate", "--report", str(tmp_path / "missing.json")]) == 2
    bad = tmp_path / "bad.json"
    bad.write_text('{"version": 1}')
    assert main(["gate", "--report", str(bad)]) == 2
    bad.write_text("non json")
    assert main(["gate", "--report", str(bad)]) == 2
    for argv in (["gate", "--fail-on", "urgente"], ["gate", "--pr", "1"], ["gate", "--base", "x"]):
        with pytest.raises(SystemExit) as err:
            main(argv)
        assert err.value.code == 2


def test_report_name_has_one_source_of_truth() -> None:
    """ADR-0010 (R-09): `publish` scrive il nome pubblico, la CLI non rinomina."""
    from ca_cli import gate, scan
    from ca_core.pipeline import publish

    assert publish.REPORT_NAME == scan.REPORT_FILE == gate.DEFAULT_REPORT == REPORT
    assert publish.REPORT_NAME == "code-analyzer.report.json"


def test_publish_writes_the_public_name_without_any_rename(env: Env) -> None:
    from ca_cli.scan import _CapturingSink

    context = env.context(FakePluginExecutor({"bandit": env.ok()}))
    sink = _CapturingSink(context, str(env.out))
    sink.write("x.json", b"{}")
    assert sorted(sink.contents) == ["x.json"] and (env.out / "x.json").is_file()
