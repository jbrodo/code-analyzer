"""`notify` (ADR-0027): commento e check run dal report, con un trasporto finto (nessuna rete)."""

import json
from collections.abc import Mapping
from pathlib import Path
from typing import Any

import pytest
from builders import finding, report

from ca_cli.composition import Context, vendor_schema_store
from ca_cli.main import main
from ca_core.fakes import FakePluginExecutor, FixedClock
from ca_core.models.finding import BaselineState, Level
from ca_integrations.github import Response, TransportError
from ca_plugins.source import LocalSourceReader

TOKEN = "ghs_TOKEN-THAT-MUST-NEVER-APPEAR-0123456789"
SHA = "c" * 40
BASE = "a" * 40


class Recorder:
    def __init__(self, *replies: Response | Exception) -> None:
        self.replies = list(replies)
        self.calls: list[tuple[str, str, Mapping[str, str], bytes | None]] = []

    def request(
        self, method: str, url: str, headers: Mapping[str, str], body: bytes | None, timeout: float
    ) -> Response:
        self.calls.append((method, url, headers, body))
        reply = self.replies.pop(0) if self.replies else Response(200, {}, b"[]")
        if isinstance(reply, Exception):
            raise reply
        return reply


def ok(body: object = None, status: int = 200) -> Response:
    return Response(status, {}, json.dumps(body if body is not None else {"id": 7}).encode())


def context(transport: Recorder) -> Context:
    return Context(
        executor=FakePluginExecutor({}),
        source=LocalSourceReader(),
        clock=FixedClock(),
        schemas=vendor_schema_store,
        notify_transport=transport,
    )


def pr_report(tmp: Path, *, number: int | None = None) -> Path:
    items = [
        finding("n", level=Level.HIGH, baseline_state=BaselineState.NEW),
        finding("o", level=Level.HIGH, baseline_state=BaselineState.EXISTING),
    ]
    scan: dict[str, Any] = {"kind": "pr", "base_commit": BASE}
    if number:
        scan["pull_request"] = number
    data = report(
        items,
        gate={"mode": "new-findings-only", "effective_mode": "new-findings-only"},
        scan=scan,
        baseline={
            "status": "valid",
            "commit": BASE,
            "source": "ci-artifact",
            "new": 1,
            "existing": 1,
        },
    )
    path = tmp / "report.json"
    path.write_text(data.model_dump_json())
    return path


@pytest.fixture(autouse=True)
def clean_env(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in (
        "GITHUB_TOKEN",
        "GITHUB_REPOSITORY",
        "GITHUB_EVENT_PATH",
        "GITHUB_STEP_SUMMARY",
        "GITHUB_API_URL",
    ):
        monkeypatch.delenv(name, raising=False)


def notify(transport: Recorder, report_path: Path, *flags: str) -> int:
    argv = ["notify", "--provider", "github", "--report", str(report_path), *flags]
    return main(argv, context=context(transport))


def env(monkeypatch: pytest.MonkeyPatch, **values: str) -> None:
    for name, value in {"GITHUB_TOKEN": TOKEN, "GITHUB_REPOSITORY": "acme/shop", **values}.items():
        monkeypatch.setenv(name, value)


def test_comment_and_check_run_are_written_with_the_data_of_the_flags(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    env(monkeypatch)
    transport = Recorder(ok([]), ok({"id": 5}, 201), ok({"id": 9}, 201))
    code = notify(transport, pr_report(tmp_path), "--pull-request", "12", "--head-sha", SHA)
    assert code == 0
    (list_call, post_comment, post_check) = transport.calls
    assert list_call[0] == "GET" and "/repos/acme/shop/issues/12/comments" in list_call[1]
    assert post_comment[0] == "POST" and post_comment[1].endswith("/issues/12/comments")
    body = json.loads(post_comment[3] or b"")["body"]
    assert body.startswith("<!-- code-analyzer:1 -->") and "1 nuovi" in body and "r\\-o" not in body
    check = json.loads(post_check[3] or b"")
    assert (check["head_sha"], check["conclusion"]) == (SHA, "failure")
    out = capsys.readouterr()
    assert TOKEN not in out.out + out.err
    assert all(TOKEN not in str(call[3]) for call in transport.calls)


def test_the_pr_number_comes_from_the_report_then_from_the_event_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    event = tmp_path / "event.json"
    event.write_text(json.dumps({"pull_request": {"number": 33, "head": {"sha": SHA}}}))
    env(monkeypatch, GITHUB_EVENT_PATH=str(event))
    transport = Recorder(ok([]), ok({"id": 1}, 201), ok({"id": 2}, 201))
    assert notify(transport, pr_report(tmp_path)) == 0
    assert "/issues/33/comments" in transport.calls[0][1]
    assert json.loads(transport.calls[2][3] or b"")["head_sha"] == SHA
    transport = Recorder(ok([]), ok({"id": 1}, 201), ok({"id": 2}, 201))
    assert notify(transport, pr_report(tmp_path, number=44), "--head-sha", SHA) == 0
    assert "/issues/44/comments" in transport.calls[0][1]  # il report vince sull'evento


def test_an_existing_comment_of_the_expected_author_is_updated(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    env(monkeypatch)
    mine = {
        "id": 99,
        "user": {"login": "github-actions[bot]"},
        "body": "<!-- code-analyzer:1 --> x",
    }
    transport = Recorder(ok([mine]), ok({"id": 99}))
    assert notify(transport, pr_report(tmp_path), "--pull-request", "3", "--no-check-run") == 0
    assert [c[0] for c in transport.calls] == ["GET", "PATCH"]


def test_the_switches_turn_each_part_off(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    env(monkeypatch)
    transport = Recorder(ok({"id": 1}, 201))
    assert notify(transport, pr_report(tmp_path), "--no-comment", "--head-sha", SHA) == 0
    assert len(transport.calls) == 1 and transport.calls[0][1].endswith("/check-runs")


def test_a_missing_permission_degrades_to_the_job_summary_and_exits_zero(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    summary = tmp_path / "summary.md"
    env(monkeypatch, GITHUB_STEP_SUMMARY=str(summary))
    forbidden = Response(403, {}, b'{"message":"Resource not accessible by integration"}')
    transport = Recorder(forbidden, forbidden)
    code = notify(transport, pr_report(tmp_path), "--pull-request", "3", "--head-sha", SHA)
    assert code == 0
    assert "Code Analyzer" in summary.read_text()
    err = capsys.readouterr().err
    assert "non permesso" in err and "Resource not accessible" not in err


def test_a_forbidden_without_a_summary_still_exits_zero(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    env(monkeypatch)
    forbidden = Response(403, {}, b"{}")
    code = notify(Recorder(forbidden), pr_report(tmp_path), "--pull-request", "3", "--no-check-run")
    assert code == 0 and "nessun riepilogo" in capsys.readouterr().err


@pytest.mark.parametrize(
    "reply",
    [Response(500, {}, b"x"), Response(401, {}, b"x"), TransportError("down")],
)
def test_other_failures_exit_two_with_a_code_and_no_secret(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    reply: Response | Exception,
) -> None:
    env(monkeypatch)
    code = notify(Recorder(reply), pr_report(tmp_path), "--pull-request", "3", "--no-check-run")
    err = capsys.readouterr().err
    assert code == 2 and "notify: commento" in err and TOKEN not in err


def test_a_failed_comment_does_not_stop_the_check_run(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    env(monkeypatch)
    transport = Recorder(Response(500, {}, b"x"), ok({"id": 2}, 201))
    assert notify(transport, pr_report(tmp_path), "--pull-request", "3", "--head-sha", SHA) == 2
    assert len(transport.calls) == 2


@pytest.mark.parametrize(
    ("values", "flags", "message"),
    [
        ({"GITHUB_TOKEN": ""}, ["--pull-request", "3"], "GITHUB_TOKEN"),
        ({"GITHUB_REPOSITORY": "no-slash"}, ["--pull-request", "3"], "repository"),
        ({}, [], "numero della PR"),
        ({}, ["--pull-request", "3"], "commit di testa"),
        ({}, ["--pull-request", "3", "--head-sha", "abc"], "commit di testa"),
        ({}, ["--pull-request", "3", "--no-check-run", "--author", "a b"], "autore"),
        (
            {"GITHUB_API_URL": "http://api.example"},
            ["--pull-request", "3", "--no-check-run"],
            "GitHub",
        ),
    ],
)
def test_bad_inputs_exit_two_before_any_request(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    values: dict[str, str],
    flags: list[str],
    message: str,
) -> None:
    env(monkeypatch, **values)
    transport = Recorder()
    assert notify(transport, pr_report(tmp_path), *flags) == 2
    assert transport.calls == [] and message in capsys.readouterr().err


@pytest.mark.parametrize(
    "flags",
    [
        ["--pull-request", "0"],
        ["--pull-request", "x"],
        ["--max-findings", "1001"],
        ["--provider", "gitlab"],
    ],
)
def test_syntax_errors_exit_two(tmp_path: Path, flags: list[str]) -> None:
    with pytest.raises(SystemExit) as info:
        notify(Recorder(), pr_report(tmp_path), *flags)
    assert info.value.code == 2


def test_a_hostile_event_file_is_ignored(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    event = tmp_path / "event.json"
    event.write_text(json.dumps({"pull_request": {"number": True, "head": {"sha": "../x"}}}))
    env(monkeypatch, GITHUB_EVENT_PATH=str(event))
    assert notify(Recorder(), pr_report(tmp_path)) == 2  # numero sconosciuto: non si inventa


def test_an_unreadable_report_exits_two(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    env(monkeypatch)
    assert notify(Recorder(), tmp_path / "missing.json", "--pull-request", "3") == 2
