"""`upload` (L-03, ADR-0016): invio al server con il token OIDC, trasporto finto (nessuna rete)."""

import json
from pathlib import Path

import pytest
from builders import finding, report
from test_cli_notify import Recorder, context, ok

from ca_cli.main import main
from ca_integrations.github import Response, TransportError

TOKEN = "eyJ.OIDC-TOKEN-THAT-MUST-NEVER-APPEAR.sig"  # noqa: S105
REQUEST_TOKEN = "REQUEST-TOKEN-NEVER-PRINTED"  # noqa: S105


@pytest.fixture(autouse=True)
def clean_env(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in (
        "CA_OIDC_TOKEN",
        "ACTIONS_ID_TOKEN_REQUEST_URL",
        "ACTIONS_ID_TOKEN_REQUEST_TOKEN",
        "CA_UPLOAD_ALLOW_LOOPBACK_HTTP",
    ):
        monkeypatch.delenv(name, raising=False)


def make_report(tmp: Path, *extra: str) -> Path:
    path = tmp / "code-analyzer.report.json"
    path.write_text(report([finding("a")]).model_dump_json())
    for name in extra:
        (tmp / name).write_text('{"x": 1}')
    return path


def upload(transport: Recorder, path: Path, *flags: str) -> int:
    argv = ["upload", "--server", "https://ca.example.org", "--report", str(path), *flags]
    return main(argv, context=context(transport))


def test_the_report_and_the_files_beside_it_are_sent_with_the_token_of_the_environment(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("CA_OIDC_TOKEN", TOKEN)
    path = make_report(tmp_path, "code-analyzer.sarif", "code-analyzer.graph.json")
    transport = Recorder(ok({"id": "abc"}, 201))
    assert upload(transport, path) == 0
    ((method, url, headers, body),) = transport.calls
    assert (method, url) == ("POST", "https://ca.example.org/v1/scans")
    assert headers["Authorization"] == f"Bearer {TOKEN}"
    assert body is not None
    for part in ("report", "sarif", "graph"):
        assert f'name="{part}"'.encode() in body
    assert b'name="sbom"' not in body
    out = capsys.readouterr()
    assert "inviata" in out.out and TOKEN not in out.out + out.err


def test_a_repeated_upload_is_a_success(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("CA_OIDC_TOKEN", TOKEN)
    assert upload(Recorder(ok({"id": "abc"}, 200)), make_report(tmp_path)) == 0
    assert "già presente" in capsys.readouterr().out


def test_github_actions_token_is_requested_with_the_audience(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("ACTIONS_ID_TOKEN_REQUEST_URL", "https://token.actions.example/t?api=1")
    monkeypatch.setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", REQUEST_TOKEN)
    transport = Recorder(ok({"value": TOKEN}), ok({"id": "x"}, 201))
    assert upload(transport, make_report(tmp_path), "--audience", "https://ca.example.org") == 0
    first, second = transport.calls
    assert first[1] == "https://token.actions.example/t?api=1&audience=https%3A%2F%2Fca.example.org"
    assert first[2]["Authorization"] == f"Bearer {REQUEST_TOKEN}"
    assert second[2]["Authorization"] == f"Bearer {TOKEN}"


def test_without_a_token_nothing_is_sent(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    transport = Recorder()
    assert upload(transport, make_report(tmp_path)) == 2
    assert transport.calls == [] and "token OIDC" in capsys.readouterr().err


def test_a_refusal_prints_only_the_problem_code_never_the_text(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("CA_OIDC_TOKEN", TOKEN)
    body = {"code": "repository-mismatch", "detail": "SEGRETO-DEL-SERVER"}
    assert upload(Recorder(ok(body, 403)), make_report(tmp_path)) == 2
    err = capsys.readouterr().err
    assert "403" in err and "repository-mismatch" in err and "SEGRETO" not in err
    assert TOKEN not in err


def test_an_unreachable_server_is_exit_2_without_the_address(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("CA_OIDC_TOKEN", TOKEN)
    assert upload(Recorder(TransportError("x")), make_report(tmp_path)) == 2
    err = capsys.readouterr().err
    assert "non raggiungibile" in err and "ca.example.org" not in err


@pytest.mark.parametrize(
    "server",
    ["http://ca.example.org", "https://user:pw@ca.example.org", "ftp://x", "https://x?a=1"],
)
def test_an_unsafe_server_address_is_refused_before_any_request(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, server: str
) -> None:
    monkeypatch.setenv("CA_OIDC_TOKEN", TOKEN)
    transport = Recorder()
    argv = ["upload", "--server", server, "--report", str(make_report(tmp_path))]
    assert main(argv, context=context(transport)) == 2 and transport.calls == []


def test_http_is_allowed_only_on_loopback_when_asked(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("CA_OIDC_TOKEN", TOKEN)
    monkeypatch.setenv("CA_UPLOAD_ALLOW_LOOPBACK_HTTP", "1")
    path = make_report(tmp_path)
    transport = Recorder(ok({"id": "x"}, 201))
    assert (
        main(
            ["upload", "--server", "http://127.0.0.1:8000", "--report", str(path)],
            context=context(transport),
        )
        == 0
    )
    remote = Recorder()
    assert (
        main(
            ["upload", "--server", "http://ca.example.org", "--report", str(path)],
            context=context(remote),
        )
        == 2
    )


def test_an_invalid_report_is_not_sent(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("CA_OIDC_TOKEN", TOKEN)
    path = tmp_path / "r.json"
    path.write_text(json.dumps({"not": "a report"}))
    transport = Recorder()
    assert upload(transport, path) == 2 and transport.calls == []


def test_a_missing_report_is_exit_2(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("CA_OIDC_TOKEN", TOKEN)
    assert upload(Recorder(), tmp_path / "nope.json") == 2


def test_the_cli_package_does_not_import_the_server() -> None:
    source = Path("packages/ca-cli/src/ca_cli/upload.py").read_text()
    assert "ca_api" not in source and "sqlalchemy" not in source
    assert Response  # il trasporto è quello condiviso con `notify`
