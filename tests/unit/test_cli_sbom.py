"""L-03 (`sbom`) con porte finte e disco reale in `tmp_path`. Nessun Docker."""

from pathlib import Path

import pytest
from test_cli_scan_gate import Env, manifest
from test_workspace_symlinks import link

import ca_plugins
from ca_cli.main import main
from ca_core.fakes import FakePluginExecutor
from ca_core.ports import Isolation, PluginRunResult, RunOutcome, Signature

SBOM = (
    Path(ca_plugins.__file__).parent / "builtin/syft/fixtures/output/syft.python-app.cdx.json"
).read_bytes()


def syft() -> object:
    return manifest(
        "syft",
        outputs={
            "cyclonedx": "/out/sbom.cdx.json",
            "cyclonedx_version": "1.7",
            "max_bytes": 16777216,
        },
    )


def ready(env: Env, content: bytes = SBOM) -> FakePluginExecutor:
    (env.plugin_out / "sbom.cdx.json").write_bytes(content)
    return FakePluginExecutor({"syft": env.ok()})


def run(env: Env, executor: FakePluginExecutor, *flags: str, manifests: object = None) -> int:
    chosen = [syft(), manifest()] if manifests is None else manifests
    context = env.context(executor, chosen)  # type: ignore[arg-type]
    return main(["sbom", str(env.repo), *flags], context=context)


def test_writes_the_validated_document_to_stdout_running_only_syft(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    env = Env(tmp_path)
    executor = ready(env)
    assert run(env, executor) == 0
    assert capsys.readouterr().out.encode() == SBOM
    assert [r.manifest.name for r in executor.runs] == ["syft"]
    assert not env.out.exists()  # nessun report


def test_output_goes_to_the_file_and_not_to_stdout(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    env = Env(tmp_path)
    target = tmp_path / "nuova/bom.cdx.json"
    assert run(env, ready(env), "--format", "cyclonedx", "--output", str(target)) == 0
    assert target.read_bytes() == SBOM
    assert capsys.readouterr().out == ""


def test_plugin_disabled_in_the_config_still_runs(tmp_path: Path) -> None:
    env = Env(tmp_path)
    (env.repo / ".code-analyzer.yml").write_text("version: 1\nplugins:\n  disable: [syft]\n")
    assert run(env, ready(env)) == 0


@pytest.mark.parametrize("content", [b"{}", b"not json", b'{"bomFormat":"CycloneDX"}'])
def test_invalid_document_is_an_error_and_writes_nothing(
    tmp_path: Path, content: bytes, capsys: pytest.CaptureFixture[str]
) -> None:
    env = Env(tmp_path)
    target = tmp_path / "bom.json"
    assert run(env, ready(env, content), "--output", str(target)) == 2
    assert not target.exists() and capsys.readouterr().out == ""


def test_plugin_failure_is_an_error(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    env = Env(tmp_path)
    failed = PluginRunResult(
        outcome=RunOutcome.FAILED,
        exit_code=1,
        isolation=Isolation.HARDENED_CONTAINER,
        signature=Signature.VERIFIED,
        duration_seconds=0,
        output_dir=None,
        detail=None,
    )
    assert run(env, FakePluginExecutor({"syft": failed})) == 2
    assert "syft non riuscito" in capsys.readouterr().err


def test_missing_plugin_is_an_error(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    env = Env(tmp_path)
    assert run(env, FakePluginExecutor(), manifests=[manifest()]) == 2
    assert "plugin syft non disponibile" in capsys.readouterr().err


def test_spdx_is_not_available(tmp_path: Path) -> None:
    env = Env(tmp_path)
    with pytest.raises(SystemExit) as stop:
        run(env, ready(env), "--format", "spdx")
    assert stop.value.code == 2


def test_incomplete_analysis_is_declared_on_stderr_without_names(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    env = Env(tmp_path)
    link(env.repo, "TOP-SECRET-NAME.lock")
    assert run(env, ready(env)) == 0
    captured = capsys.readouterr()
    assert "1 collegamenti simbolici con contenuto non analizzato" in captured.err
    assert "TOP-SECRET-NAME" not in captured.err + captured.out
