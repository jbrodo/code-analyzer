"""L-01: scheletro del comando e radice di composizione. Nessun Docker."""

from pathlib import Path

import pytest

from ca_cli.composition import Context, DirectoryArtifactSink, SystemClock, build_context
from ca_cli.main import HANDLERS, build_parser, main
from ca_core.fakes import FakePluginExecutor, InMemorySourceReader
from ca_core.ports import ArtifactSink, Clock, PluginExecutor, SourceReader
from ca_plugins.runner import IsolationUnsatisfied, OciExecutor
from ca_plugins.source import LocalSourceReader


def test_only_the_four_commands_exist() -> None:
    assert set(HANDLERS) == {("scan", None), ("sbom", None), ("gate", None), ("config", "validate")}
    for argv in (["explain"], ["plugin", "list"], ["config", "other"], []):
        with pytest.raises(SystemExit) as err:
            build_parser().parse_args(argv)
        assert err.value.code == 2


def test_unimplemented_command_exits_2_never_1(capsys: pytest.CaptureFixture[str]) -> None:
    for argv in (["scan"], ["sbom"], ["gate"], ["config", "validate"]):
        assert main(argv) == 2
    assert "non è ancora disponibile" in capsys.readouterr().err


def test_syntax_error_exits_2() -> None:
    with pytest.raises(SystemExit) as err:
        main(["scan", "--min-isolation", "gvisor"])  # opzione di L-04: non anticipata
    assert err.value.code == 2


def test_expected_error_exits_2_without_traceback(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    def boom(*_a: object) -> int:
        raise IsolationUnsatisfied("isolamento richiesto gvisor, disponibile hardened-container")

    monkeypatch.setitem(HANDLERS, ("scan", None), boom)
    assert main(["scan"]) == 2
    err = capsys.readouterr().err
    assert "isolamento richiesto" in err and "Traceback" not in err


def test_unexpected_error_hides_details(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    def boom(*_a: object) -> int:
        raise RuntimeError("/home/utente/segreto")

    monkeypatch.setitem(HANDLERS, ("gate", None), boom)
    assert main(["gate"]) == 2
    assert "segreto" not in capsys.readouterr().err


def test_handler_receives_the_injected_context(monkeypatch: pytest.MonkeyPatch) -> None:
    ctx = Context(FakePluginExecutor(), InMemorySourceReader(), SystemClock())
    seen: list[Context] = []
    monkeypatch.setitem(HANDLERS, ("gate", None), lambda a, c: seen.append(c) or 1)
    assert main(["gate"], context=ctx) == 1
    assert seen == [ctx]


def test_composition_root_wires_real_adapters_without_touching_docker() -> None:
    ctx = build_context()
    assert isinstance(ctx.executor, OciExecutor) and isinstance(ctx.executor, PluginExecutor)
    assert isinstance(ctx.source, LocalSourceReader) and isinstance(ctx.source, SourceReader)
    assert isinstance(ctx.clock, Clock) and ctx.clock.now().tzinfo is not None
    assert isinstance(ctx.artifact_sink("/tmp/x"), ArtifactSink)


def test_artifact_sink_writes_inside_the_area_only(tmp_path: Path) -> None:
    base = tmp_path / "out"
    sink = DirectoryArtifactSink(str(base))
    ref = sink.write("code-analyzer.report.json", b"{}")
    assert (base / "code-analyzer.report.json").read_bytes() == b"{}"
    assert (ref.name, ref.size) == ("code-analyzer.report.json", 2)
    sink.write("sub/dir/a.txt", b"1")
    sink.write("sub/dir/a.txt", b"22")  # rilancio: sovrascrive
    assert (base / "sub/dir/a.txt").read_bytes() == b"22"


@pytest.mark.parametrize("name", ["../x", "/etc/x", "", "a/../b", "a//b", "."])
def test_artifact_sink_refuses_escaping_names(tmp_path: Path, name: str) -> None:
    with pytest.raises(ValueError):
        DirectoryArtifactSink(str(tmp_path / "out")).write(name, b"x")


def test_artifact_sink_does_not_follow_symlinks(tmp_path: Path) -> None:
    base = tmp_path / "out"
    base.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    (base / "link").symlink_to(outside)
    (base / "file").symlink_to(tmp_path / "victim")
    sink = DirectoryArtifactSink(str(base))
    for name in ("link/a", "file"):
        with pytest.raises(ValueError):
            sink.write(name, b"x")
    assert list(outside.iterdir()) == [] and not (tmp_path / "victim").exists()
