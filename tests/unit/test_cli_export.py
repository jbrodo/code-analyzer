"""`export` (N-06): i file scritti, la validazione prima di scrivere e gli errori."""

import json
from pathlib import Path

import pytest
from builders import finding, report

from ca_cli.composition import Context, vendor_schema_store
from ca_cli.main import main
from ca_core.fakes import FakePluginExecutor, FixedClock
from ca_core.models.finding import Category, Level
from ca_plugins.source import LocalSourceReader

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "plugin-output"
NAMES = {
    "gl-sast-report.json",
    "gl-dependency-scanning-report.json",
    "gl-code-quality-report.json",
}


def context() -> Context:
    return Context(
        executor=FakePluginExecutor({}),
        source=LocalSourceReader(),
        clock=FixedClock(),
        schemas=vendor_schema_store,
    )


def write_report(tmp: Path) -> Path:
    data = report(
        [
            finding("s", level=Level.HIGH),
            finding("q", category=Category.QUALITY, tool="ruff", level=Level.LOW),
            finding("k", category=Category.SECRET, tool="gitleaks", level=Level.CRITICAL),
        ]
    )
    path = tmp / "report.json"
    path.write_text(data.model_dump_json())
    return path


def run(*argv: str) -> int:
    return main(["export", *argv], context=context())


def test_writes_the_three_reports_and_says_what_is_not_exported(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    out = tmp_path / "out"
    out.mkdir()
    assert run("--report", str(write_report(tmp_path)), "--output-dir", str(out)) == 0
    assert {p.name for p in out.iterdir()} == NAMES
    assert len(json.loads((out / "gl-sast-report.json").read_text())["vulnerabilities"]) == 1
    assert len(json.loads((out / "gl-code-quality-report.json").read_text())) == 1
    err = capsys.readouterr().err
    assert "sast=1" in err and "secret=1" in err and "restano nel report" in err


def test_sbom_is_written_as_cyclonedx_16(tmp_path: Path) -> None:
    out = tmp_path / "out"
    out.mkdir()
    sbom = FIXTURES / "syft.cdx.json"
    code = run(
        "--report", str(write_report(tmp_path)), "--sbom", str(sbom), "--output-dir", str(out)
    )
    assert code == 0
    written = json.loads((out / "gl-sbom-code-analyzer.cdx.json").read_text())
    assert written["specVersion"] == "1.6"


def test_a_sbom_that_does_not_convert_writes_nothing(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    out = tmp_path / "out"
    out.mkdir()
    bad = tmp_path / "bad.json"
    document = json.loads((FIXTURES / "syft.cdx.json").read_text())
    document["citations"] = [{"timestamp": "2026-01-01T00:00:00Z"}]
    bad.write_text(json.dumps(document))
    code = run(
        "--report", str(write_report(tmp_path)), "--sbom", str(bad), "--output-dir", str(out)
    )
    assert code == 2
    assert list(out.iterdir()) == []  # nessun file: o tutti o nessuno
    assert "gl-sbom-code-analyzer.cdx.json" in capsys.readouterr().err


@pytest.mark.parametrize("content", ["{", '{"version": "9"}', "[]"])
def test_an_invalid_report_is_exit_2_and_not_echoed(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], content: str
) -> None:
    path = tmp_path / "r.json"
    path.write_text(content)
    assert run("--report", str(path), "--output-dir", str(tmp_path)) == 2
    assert content not in capsys.readouterr().err or content == "{"


def test_missing_files_are_exit_2(tmp_path: Path) -> None:
    assert run("--report", str(tmp_path / "none.json"), "--output-dir", str(tmp_path)) == 2
    report_path = write_report(tmp_path)
    assert (
        run(
            "--report",
            str(report_path),
            "--sbom",
            str(tmp_path / "none"),
            "--output-dir",
            str(tmp_path),
        )
        == 2
    )


def test_export_never_decides_the_exit_with_the_gate(tmp_path: Path) -> None:
    """Un report con finding critici esporta comunque con exit 0: decide solo `gate`."""
    assert run("--report", str(write_report(tmp_path)), "--output-dir", str(tmp_path)) == 0
