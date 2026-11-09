"""N-27 (S-02): artefatti non leggibili da altri e fingerprint dei segreti fuori dai log."""

import argparse
import stat
from pathlib import Path

import pytest

from ca_cli import gate
from ca_cli.composition import DirectoryArtifactSink
from ca_core.models.finding import Category, Level
from ca_core.pipeline.gate import GateFinding, GateResult


@pytest.mark.parametrize("existing", [False, True])
def test_artifacts_are_private_even_if_the_file_existed(tmp_path: Path, existing: bool) -> None:
    target = tmp_path / "report.json"
    if existing:
        target.write_text("vecchio")
        target.chmod(0o644)
    DirectoryArtifactSink(str(tmp_path)).write("report.json", b"{}")
    assert stat.S_IMODE(target.stat().st_mode) == 0o600


def blocking(fingerprint: str, category: Category) -> GateFinding:
    return GateFinding(fingerprint=fingerprint, level=Level.HIGH, category=category, rule_id="r")


def test_gate_output_omits_only_the_fingerprint_of_secrets(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    result = GateResult(
        exit_code=1,
        block_on=[Level.HIGH],
        block_on_source="default",
        blocking=[
            blocking("sha256:segreto", Category.SECRET),
            blocking("sha256:sast", Category.SAST),
        ],
        warned=[],
        reasons=[],
    )
    monkeypatch.setattr(gate, "_read_report", lambda _path: None)
    monkeypatch.setattr(gate, "evaluate_gate", lambda *_a, **_k: result)
    args = argparse.Namespace(report="r.json", fail_on=None, allow_partial=False)
    assert gate.handle(args, None) == 1  # type: ignore[arg-type]
    out = capsys.readouterr().out
    assert "sha256:segreto" not in out and "bloccante - alto secret" in out
    assert "bloccante sha256:sast alto sast" in out
