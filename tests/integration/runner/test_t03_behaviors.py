# ruff: noqa: F401, F811  (le fixture di t03_support si importano e si usano come argomenti)
"""T-03: ogni comportamento del plugin finto (T-02) produce l'esito di ADR-0004 e ADR-0005.

Contro un daemon Docker reale e il runner reale (`OciExecutor`). I tentativi ostili sono provati
dall'interno del container (`report.json`: l'errno restituito dal kernel), non solo dall'exit del
plugin: un plugin che ignorasse il tentativo uscirebbe comunque con 0.
"""

import json
import os
import time
from pathlib import Path

import pytest
from t03_support import Lab, ex, lab, needs_docker, run_dirs, work

from ca_core.ports import RunOutcome
from ca_core.sarif import SarifError, SarifLimits, read_sarif_file
from ca_core.schema_validation import SchemaStore
from ca_plugins.runner import OciExecutor, OutputReader

pytestmark = needs_docker

SCHEMAS = Path(__file__).resolve().parents[3] / "schemas" / "vendor"
MAX_BYTES = 1_048_576

# comportamento -> (esito, exit, dettaglio, output esposto all'host)
TABLE = {
    "success": (RunOutcome.OK, 0, None, True),
    "write-tmp": (RunOutcome.OK, 0, None, True),
    "write-out": (RunOutcome.OK, 0, None, True),
    "invalid-sarif": (RunOutcome.OK, 0, None, True),  # la validita' SARIF e' di ca-core (K-01)
    "network": (RunOutcome.OK, 0, None, True),
    "write-workspace": (RunOutcome.OK, 0, None, True),
    "write-rootfs": (RunOutcome.OK, 0, None, True),
    "exec-tmp": (RunOutcome.OK, 0, None, True),
    "exit-nonzero": (RunOutcome.FAILED, 3, "exit 3", False),
    "oversize": (RunOutcome.INVALID_OUTPUT, 0, "output oltre il limite: results.sarif", False),
    "symlink-out": (RunOutcome.INVALID_OUTPUT, 0, "output non valido: results.sarif", False),
    "fifo-out": (RunOutcome.INVALID_OUTPUT, 0, "output non valido: results.sarif", False),
}


@pytest.mark.parametrize("behavior", sorted(TABLE))
def test_behavior_outcome(
    ex: OciExecutor, lab: Lab, work: Path, tmp_path: Path, behavior: str
) -> None:
    outcome, code, detail, exposed = TABLE[behavior]
    started = time.monotonic()
    result = ex.run(lab.request(tmp_path / "r", behavior))
    assert time.monotonic() - started < 60  # nessuna FIFO o attesa blocca l'host
    assert (result.outcome, result.exit_code, result.detail) == (outcome, code, detail)
    assert (result.output_dir is not None) is exposed
    if not exposed:
        assert run_dirs(work) == []  # la directory dell'esecuzione e' gia' stata rimossa
    else:
        assert result.output_dir
        ex.release(result.output_dir)
        assert run_dirs(work) == []


@pytest.mark.parametrize(
    ("behavior", "probe", "errno_text"),
    [
        ("network", "network", "Network is unreachable"),
        ("write-workspace", "workspace_write", "Read-only file system"),
        ("write-rootfs", "rootfs_write", "Read-only file system"),
        ("exec-tmp", "tmp_exec", "Permission denied"),
        ("write-tmp", "tmp_write", "ok"),
        ("write-out", "out_write", "ok"),
    ],
)
def test_attempts_are_decided_by_the_kernel_not_by_the_plugin(
    ex: OciExecutor, lab: Lab, tmp_path: Path, behavior: str, probe: str, errno_text: str
) -> None:
    result = ex.run(lab.request(tmp_path / "r", behavior, report=True))
    assert result.outcome is RunOutcome.OK and result.output_dir
    report = json.loads(OutputReader().read_file(result.output_dir, "report.json", MAX_BYTES))
    assert report["probes"][probe] == errno_text


def test_workspace_is_unchanged_after_a_write_attempt(
    ex: OciExecutor, lab: Lab, tmp_path: Path
) -> None:
    result = ex.run(lab.request(tmp_path / "r", "write-workspace"))
    assert result.outcome is RunOutcome.OK
    assert sorted(p.name for p in (tmp_path / "r" / "ws").iterdir()) == ["app.py"]


def test_success_output_is_a_host_owned_private_copy_and_valid_sarif(
    ex: OciExecutor, lab: Lab, tmp_path: Path
) -> None:
    result = ex.run(lab.request(tmp_path / "r", "success"))
    assert result.output_dir
    assert OutputReader().list_files(result.output_dir) == ["results.sarif"]
    path = Path(result.output_dir) / "results.sarif"
    assert (path.stat().st_uid, path.stat().st_mode & 0o777) == (os.getuid(), 0o600)  # copia host
    read_sarif_file(path, SchemaStore(SCHEMAS), SarifLimits(max_bytes=MAX_BYTES))


def test_invalid_sarif_passes_the_runner_and_is_rejected_by_the_sarif_reader(
    ex: OciExecutor, lab: Lab, tmp_path: Path
) -> None:
    result = ex.run(lab.request(tmp_path / "r", "invalid-sarif"))
    assert result.outcome is RunOutcome.OK and result.output_dir
    with pytest.raises(SarifError):
        read_sarif_file(
            Path(result.output_dir) / "results.sarif",
            SchemaStore(SCHEMAS),
            SarifLimits(max_bytes=MAX_BYTES),
        )


def test_write_out_extra_file_is_never_copied_to_the_host(
    ex: OciExecutor, lab: Lab, tmp_path: Path
) -> None:
    """Il plugin scrive `extra.txt` (riesce: `out_write` ok) ma non è dichiarato: non esce."""
    result = ex.run(lab.request(tmp_path / "r", "write-out", report=True))
    assert result.output_dir
    assert OutputReader().list_files(result.output_dir) == ["report.json", "results.sarif"]
    report = json.loads(OutputReader().read_file(result.output_dir, "report.json", MAX_BYTES))
    assert report["probes"]["out_write"] == "ok"


def test_timeout_kills_the_container_and_discards_the_output(
    ex: OciExecutor, lab: Lab, work: Path, tmp_path: Path
) -> None:
    started = time.monotonic()
    result = ex.run(lab.request(tmp_path / "r", "timeout", timeout="2s"))
    assert (result.outcome, result.exit_code, result.output_dir) == (RunOutcome.TIMEOUT, None, None)
    assert 2 <= time.monotonic() - started < 30
    assert lab.containers() == []  # ucciso il container, non solo il client
    assert run_dirs(work) == []


def test_unknown_behavior_is_rejected_by_the_plugin_with_exit_64(
    ex: OciExecutor, lab: Lab, tmp_path: Path
) -> None:
    result = ex.run(lab.request(tmp_path / "r", "rm-rf"))
    assert (result.outcome, result.exit_code) == (RunOutcome.FAILED, 64)
