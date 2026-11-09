# ruff: noqa: F401, F811  (le fixture di t03_support si importano e si usano come argomenti)
"""T-03 dopo R-09: un plugin ostile scrive in `/out` oltre ogni limite o lascia alberi.

`/out` e' un volume tmpfs per esecuzione con tetto `out_tmpfs_bytes` (ADR-0004, emendamento per
R-09): nulla di quanto il plugin scrive tocca il disco dell'host, e le sottodirectory create da
`65534` spariscono con il volume. All'host arrivano solo le copie dei file dichiarati.
La prova del tetto esatto e' in `test_r09_out_tmpfs.py`.
"""

import json
import shutil
import subprocess
import tempfile
import threading
import time
from collections.abc import Callable, Iterator
from pathlib import Path

import pytest
from t03_support import Lab, ex, lab, needs_docker, run_dirs, work

from ca_core.ports import RunOutcome, SourceError
from ca_plugins.runner import OutputReader

pytestmark = needs_docker

MIB = 1024 * 1024
MAX_BYTES = 1_048_576


def fstype(path: Path) -> str:
    return subprocess.run(
        ["stat", "-f", "-c", "%T", str(path)], capture_output=True, text=True, check=True
    ).stdout.strip()


def tree_bytes(root: Path) -> int:
    return sum(p.lstat().st_size for p in root.rglob("*") if p.is_file() and not p.is_symlink())


class Sampler(threading.Thread):
    """Misura dall'host la dimensione di `fill.bin` mentre il container scrive."""

    def __init__(self, work: Path) -> None:
        super().__init__(daemon=True)
        self.work = work
        self.peak = 0
        self.started = time.monotonic()
        self.reached_at = 0.0  # secondi dall'avvio del campionatore al picco
        self.stop_event = threading.Event()

    def run(self) -> None:
        while not self.stop_event.is_set():
            for path in self.work.glob("ca-oci-*/run-*/out/fill.bin"):
                try:
                    size = path.stat().st_size
                    if size > self.peak:
                        self.peak, self.reached_at = size, time.monotonic() - self.started
                except OSError:
                    pass
            time.sleep(0.02)


@pytest.fixture(params=["tmp_path", "var_tmp"])
def fill_work(request: pytest.FixtureRequest, lab: Lab, tmp_path: Path) -> Iterator[Path]:
    """Radice di lavoro su due file system: quello dei test (qui tmpfs) e `/var/tmp` (disco)."""
    if request.param == "tmp_path":
        base = tmp_path / "w"
        base.mkdir()
    else:
        base = Path(tempfile.mkdtemp(prefix="ca-t03-", dir="/var/tmp"))  # noqa: S108
    yield base
    lab.scrub(base)
    shutil.rmtree(base, ignore_errors=True)
    assert lab.containers() == []


def test_fill_out_never_reaches_the_host_disk(
    lab: Lab, fill_work: Path, tmp_path: Path, record_property: Callable[[str, object], None]
) -> None:
    """256 MiB chiesti con `max_bytes` di 1 MiB: il tmpfs ferma il plugin (ENOSPC), l'host non vede
    un solo byte durante l'esecuzione, e dopo il timeout non resta nulla."""
    sampler = Sampler(fill_work)
    with lab.executor(fill_work) as ex:
        sampler.start()
        result = ex.run(lab.request(tmp_path / "r", "fill-out", timeout="6s", mib=256, hold=True))
        sampler.stop_event.set()
        sampler.join()
    record_property("fs", fstype(fill_work))
    assert (result.outcome, result.detail) == (RunOutcome.TIMEOUT, "timeout oltre 6s")
    assert result.output_dir is None
    assert sampler.peak == 0  # nessun fill.bin sul file system dell'host
    assert run_dirs(fill_work) == []
    assert tree_bytes(fill_work) == 0


def test_fill_out_that_exits_copies_only_the_declared_file(
    lab: Lab, work: Path, tmp_path: Path
) -> None:
    """Esce 0 con un file non dichiarato di 8 MiB: e' un successo, il file non esce dal volume."""
    with lab.executor(work) as ex:
        result = ex.run(lab.request(tmp_path / "r", "fill-out", mib=8))
        assert result.outcome is RunOutcome.OK and result.output_dir
        assert OutputReader().list_files(result.output_dir) == ["results.sarif"]
        assert tree_bytes(work) < MIB
        ex.release(result.output_dir)
        assert tree_bytes(work) == 0


@pytest.mark.parametrize("mode", [0o000, 0o755, 0o777], ids=["mode-000", "mode-755", "mode-777"])
def test_subdirectory_in_out_is_invisible_to_the_reader(
    lab: Lab, work: Path, tmp_path: Path, mode: int
) -> None:
    with lab.executor(work) as ex:
        result = ex.run(lab.request(tmp_path / "r", "subdir-out", mode=mode))
        assert result.outcome is RunOutcome.OK and result.output_dir
        reader = OutputReader()
        assert reader.list_files(result.output_dir) == ["results.sarif"]
        with pytest.raises(SourceError):
            reader.read_file(result.output_dir, "locked/f", 64)
        ex.release(result.output_dir)


@pytest.mark.parametrize("mode", [0o000, 0o755], ids=["mode-000", "mode-755"])
def test_release_removes_a_plugin_created_subdirectory(
    lab: Lab, work: Path, tmp_path: Path, mode: int
) -> None:
    with lab.executor(work) as ex:
        result = ex.run(lab.request(tmp_path / "r", "subdir-out", mode=mode))
        assert result.output_dir
        ex.release(result.output_dir)
        left = sorted(str(p.relative_to(work)) for p in work.rglob("*"))
        assert run_dirs(work) == [], f"restano sull'host: {left}"


def test_release_removes_a_world_writable_plugin_subdirectory(
    lab: Lab, work: Path, tmp_path: Path
) -> None:
    """Con 0777 l'host (altro utente) puo' scrivere nella sottodirectory e quindi rimuoverla."""
    with lab.executor(work) as ex:
        result = ex.run(lab.request(tmp_path / "r", "subdir-out", mode=0o777))
        assert result.output_dir
        ex.release(result.output_dir)
        assert run_dirs(work) == []


def test_nothing_remains_after_release_or_close_of_a_locked_subdirectory(
    lab: Lab, work: Path, tmp_path: Path
) -> None:
    """Sottodirectory 000 creata dal plugin: vive solo nel volume, `rmtree` riesce sempre."""
    ex = lab.executor(work)
    result = ex.run(lab.request(tmp_path / "r", "subdir-out", mode=0))
    assert result.outcome is RunOutcome.OK and result.output_dir
    assert next(work.rglob("locked"), None) is None
    ex.release(result.output_dir)
    assert run_dirs(work) == []
    ex.close()
    assert list(work.rglob("*")) == []
