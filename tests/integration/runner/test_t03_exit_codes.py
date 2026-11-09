# ruff: noqa: F401, F811  (le fixture di t03_support si importano e si usano come argomenti)
"""T-03: gli errori che fermano la scansione portano exit 2 e non avviano alcun container.

Le eccezioni portano `exit_code = 2` (ADR-0004, ADR-0005): la CLI le traduce in exit 2. I casi che
non toccano il daemon girano sempre; quelli con il daemon richiedono `CA_TEST_DOCKER=1`.
"""

import stat
import subprocess
from pathlib import Path

import pytest
from t03_support import Lab, ex, lab, work

from ca_core.ports import Isolation, ScanAborted
from ca_plugins.runner import (
    IsolationUnsatisfied,
    OciExecutor,
    RuntimeUnavailable,
    require_isolation,
)


def test_all_aborting_errors_carry_exit_code_2() -> None:
    assert (
        ScanAborted.exit_code == RuntimeUnavailable.exit_code == IsolationUnsatisfied.exit_code == 2
    )


def test_missing_runtime_is_exit_2_and_never_falls_back_to_a_subprocess(tmp_path: Path) -> None:
    executor = OciExecutor(runtime="ca-no-such-runtime", work_dir=str(tmp_path))
    with pytest.raises(RuntimeUnavailable) as info:
        executor.isolation()
    assert info.value.exit_code == 2
    with pytest.raises(RuntimeUnavailable):
        executor.run(None)  # type: ignore[arg-type]  # fallisce prima di guardare la richiesta
    assert list(tmp_path.iterdir()) == []


def test_unreachable_daemon_is_exit_2(tmp_path: Path) -> None:
    broken = tmp_path / "docker"
    broken.write_text("#!/bin/sh\nexit 1\n")
    broken.chmod(stat.S_IRWXU)
    with pytest.raises(RuntimeUnavailable):
        OciExecutor(runtime=str(broken)).isolation()


@pytest.mark.parametrize(
    ("available", "minimum", "ok"),
    [
        (Isolation.HARDENED_CONTAINER, None, True),
        (Isolation.HARDENED_CONTAINER, Isolation.HARDENED_CONTAINER, True),
        (Isolation.GVISOR, Isolation.HARDENED_CONTAINER, True),
        (Isolation.GVISOR, Isolation.GVISOR, True),
        (Isolation.HARDENED_CONTAINER, Isolation.GVISOR, False),
    ],
)
def test_min_isolation_is_enforced(
    available: Isolation, minimum: Isolation | None, ok: bool
) -> None:
    if ok:
        require_isolation(available, minimum)
    else:
        with pytest.raises(IsolationUnsatisfied) as info:
            require_isolation(available, minimum)
        assert info.value.exit_code == 2


def test_min_isolation_gvisor_stops_before_any_container_on_this_daemon(
    lab: Lab, tmp_path: Path
) -> None:
    """Senza `runsc` il livello e' `hardened-container` (gVisor non provato): `gvisor` e' negato."""
    with lab.executor(tmp_path / "w") as ex:
        available = ex.isolation()
        if available is Isolation.GVISOR:
            pytest.skip("questo daemon ha runsc: il caso negativo non e' esercitabile")
        with pytest.raises(IsolationUnsatisfied):
            require_isolation(available, Isolation.GVISOR)
    assert lab.containers() == []


def test_image_missing_from_the_daemon_fails_that_plugin_only_and_creates_nothing(
    lab: Lab, work: Path, tmp_path: Path
) -> None:
    """Immagine per digest assente, senza verificatore: nessuna custodia di `/out`, nessun pull."""
    digest = "sha256:" + "0" * 64
    image = f"localhost/ca-t03-never-built:t@{digest}"
    with OciExecutor(work_dir=str(work)) as ex:
        result = ex.run(lab.request(tmp_path / "r", "success", image=image))
    assert result.outcome.value == "failed" and (result.detail or "").startswith(
        "custodia"
    )  # fallimento chiuso
    assert lab.containers() == []
    inspected = subprocess.run(
        ["docker", "image", "inspect", f"localhost/ca-t03-never-built@{digest}"],
        capture_output=True,
        check=False,
    )
    assert inspected.returncode != 0  # nessun pull
