# ruff: noqa: F401, F811  (le fixture di t03_support si importano e si usano come argomenti)
"""R-09, A-01 `/out`: volume tmpfs per esecuzione con custodia, provato con un daemon Docker reale.

Provato: il tetto del volume ferma la scrittura (ENOSPC) senza toccare il disco dell'host; la
custodia lo tiene in sola lettura; all'host arriva solo il file dichiarato, con i controlli di tipo
e dimensione fatti sull'intestazione del tar; container, custodia e volume spariscono sempre.
Non provato: Podman, gVisor (`UNPROVEN`), `userns-remap` e Docker rootless.
"""

import json
import subprocess
import uuid
from pathlib import Path

import pytest
from t03_support import Lab, ex, lab, needs_docker, work

from ca_core.ports import Isolation, RunOutcome
from ca_plugins.runner import OutputReader, holder_args, out_tmpfs_bytes, out_volume_args

pytestmark = needs_docker

MIB = 1024 * 1024
MAX_BYTES = 1 << 20


def dangling_volumes(lab: Lab) -> list[str]:
    """Volumi del runner non usati da alcun container: ciò che una pulizia mancata lascerebbe."""
    return lab.docker(
        "volume",
        "ls",
        "-q",
        "--filter",
        "dangling=true",
        "--filter",
        "label=code-analyzer.executor=1",
    ).split()


def test_a_plugin_filling_out_succeeds_and_only_the_declared_file_reaches_the_host(
    ex: object, lab: Lab, work: Path, tmp_path: Path
) -> None:
    """64 MiB chiesti contro un tmpfs da 17 MiB (1 output di 1 MiB + margine): il plugin arriva
    a ENOSPC e esce 0 (il tetto esatto è provato sotto), l'host riceve solo `results.sarif`."""
    request = lab.request(tmp_path / "r", "fill-out", mib=64)
    assert out_tmpfs_bytes(request.manifest.outputs) == 17 * MIB
    result = ex.run(request)  # type: ignore[attr-defined]
    assert result.outcome is RunOutcome.OK and result.output_dir, result.detail
    assert [p.name for p in Path(result.output_dir).iterdir()] == ["results.sarif"]
    ex.release(result.output_dir)  # type: ignore[attr-defined]
    assert lab.containers() == [] and dangling_volumes(lab) == []


@pytest.mark.parametrize(
    ("behavior", "detail"),
    [
        ("symlink-out", "output non valido: results.sarif"),
        ("fifo-out", "output non valido: results.sarif"),
        ("oversize", "output oltre il limite: results.sarif"),
    ],
)
def test_declared_output_of_the_wrong_type_or_size_is_invalid_and_cleans_up(
    ex: object, lab: Lab, tmp_path: Path, behavior: str, detail: str
) -> None:
    result = ex.run(lab.request(tmp_path / "r", behavior))  # type: ignore[attr-defined]
    assert (result.outcome, result.exit_code, result.detail) == (
        RunOutcome.INVALID_OUTPUT,
        0,
        detail,
    )
    assert result.output_dir is None
    assert lab.containers() == [] and dangling_volumes(lab) == []


def test_undeclared_files_and_directories_are_never_copied(
    ex: object, lab: Lab, tmp_path: Path
) -> None:
    result = ex.run(lab.request(tmp_path / "r", "subdir-out", mode=0o755))  # type: ignore[attr-defined]
    assert result.outcome is RunOutcome.OK and result.output_dir
    assert sorted(p.name for p in Path(result.output_dir).iterdir()) == ["results.sarif"]


def test_holder_keeps_the_volume_read_only_and_the_volume_is_a_capped_noexec_tmpfs(
    lab: Lab,
) -> None:
    """Il volume e la custodia come li crea il runner, provati a mano con gli stessi argomenti."""
    token = uuid.uuid4().hex[:16]
    volume, holder = f"ca-out-r09-{token}", f"ca-hold-r09-{token}"
    try:
        create = out_volume_args(volume, 4 * MIB, 4_000_000_000)
        lab.docker(*create[:-1], volume)
        args = holder_args(
            name=holder,
            image=lab.image_id,
            volume=volume,
            isolation=Isolation.HARDENED_CONTAINER,
            sleep_seconds=60,
            expires=4_000_000_000,
        )
        lab.docker(*args)
        lab.docker("start", holder)
        mounts = lab.docker(
            "exec",
            holder,
            "python",
            "-c",
            "rows = [r.split() for r in open('/proc/self/mountinfo')]\n"
            "print([r[5] for r in rows if r[4] == '/out'][0])",
        )
        assert {"ro", "noexec", "nosuid", "nodev"} <= set(mounts.split(","))
        denied = subprocess.run(
            ["docker", "exec", holder, "python", "-c", "open('/out/x','w')"],
            capture_output=True,
            text=True,
            check=False,
        )
        assert denied.returncode != 0 and "Read-only file system" in denied.stderr
        # un secondo container scrive come 65534 fino al tetto, mai oltre
        written = lab.docker(
            "run",
            "--rm",
            "--pull",
            "never",
            "--user",
            "65534:65534",
            "--network",
            "none",
            "--mount",
            f"type=volume,src={volume},dst=/out",
            "--entrypoint",
            "python",
            lab.image_id,
            "-c",
            "import os\n"
            "n=0\n"
            "try:\n"
            "    with open('/out/f','wb',buffering=0) as h:\n"
            "        while n < 16:\n"
            "            h.write(b'0'*(1<<20)); n+=1\n"
            "except OSError as e:\n"
            "    print(n, e.strerror)\n",
        )
        assert written == "4 No space left on device"
    finally:
        subprocess.run(["docker", "rm", "-f", holder], capture_output=True, check=False)
        subprocess.run(["docker", "volume", "rm", "-f", volume], capture_output=True, check=False)
