# ruff: noqa: F401, F811  (le fixture di t03_support si importano e si usano come argomenti)
"""T-03: il profilo `hardened-container` visto dall'interno del container (ADR-0004).

Il plugin finto con `report` legge `/proc` e `/sys` e scrive `report.json` in `/out`: quello che
si afferma qui e' quello che il processo ostile vede davvero, non gli argomenti passati al CLI.
"""

import json
import os
from pathlib import Path
from typing import Any

import pytest
from t03_support import Lab, ex, lab, needs_docker, work

from ca_plugins.runner import OciExecutor, OutputReader, out_tmpfs_bytes

pytestmark = needs_docker

# Sentinelle: nomi e valori inconfondibili, falsi. Nessuna deve arrivare al plugin.
HOST_ENV = {
    "AWS_SECRET_ACCESS_KEY": "CA-FAKE-HOST-SECRET-aws-DO-NOT-USE",
    "GITHUB_TOKEN": "CA-FAKE-HOST-SECRET-gh-DO-NOT-USE",
    "CA_INSECURE_ALLOW_UNSIGNED": "1",
    "CA_COSIGN_PUBLIC_KEY": "/nonexistent/CA-FAKE-HOST-SECRET.pub",
    "SSH_AUTH_SOCK": "/tmp/CA-FAKE-HOST-SECRET-agent.sock",
    "HTTP_PROXY": "http://CA-FAKE-HOST-SECRET.invalid:3128",
    "LD_PRELOAD": "/nonexistent/CA-FAKE-HOST-SECRET.so",
}


def report(ex: OciExecutor, lab: Lab, base: Path, **kwargs: Any) -> dict[str, Any]:
    result = ex.run(lab.request(base, "report", **kwargs))
    assert result.output_dir, result.detail
    data = OutputReader().read_file(result.output_dir, "report.json", 1 << 20)
    ex.release(result.output_dir)
    return json.loads(data)  # type: ignore[no-any-return]


def test_no_host_environment_reaches_the_plugin(
    ex: OciExecutor, lab: Lab, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    for name, value in HOST_ENV.items():
        monkeypatch.setenv(name, value)
    seen = report(ex, lab, tmp_path / "r")["env"]
    # Insieme previsto: le variabili dell'immagine, `HOME=/tmp` del runner e `HOSTNAME` di Docker.
    expected_keys = set(lab.image_env()) | {"HOME", "HOSTNAME"}
    assert set(seen) == expected_keys
    for name, value in lab.image_env().items():
        assert seen[name] == value  # `PATH` e' quello dell'immagine, non quello dell'host
    assert seen["HOME"] == "/tmp"
    assert not set(HOST_ENV) & set(seen)
    assert not any("CA-FAKE-HOST-SECRET" in v for v in seen.values())


def test_identity_capabilities_and_syscall_filter(
    ex: OciExecutor, lab: Lab, tmp_path: Path
) -> None:
    data = report(ex, lab, tmp_path / "r")
    assert (data["uid"], data["gid"], data["groups"]) == (65534, 65534, [65534])
    zero = "0000000000000000"
    status = data["status"]
    assert {k: status[k] for k in ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb")} == {
        k: zero for k in ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb")
    }
    assert status["NoNewPrivs"] == "1"
    assert status["Seccomp"] == "2"  # filtro seccomp attivo (profilo predefinito del daemon)
    assert data["docker_sock"] is False


def test_mounts_and_resource_limits(ex: OciExecutor, lab: Lab, tmp_path: Path) -> None:
    req = lab.request(tmp_path / "r", "report")
    result = ex.run(req)
    assert result.output_dir, result.detail
    data = json.loads(OutputReader().read_file(result.output_dir, "report.json", 1 << 20))
    mounts = data["mounts"]
    assert "ro" in mounts["/"].split(",")
    assert "ro" in mounts["/workspace"].split(",")
    assert "ro" in mounts["/inputs/config.json"].split(",")
    assert {"rw", "noexec", "nosuid", "nodev"} <= set(mounts["/out"].split(","))  # volume tmpfs
    assert {"rw", "noexec", "nosuid"} <= set(mounts["/tmp"].split(","))
    cgroup = data["cgroup"]
    assert cgroup["pids.max"] == "64"  # `resources.pids` del manifest
    # `resources.memory` più il tmpfs di `/out` (ADR-0004, R-09); swap = memoria: nessuno swap
    assert cgroup["memory.max"] == str(256 * 1024 * 1024 + out_tmpfs_bytes(req.manifest.outputs))
    assert cgroup["memory.swap.max"] == "0"
    assert cgroup["cpu.max"] == "100000 100000"  # `resources.cpu` = 1


def test_workspace_of_another_owner_is_readable_and_out_is_writable_as_65534(
    ex: OciExecutor, lab: Lab, tmp_path: Path
) -> None:
    base = tmp_path / "r"
    result = ex.run(
        lab.request(
            base,
            "write-out",
            report=True,
            read="app.py",
            workspace_files={"app.py": "print('proprietario diverso')\n"},
        )
    )
    assert result.output_dir
    data = json.loads(OutputReader().read_file(result.output_dir, "report.json", 1 << 20))
    workspace = data["workspace"]
    assert workspace["uid"] == os.getuid() != 65534  # il file e' dell'utente dell'host
    assert workspace["content"] == "print('proprietario diverso')\n"
    assert data["probes"]["out_write"] == "ok"
    assert data["out_mode"] == "0o700"  # radice del volume tmpfs, proprietario 65534
    # solo i file dichiarati arrivano all'host, come copie dell'utente dell'host
    assert sorted(p.name for p in Path(result.output_dir).iterdir()) == [
        "report.json",
        "results.sarif",
    ]
    for name in ("report.json", "results.sarif"):
        assert (Path(result.output_dir) / name).stat().st_uid == os.getuid()


def test_unreadable_workspace_file_is_invisible_to_the_plugin_characterization(
    ex: OciExecutor, lab: Lab, tmp_path: Path
) -> None:
    """Osservazione, non requisito: un file 0600 dell'host e' illeggibile da `65534`.

    Il runner monta il workspace cosi' com'e': i permessi dei file decidono cosa vede lo scanner
    (un checkout con file 0600 produce falsi negativi silenziosi). Fissa il comportamento attuale.
    """
    request = lab.request(
        tmp_path / "r", "report", read="secret.txt", workspace_files={"secret.txt": "x"}
    )
    (tmp_path / "r" / "ws" / "secret.txt").chmod(0o600)
    result = ex.run(request)
    assert result.output_dir
    data = json.loads(OutputReader().read_file(result.output_dir, "report.json", 1 << 20))
    assert data["workspace"] == {"error": "Permission denied"}
