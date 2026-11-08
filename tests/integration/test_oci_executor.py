"""`OciExecutor` contro un daemon Docker reale, con il plugin finto (T-02). Opzionale.

Si attiva con `CA_TEST_DOCKER=1`. Costruisce `localhost/ca-fake-plugin:oci-test` (nessuna rete oltre
il pull della base già in cache) e lo rimuove a fine sessione; ogni test verifica che non resti
alcun container del runner. `runsc` e Podman non sono coperti.
"""

import json
import os
import shutil
import subprocess
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from ca_core.models import PackagedPluginManifest
from ca_core.ports import (
    FeedsSyncRequest,
    Isolation,
    PluginExecutor,
    PluginRunRequest,
    RunOutcome,
    Signature,
)
from ca_plugins.runner import OciExecutor, OutputReader

FAKE = Path(__file__).resolve().parents[1] / "fixtures" / "plugins" / "fake"
TAG = "localhost/ca-fake-plugin:oci-test"

pytestmark = pytest.mark.skipif(
    os.environ.get("CA_TEST_DOCKER") != "1" or shutil.which("docker") is None,
    reason="richiede un daemon Docker: CA_TEST_DOCKER=1",
)


def docker(*args: str) -> str:
    return subprocess.run(
        ["docker", *args], capture_output=True, text=True, check=True, timeout=300
    ).stdout.strip()


def leftovers() -> list[str]:
    return docker("ps", "-aq", "--filter", "label=code-analyzer.executor=1").split()


@pytest.fixture(scope="module")
def image_id() -> Iterator[str]:
    docker("build", "-q", "-t", TAG, str(FAKE))
    yield docker("image", "inspect", "--format", "{{.Id}}", TAG)
    subprocess.run(["docker", "rmi", "-f", TAG], capture_output=True, check=False)


def manifest(image_id: str, **resources: Any) -> PackagedPluginManifest:
    data = json.loads((FAKE / "plugin.yaml").read_text())
    data["image"] = f"localhost/ca-fake-plugin:oci-test@{image_id}"
    data["resources"].update(resources)
    return PackagedPluginManifest.model_validate(data)


@pytest.fixture
def executor(image_id: str, tmp_path: Path) -> Iterator[OciExecutor]:
    # La base locale non ha digest di registry: si esegue l'ID immutabile dell'immagine.
    with OciExecutor(work_dir=str(tmp_path), image_ref=lambda _: image_id) as ex:
        yield ex
    assert leftovers() == []


def request(image_id: str, tmp_path: Path, behavior: str, **res: Any) -> PluginRunRequest:
    tmp_path.mkdir(exist_ok=True)
    workspace = tmp_path / "ws"
    workspace.mkdir(exist_ok=True)
    (workspace / "app.py").write_text("print(1)\n")
    config = tmp_path / "config.json"
    config.write_text(json.dumps({"behavior": behavior}))
    config.chmod(0o600)  # il runner lo rende leggibile da 65534
    return PluginRunRequest(
        manifest=manifest(image_id, **res), workspace=str(workspace), config=str(config)
    )


def test_executor_is_a_port_and_reports_isolation(executor: OciExecutor) -> None:
    assert isinstance(executor, PluginExecutor)
    runtimes = docker("info", "--format", "{{json .Runtimes}}")
    expected = Isolation.GVISOR if "runsc" in runtimes else Isolation.HARDENED_CONTAINER
    assert executor.isolation() is expected


def test_success_output_is_readable_and_released(
    executor: OciExecutor, image_id: str, tmp_path: Path
) -> None:
    result = executor.run(request(image_id, tmp_path, "success"))
    assert (result.outcome, result.exit_code, result.detail) == (RunOutcome.OK, 0, None)
    assert result.output_dir is not None
    run_dir = Path(result.output_dir).parent
    assert oct(run_dir.stat().st_mode & 0o777) == "0o700"
    assert oct(Path(result.output_dir).stat().st_mode & 0o777) == "0o777"
    data = OutputReader().read_file(result.output_dir, "results.sarif", 1_048_576)
    assert b'"version"' in data
    executor.release(result.output_dir)
    assert not run_dir.exists()


def test_plugin_writes_as_nobody_in_out_and_tmp(
    executor: OciExecutor, image_id: str, tmp_path: Path
) -> None:
    result = executor.run(request(image_id, tmp_path, "write-out"))
    assert result.outcome is RunOutcome.OK and result.output_dir
    assert OutputReader().list_files(result.output_dir) == ["extra.txt", "results.sarif"]
    assert (Path(result.output_dir) / "extra.txt").stat().st_uid == 65534
    assert executor.run(request(image_id, tmp_path, "write-tmp")).outcome is RunOutcome.OK


@pytest.mark.parametrize("behavior", ["network", "write-workspace", "write-rootfs", "exec-tmp"])
def test_hostile_attempts_are_blocked_by_the_profile(
    executor: OciExecutor, image_id: str, tmp_path: Path, behavior: str
) -> None:
    # il plugin finto esce con 4 se il tentativo riesce
    result = executor.run(request(image_id, tmp_path, behavior))
    assert (result.outcome, result.exit_code) == (RunOutcome.OK, 0)


def test_exit_nonzero_fails_without_exposing_output(
    executor: OciExecutor, image_id: str, tmp_path: Path
) -> None:
    result = executor.run(request(image_id, tmp_path, "exit-nonzero"))
    assert (result.outcome, result.exit_code, result.output_dir) == (RunOutcome.FAILED, 3, None)


def test_unknown_behavior_exit_64(executor: OciExecutor, image_id: str, tmp_path: Path) -> None:
    assert executor.run(request(image_id, tmp_path, "rm-rf")).exit_code == 64


def test_symlink_out_fails_the_plugin(executor: OciExecutor, image_id: str, tmp_path: Path) -> None:
    result = executor.run(request(image_id, tmp_path, "symlink-out"))
    assert result.outcome is RunOutcome.FAILED
    assert result.detail == "output non valido: results.sarif"
    assert result.output_dir is None


def test_oversize_fails_the_plugin(executor: OciExecutor, image_id: str, tmp_path: Path) -> None:
    result = executor.run(request(image_id, tmp_path, "oversize"))
    assert result.outcome is RunOutcome.FAILED
    assert result.detail == "output oltre il limite: results.sarif"
    assert result.output_dir is None


def test_timeout_kills_the_container_not_just_the_client(
    executor: OciExecutor, image_id: str, tmp_path: Path
) -> None:
    started = time.monotonic()
    result = executor.run(request(image_id, tmp_path, "timeout", timeout="2s"))
    assert result.outcome is RunOutcome.TIMEOUT and result.output_dir is None
    assert time.monotonic() - started < 30
    assert leftovers() == []  # `timeout docker run` lascerebbe il container vivo (T-02)


def test_verifier_failure_starts_no_container(image_id: str, tmp_path: Path) -> None:
    def deny(_m: PackagedPluginManifest, _ref: str) -> Signature:
        raise PermissionError("firma assente")

    with OciExecutor(work_dir=str(tmp_path), verifier=deny, image_ref=lambda _: image_id) as ex:
        with pytest.raises(PermissionError):
            ex.run(request(image_id, tmp_path, "success"))
    assert leftovers() == []


def test_missing_image_by_digest_fails_cleanly_without_pulling(
    image_id: str, tmp_path: Path
) -> None:
    with OciExecutor(work_dir=str(tmp_path)) as ex:  # riferimento per digest: non è locale
        result = ex.run(request(image_id, tmp_path, "success"))
    assert result.outcome is RunOutcome.FAILED and (result.detail or "").startswith("create")
    assert leftovers() == []


def test_unreadable_workspace_is_a_failed_result(
    executor: OciExecutor, image_id: str, tmp_path: Path
) -> None:
    req = request(image_id, tmp_path, "success").model_copy(update={"workspace": "/no/such/dir"})
    assert executor.run(req).outcome is RunOutcome.FAILED


def test_feeds_sync_has_network_and_no_workspace(
    executor: OciExecutor, image_id: str, tmp_path: Path
) -> None:
    data = json.loads((FAKE / "plugin.yaml").read_text())
    data["image"] = f"localhost/ca-fake-plugin:oci-test@{image_id}"
    data["feeds"] = {
        "sync_command": ["python", "-c", "open('/feeds/db','w').write('1')"],
        "ecosystems": ["npm"],
        "mount": "/feeds",
        "sync_timeout": "20s",
    }
    snapshot = tmp_path / "snap"
    snapshot.mkdir()
    snapshot.chmod(0o777)
    result = executor.sync_feeds(
        FeedsSyncRequest(
            manifest=PackagedPluginManifest.model_validate(data), snapshot_dir=str(snapshot)
        )
    )
    assert (result.outcome, result.output_dir) == (RunOutcome.OK, None)
    assert (snapshot / "db").read_text() == "1"


def test_run_many_runs_in_parallel_with_distinct_outcomes(image_id: str, tmp_path: Path) -> None:
    reqs = [
        request(image_id, tmp_path / "a", "success"),
        request(image_id, tmp_path / "b", "exit-nonzero"),
        request(image_id, tmp_path / "c", "timeout", timeout="3s"),
        request(image_id, tmp_path / "d", "symlink-out"),
        request(image_id, tmp_path / "e", "success"),
    ]
    with OciExecutor(work_dir=str(tmp_path), image_ref=lambda _: image_id, max_parallel=5) as ex:
        started = time.monotonic()
        results = ex.run_many(reqs)
        elapsed = time.monotonic() - started
        for r in results:
            if r.output_dir:
                ex.release(r.output_dir)
    assert [(r.outcome.value, r.exit_code) for r in results] == [
        ("ok", 0),
        ("failed", 3),
        ("timeout", None),
        ("failed", 0),
        ("ok", 0),
    ]
    assert results[3].detail == "output non valido: results.sarif"
    assert all(r.duration_seconds > 0 for r in results)
    assert elapsed < 40
    assert leftovers() == []
