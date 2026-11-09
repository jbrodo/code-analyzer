# ruff: noqa: F401, F811  (le fixture di t03_support si importano e si usano come argomenti)
"""R-09, M-03: ciclo di vita, interruzione e orfani, con un daemon Docker reale.

Provato: nessun container, custodia o volume resta dopo esiti ok, falliti, a timeout o
interrotti; `abort()` e un SIGTERM al processo fermano i container in corsa; all'avvio si
rimuovono solo gli orfani scaduti (etichetta scaduta, assente o non numerica).
Non provato: SIGKILL del client (residuo noto, ADR-0004), Podman, gVisor.
"""

import os
import signal
import subprocess
import sys
import threading
import time
import uuid
from pathlib import Path

import pytest
from t03_support import ROOT, Lab, ex, lab, needs_docker, work

from ca_core.ports import RunOutcome

pytestmark = needs_docker

FILTER = ["--filter", "label=code-analyzer.executor=1"]


def dangling(lab: Lab) -> list[str]:
    return lab.docker("volume", "ls", "-q", "--filter", "dangling=true", *FILTER).split()


def names(lab: Lab, kind: str, *needle: str) -> list[str]:
    cmd = ["ps", "-a", "--format", "{{.Names}}"] if kind == "c" else ["volume", "ls", "-q"]
    return [n for n in lab.docker(*cmd, *FILTER).split() if n.startswith(needle)]


@pytest.mark.parametrize(
    ("behavior", "outcome"),
    [
        ("success", RunOutcome.OK),
        ("exit-nonzero", RunOutcome.FAILED),
        ("timeout", RunOutcome.TIMEOUT),
        ("symlink-out", RunOutcome.INVALID_OUTPUT),
    ],
)
def test_nothing_remains_after_any_outcome(
    ex: object, lab: Lab, tmp_path: Path, behavior: str, outcome: RunOutcome
) -> None:
    timeout = "2s" if behavior == "timeout" else "10s"
    result = ex.run(lab.request(tmp_path / "r", behavior, timeout=timeout))  # type: ignore[attr-defined]
    assert result.outcome is outcome
    assert lab.containers() == [] and dangling(lab) == []


def test_abort_stops_a_running_plugin_and_leaves_nothing(
    ex: object, lab: Lab, tmp_path: Path
) -> None:
    box: list[object] = []
    request = lab.request(tmp_path / "r", "timeout", timeout="60s")
    thread = threading.Thread(target=lambda: box.append(ex.run(request)))  # type: ignore[attr-defined]
    thread.start()
    deadline = time.monotonic() + 30
    while len(lab.containers()) < 2 and time.monotonic() < deadline:  # plugin + custodia
        time.sleep(0.2)
    assert len(lab.containers()) == 2
    started = time.monotonic()
    ex.abort()  # type: ignore[attr-defined]
    thread.join(30)
    assert not thread.is_alive() and time.monotonic() - started < 20
    assert lab.containers() == [] and dangling(lab) == []


def make_orphan(lab: Lab, tag: str, expires: str | None) -> tuple[str, str]:
    """Container (creato, non avviato) e volume con l'etichetta del runner."""
    token = f"{tag}-{uuid.uuid4().hex[:8]}"
    labels = ["--label", "code-analyzer.executor=1"]
    if expires is not None:
        labels += ["--label", f"code-analyzer.expires={expires}"]
    container, volume = f"ca-r09orphan-{token}", f"ca-out-r09orphan-{token}"
    lab.docker("create", "--name", container, *labels, "--pull", "never", lab.image_id)
    lab.docker("volume", "create", *labels, volume)
    return container, volume


def test_startup_sweep_removes_only_expired_absent_or_malformed_orphans(
    lab: Lab, work: Path, tmp_path: Path
) -> None:
    future = str(int(time.time()) + 3600)
    cases = {
        "old": make_orphan(lab, "old", "1"),
        "none": make_orphan(lab, "none", None),
        "bad": make_orphan(lab, "bad", "abc"),
        "fresh": make_orphan(lab, "fresh", future),
    }
    try:
        with lab.executor(work) as executor:
            assert executor.run(lab.request(tmp_path / "r", "success")).outcome is RunOutcome.OK
        for key in ("old", "none", "bad"):
            container, volume = cases[key]
            assert names(lab, "c", container) == [] and names(lab, "v", volume) == [], key
        container, volume = cases["fresh"]  # di un'altra scansione ancora valida: intatta
        assert names(lab, "c", container) == [container]
        assert names(lab, "v", volume) == [volume]
    finally:
        for container, volume in cases.values():
            subprocess.run(["docker", "rm", "-f", container], capture_output=True, check=False)
            subprocess.run(
                ["docker", "volume", "rm", "-f", volume], capture_output=True, check=False
            )


def test_containers_and_volumes_carry_an_expiry_label_after_the_run_timeout(
    ex: object, lab: Lab, tmp_path: Path
) -> None:
    box: list[object] = []
    request = lab.request(tmp_path / "r", "timeout", timeout="30s")
    thread = threading.Thread(target=lambda: box.append(ex.run(request)))  # type: ignore[attr-defined]
    thread.start()
    deadline = time.monotonic() + 30
    while len(lab.containers()) < 2 and time.monotonic() < deadline:
        time.sleep(0.2)
    try:
        label = '{{index .Config.Labels "code-analyzer.expires"}}'
        found = [int(lab.docker("inspect", "--format", label, c)) for c in lab.containers()]
        assert len(found) == 2
        now = time.time()
        assert all(now + 30 + 900 - 60 <= value <= now + 30 + 900 + 5 for value in found)
        volumes = [
            v for v in lab.docker("volume", "ls", "-q", *FILTER).split() if v.startswith("ca-out-")
        ]
        vlabel = '{{index .Labels "code-analyzer.expires"}}'
        mine = [int(lab.docker("volume", "inspect", "--format", vlabel, v) or 0) for v in volumes]
        assert any(now + 30 + 900 - 60 <= value <= now + 30 + 900 + 5 for value in mine)
    finally:
        ex.abort()  # type: ignore[attr-defined]
        thread.join(30)


CHILD = """
import sys
from ca_cli.main import _interruptible
from ca_core.ports import PluginRunRequest
from ca_plugins.runner import OciExecutor
image = sys.argv[1]
requests = [PluginRunRequest.model_validate_json(open(p).read()) for p in sys.argv[3:]]
ex = OciExecutor(work_dir=sys.argv[2], image_ref=lambda _: image, max_parallel=1)
with _interruptible():
    try:
        ex.run_many(requests)
    except KeyboardInterrupt:
        sys.exit(2)
    finally:
        ex.close()
"""


def test_sigterm_to_the_process_stops_containers_and_cancels_the_queue(
    lab: Lab, work: Path, tmp_path: Path
) -> None:
    files = []
    for i in range(4):  # max_parallel=1: dopo il segnale la coda non deve partire
        request = lab.request(tmp_path / f"r{i}", "timeout", timeout="60s")
        path = tmp_path / f"req{i}.json"
        path.write_text(request.model_dump_json())
        files.append(str(path))
    proc = subprocess.Popen(
        [sys.executable, "-I", "-c", CHILD, lab.image_id, str(work), *files],
        env={"PATH": os.environ["PATH"], "HOME": os.environ.get("HOME", "/tmp")},
        cwd=ROOT,
    )
    try:
        deadline = time.monotonic() + 60
        while len(lab.containers()) < 2 and time.monotonic() < deadline:
            time.sleep(0.2)
        assert len(lab.containers()) == 2
        proc.send_signal(signal.SIGTERM)
        proc.send_signal(signal.SIGTERM)  # il secondo non interrompe la pulizia
        assert proc.wait(timeout=60) == 2
        assert lab.containers() == [] and dangling(lab) == []
        time.sleep(2)  # nessun container della coda parte dopo l'interruzione
        assert lab.containers() == []
    finally:
        if proc.poll() is None:
            proc.kill()


# --- /feeds: guardia, `--ulimit fsize` e `purge_feeds` (ADR-0006) -------------------------


def feeds_request(lab: Lab, base: Path, code: str, max_bytes: int, timeout: str = "30s"):  # type: ignore[no-untyped-def]
    from ca_core.models import PackagedPluginManifest
    from ca_core.ports import FeedsSyncRequest

    data = lab.manifest().model_dump(mode="json", exclude_none=True)
    data["feeds"] = {
        "sync_command": ["python", "-c", code],
        "ecosystems": ["npm"],
        "mount": "/feeds",
        "sync_timeout": timeout,
    }
    snapshot = base / "snap"
    snapshot.mkdir(parents=True)
    snapshot.chmod(0o777)
    request = FeedsSyncRequest(
        manifest=PackagedPluginManifest.model_validate(data),
        snapshot_dir=str(snapshot),
        max_bytes=max_bytes,
    )
    return request, snapshot


def test_guard_stops_a_sync_that_writes_more_than_max_bytes(
    ex: object, lab: Lab, tmp_path: Path
) -> None:
    code = (
        "import time\n"
        "for i in range(10000):\n"
        "    open(f'/feeds/f{i}', 'wb').write(b'0' * 1048576)\n"
        "    time.sleep(0.05)\n"
    )
    request, snapshot = feeds_request(lab, tmp_path, code, max_bytes=8 * 1024**2)
    started = time.monotonic()
    result = ex.sync_feeds(request)  # type: ignore[attr-defined]
    assert result.outcome is RunOutcome.FAILED
    assert result.detail == "sincronizzazione dei feed oltre i limiti di byte o di voci"
    assert time.monotonic() - started < 25
    total = sum(p.stat().st_blocks * 512 for p in snapshot.iterdir())
    assert total < 8 * 1024**2 + 64 * 1024**2  # fermata entro pochi controlli: nessun riempimento
    assert lab.containers() == []


def test_fsize_ulimit_stops_a_single_file_at_max_bytes(
    ex: object, lab: Lab, tmp_path: Path
) -> None:
    code = "open('/feeds/big', 'wb').write(b'0' * (64 * 1048576))"
    request, snapshot = feeds_request(lab, tmp_path, code, max_bytes=1024**2)
    result = ex.sync_feeds(request)  # type: ignore[attr-defined]
    assert result.outcome is RunOutcome.FAILED  # SIGXFSZ
    assert (snapshot / "big").stat().st_size <= 1024**2


def test_purge_feeds_removes_what_the_host_cannot_delete(
    ex: object, lab: Lab, tmp_path: Path
) -> None:
    import shutil

    code = (
        "import os\n"
        "os.makedirs('/feeds/a/b')\n"
        "open('/feeds/a/b/f', 'w').write('x')\n"
        "os.symlink('/etc', '/feeds/a/link')\n"
        "os.chmod('/feeds/a/b', 0o555)\n"
        "os.chmod('/feeds/a', 0o555)\n"
    )
    request, snapshot = feeds_request(lab, tmp_path, code, max_bytes=1024**2)
    assert ex.sync_feeds(request).outcome is RunOutcome.OK  # type: ignore[attr-defined]
    shutil.rmtree(snapshot, ignore_errors=True)
    assert snapshot.exists()  # M-01: l'host non riesce, e senza errore
    from ca_core.ports import FeedsPurgeRequest

    ex.purge_feeds(FeedsPurgeRequest(manifest=request.manifest, snapshot_dir=str(snapshot)))  # type: ignore[attr-defined]
    assert list(snapshot.iterdir()) == []
    shutil.rmtree(snapshot)
    assert Path("/etc/passwd").exists()  # il symlink a /etc non è stato seguito
    assert lab.containers() == []
