"""R-02 (comandi, senza daemon) e R-03 (lettura sicura di `/out`). Nessun Docker."""

import os
from pathlib import Path

import pytest

from ca_core.models import PackagedPluginManifest
from ca_core.ports import Isolation, PluginRunRequest, SourceError, SourceReader, SourceTooLarge
from ca_plugins.runner import (
    OciExecutor,
    OutputReader,
    RuntimeUnavailable,
    bind_mount,
    container_args,
    digest_ref,
)

DIGEST = "sha256:" + "ab" * 32
MANIFEST = PackagedPluginManifest.model_validate(
    {
        "apiVersion": "code-analyzer/v1",
        "name": "demo",
        "version": "1.0.0",
        "image": f"registry.invalid/ca/demo:1.0.0@{DIGEST}",
        "capabilities": ["detect"],
        "languages": [],
        "categories": ["quality"],
        "inputs": {"workspace": "readonly"},
        "outputs": {"sarif": "/out/results.sarif", "max_bytes": 1024},
        "resources": {"cpu": "1.5", "memory": "2Gi", "pids": 77, "timeout": "30s"},
        "network": "none",
    }
)
WORKSPACE = bind_mount(Path("/srv/ws"), "/workspace", readonly=True)


def args(**kw: object) -> list[str]:
    base: dict[str, object] = {
        "name": "ca-demo-1",
        "image": digest_ref(MANIFEST.image),
        "manifest": MANIFEST,
        "mounts": [WORKSPACE],
        "isolation": Isolation.HARDENED_CONTAINER,
    }
    return container_args(**{**base, **kw})  # type: ignore[arg-type]


def test_image_is_run_by_digest_never_by_tag() -> None:
    assert digest_ref(MANIFEST.image) == f"registry.invalid/ca/demo@{DIGEST}"
    assert digest_ref(f"localhost:5000/a/b:1.0.0@{DIGEST}") == f"localhost:5000/a/b@{DIGEST}"
    with pytest.raises(ValueError):
        digest_ref("registry.invalid/ca/demo:1.0.0")
    assert args()[-1] == f"registry.invalid/ca/demo@{DIGEST}"


def test_hardened_profile() -> None:
    a = args()
    pairs = dict(zip(a, a[1:], strict=False))
    assert pairs["--network"] == "none"
    assert pairs["--cap-drop"] == "ALL"
    assert pairs["--security-opt"] == "no-new-privileges"
    assert pairs["--user"] == "65534:65534"
    assert pairs["--tmpfs"] == "/tmp:rw,noexec,nosuid"
    assert pairs["--env"] == "HOME=/tmp"
    assert (pairs["--cpus"], pairs["--memory"], pairs["--memory-swap"]) == (
        "1.5",
        str(2 * 1024**3),
        str(2 * 1024**3),
    )  # byte, senza tmpfs
    assert pairs["--pids-limit"] == "77"
    assert pairs["--pull"] == "never"
    assert "--read-only" in a
    assert a.count("--env") == 1  # nessuna variabile dell'host, nessun `-e NOME`
    assert "--runtime" not in a
    assert "--privileged" not in a and not any("docker.sock" in x for x in a)
    assert "type=bind,src=/srv/ws,dst=/workspace,readonly" in a


def test_gvisor_adds_runtime() -> None:
    a = args(isolation=Isolation.GVISOR)
    assert a[a.index("--runtime") + 1] == "runsc"


def test_code_or_network_never_both() -> None:
    with pytest.raises(ValueError):
        args(network=True)
    sync = args(network=True, mounts=[bind_mount(Path("/s"), "/feeds", readonly=False)])
    assert "--network" not in sync


@pytest.mark.parametrize("path", ["/a,b", '/a"b', "/a\nb"])
def test_mount_path_that_breaks_the_spec_is_refused(path: str) -> None:
    with pytest.raises(Exception, match="percorso"):
        bind_mount(Path(path), "/workspace", readonly=True)


def test_no_oci_runtime_is_explicit_error_with_exit_2() -> None:
    executor = OciExecutor(runtime="ca-no-such-runtime")
    with pytest.raises(RuntimeUnavailable) as err:
        executor.isolation()
    assert err.value.exit_code == 2


def test_without_runtime_the_verifier_is_not_reached() -> None:
    # senza runtime l'esecuzione si ferma prima di ogni verifica: nessun ripiego
    called: list[str] = []
    executor = OciExecutor(runtime="ca-no-such-runtime", verifier=lambda m, i: called.append(i))
    with pytest.raises(RuntimeUnavailable):
        executor.run(PluginRunRequest(manifest=MANIFEST, workspace="/nonexistent"))
    assert called == []


# --- R-03 ---------------------------------------------------------------------------------------


@pytest.fixture
def out(tmp_path: Path) -> Path:
    (tmp_path / "results.sarif").write_bytes(b"x" * 10)
    return tmp_path


def test_reader_is_a_source_reader() -> None:
    assert isinstance(OutputReader(), SourceReader)


def test_reads_regular_file_and_lists_first_level_only(out: Path) -> None:
    (out / "sub").mkdir()
    (out / "sub" / "x").write_bytes(b"1")
    (out / "link").symlink_to("/etc/passwd")
    os.mkfifo(out / "fifo")
    reader = OutputReader()
    assert reader.read_file(str(out), "results.sarif", 10) == b"x" * 10
    assert reader.list_files(str(out)) == ["results.sarif"]


def test_over_the_limit_is_refused_without_reading(out: Path) -> None:
    with pytest.raises(SourceTooLarge):
        OutputReader().read_file(str(out), "results.sarif", 9)


def test_file_that_grows_after_fstat_is_not_read_past_the_limit(
    out: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import ca_plugins.runner as runner

    real = runner._open_regular
    monkeypatch.setattr(runner, "_open_regular", lambda d, n, m: (real(d, n, 10**6)[0], 0))
    with pytest.raises(SourceTooLarge):
        OutputReader().read_file(str(out), "results.sarif", 9)


@pytest.mark.parametrize("name", ["../x", "a/b", "/etc/passwd", "", ".", "..", "a\x00b"])
def test_paths_outside_first_level_are_refused(out: Path, name: str) -> None:
    with pytest.raises(SourceError):
        OutputReader().read_file(str(out), name, 100)


def test_symlink_is_refused_even_inside_the_root(out: Path) -> None:
    (out / "alias").symlink_to("results.sarif")
    (out / "evil").symlink_to("/etc/passwd")
    for name in ("alias", "evil"):
        with pytest.raises(SourceError):
            OutputReader().read_file(str(out), name, 10_000)
        with pytest.raises(SourceError):
            OutputReader().check(str(out), name, 10_000)


def test_fifo_directory_and_missing_are_refused_without_blocking(out: Path) -> None:
    os.mkfifo(out / "fifo")
    (out / "dir").mkdir()
    for name in ("fifo", "dir", "missing"):
        with pytest.raises(SourceError):
            OutputReader().read_file(str(out), name, 100)


def test_root_must_be_a_real_directory(tmp_path: Path) -> None:
    (tmp_path / "real").mkdir()
    (tmp_path / "link").symlink_to(tmp_path / "real")
    with pytest.raises(SourceError):
        OutputReader().list_files(str(tmp_path / "link"))
    with pytest.raises(SourceError):
        OutputReader().list_files(str(tmp_path / "missing"))


# --- R-05 ---------------------------------------------------------------------------------------


def test_min_isolation_below_available_exits_2_before_any_container() -> None:
    from ca_plugins.runner import IsolationUnsatisfied, require_isolation

    require_isolation(Isolation.GVISOR, Isolation.GVISOR)
    require_isolation(Isolation.GVISOR, Isolation.HARDENED_CONTAINER)
    require_isolation(Isolation.HARDENED_CONTAINER, Isolation.HARDENED_CONTAINER)
    require_isolation(Isolation.HARDENED_CONTAINER, None)
    with pytest.raises(IsolationUnsatisfied) as err:
        require_isolation(Isolation.HARDENED_CONTAINER, Isolation.GVISOR)
    assert err.value.exit_code == 2


def _fake_docker(tmp_path: Path, runtimes: str) -> str:
    script = tmp_path / "docker"
    script.write_text(f"#!/bin/sh\n[ \"$1\" = info ] && echo '{runtimes}' && exit 0\nexit 1\n")
    script.chmod(0o755)
    return str(script)


@pytest.mark.parametrize(
    ("runtimes", "expected"),
    [
        ('{"runc":{},"runsc":{"path":"/usr/bin/runsc"}}', Isolation.GVISOR),
        ('{"runc":{}}', Isolation.HARDENED_CONTAINER),
        ("non json", Isolation.HARDENED_CONTAINER),
    ],
)
def test_runsc_registered_selects_gvisor(
    tmp_path: Path, runtimes: str, expected: Isolation
) -> None:
    assert OciExecutor(runtime=_fake_docker(tmp_path, runtimes)).isolation() is expected


# --- R-07 ---------------------------------------------------------------------------------------


def _stub_executor(tmp_path: Path, behavior: object, **kw: int) -> OciExecutor:
    from ca_core.ports import PluginRunResult, RunOutcome

    executor = OciExecutor(work_dir=str(tmp_path), **kw)
    executor.isolation = lambda: Isolation.HARDENED_CONTAINER  # type: ignore[method-assign]
    assert PluginRunResult and RunOutcome
    executor._execute = behavior  # type: ignore[method-assign,assignment]
    return executor


def _requests(tmp_path: Path, n: int) -> list[PluginRunRequest]:
    ws = tmp_path / "ws"
    ws.mkdir(exist_ok=True)
    return [PluginRunRequest(manifest=MANIFEST, workspace=str(ws)) for _ in range(n)]


def _res(outcome: str, code: int | None, detail: str | None = None) -> object:
    from ca_core.ports import PluginRunResult, RunOutcome, Signature

    return PluginRunResult(
        outcome=RunOutcome(outcome),
        exit_code=code,
        isolation=Isolation.HARDENED_CONTAINER,
        signature=Signature.VERIFIED,
        duration_seconds=0.5,
        output_dir=None,
        detail=detail,
    )


def test_run_many_is_parallel_bounded_and_keeps_order(tmp_path: Path) -> None:
    import threading

    barrier = threading.Barrier(3, timeout=10)  # passa solo se 3 esecuzioni sono contemporanee
    live = {"now": 0, "max": 0}
    lock = threading.Lock()
    seen: list[int] = []

    def execute(manifest: object, mounts: object, isolation: object, **kw: object) -> object:
        with lock:
            live["now"] += 1
            live["max"] = max(live["max"], live["now"])
            seen.append(len(seen))
        try:
            barrier.wait()
        finally:
            with lock:
                live["now"] -= 1
        return _res("ok", 0)

    results = _stub_executor(tmp_path, execute, max_parallel=3).run_many(_requests(tmp_path, 3))
    assert [r.outcome.value for r in results] == ["ok"] * 3
    assert live["max"] == 3
    with pytest.raises(ValueError):
        OciExecutor(max_parallel=0)


def test_run_many_respects_max_parallel(tmp_path: Path) -> None:
    import threading
    import time as _time

    live = {"now": 0, "max": 0}
    lock = threading.Lock()

    def execute(manifest: object, mounts: object, isolation: object, **kw: object) -> object:
        with lock:
            live["now"] += 1
            live["max"] = max(live["max"], live["now"])
        _time.sleep(0.05)
        with lock:
            live["now"] -= 1
        return _res("ok", 0)

    _stub_executor(tmp_path, execute, max_parallel=2).run_many(_requests(tmp_path, 6))
    assert live["max"] == 2


def test_distinct_outcomes_do_not_stop_the_others(tmp_path: Path) -> None:
    script = iter(
        [
            _res("failed", 3, "exit 3"),
            _res("timeout", None, "timeout oltre 30s"),
            _res("invalid_output", 0, "output non valido: results.sarif"),
            _res("ok", 0),
        ]
    )
    lock = __import__("threading").Lock()

    def execute(manifest: object, mounts: object, isolation: object, **kw: object) -> object:
        with lock:
            return next(script)

    results = _stub_executor(tmp_path, execute, max_parallel=1).run_many(_requests(tmp_path, 4))
    assert [(r.outcome.value, r.exit_code) for r in results] == [
        ("failed", 3),
        ("timeout", None),
        ("invalid_output", 0),
        ("ok", 0),
    ]
    assert all(r.duration_seconds > 0 for r in results)
    assert len({r.detail for r in results}) == 4  # esiti distinguibili


def test_exception_in_one_run_propagates_after_cleanup(tmp_path: Path) -> None:
    def execute(manifest: object, mounts: object, isolation: object, **kw: object) -> object:
        raise PermissionError("firma assente")

    with pytest.raises(PermissionError):
        _stub_executor(tmp_path, execute).run_many(_requests(tmp_path, 3))
    # le directory delle esecuzioni sono state rimosse
    assert not list(tmp_path.glob("ca-oci-*/run-*"))


def test_preparation_oserror_is_a_failed_result(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def full(*_a: object, **_k: object) -> None:
        raise OSError(28, "No space left on device")

    monkeypatch.setattr("ca_plugins.runner._stage_file", full)
    config = tmp_path / "c.json"
    config.write_text("{}")
    request = _requests(tmp_path, 1)[0].model_copy(update={"config": str(config)})
    manifest = MANIFEST.model_copy(
        update={"inputs": MANIFEST.inputs.model_copy(update={"config": "optional"})}
    )
    request = request.model_copy(update={"manifest": manifest})
    result = _stub_executor(tmp_path, lambda *a, **k: _res("ok", 0)).run(request)
    assert result.outcome.value == "failed"
    assert (result.detail or "").startswith("errore di preparazione")
    assert not list(tmp_path.glob("ca-oci-*/run-*"))
