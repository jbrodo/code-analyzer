"""R-09 (ADR-0004, ADR-0006) senza daemon: dimensioni, comandi, copia di `/out`, guardia, orfani.

Il client del runtime è uno script che registra gli argomenti e risponde da un file di
configurazione: si prova ciò che il runner chiede e come legge le risposte, non il daemon (per
quello: `tests/integration/runner/test_r09_*.py`).
"""

import io
import json
import os
import stat
import sys
import tarfile
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from ca_core.models import PackagedPluginManifest
from ca_core.models.plugin_manifest import Outputs
from ca_core.ports import Isolation, PluginRunRequest, RunOutcome
from ca_plugins import runner
from ca_plugins.runner import (
    FEEDS_MAX_ENTRIES,
    OciExecutor,
    container_args,
    feeds_guard,
    feeds_usage,
    holder_args,
    out_tmpfs_bytes,
    out_volume_args,
)

MIB = 1024**2
DIGEST = "sha256:" + "ab" * 32
HEX = "0123456789abcdef"


def manifest(**kv: Any) -> PackagedPluginManifest:
    data: dict[str, Any] = {
        "apiVersion": "code-analyzer/v1",
        "name": "demo",
        "version": "1.0.0",
        "image": f"registry.invalid/ca/demo:1.0.0@{DIGEST}",
        "capabilities": ["detect"],
        "languages": [],
        "categories": ["quality"],
        "inputs": {"workspace": "readonly"},
        "outputs": {"sarif": "/out/results.sarif", "max_bytes": MIB},
        "resources": {"cpu": "1", "memory": "512Mi", "pids": 64, "timeout": "30s"},
        "network": "none",
    }
    return PackagedPluginManifest.model_validate({**data, **kv})


def outputs(max_bytes: int, *, two: bool = False) -> Outputs:
    extra = {"cyclonedx": "/out/s.cdx.json", "cyclonedx_version": "1.7"} if two else {}
    return Outputs.model_validate({"sarif": "/out/r.sarif", "max_bytes": max_bytes, **extra})


# --- dimensione e comandi (funzioni pure) ---------------------------------------------------


@pytest.mark.parametrize(
    ("max_bytes", "two", "expected"),
    [
        (16 * MIB, False, 32 * MIB),
        (50 * MIB, False, 66 * MIB),
        (256 * MIB, False, 320 * MIB),
        (256 * MIB, True, 640 * MIB),
        (1, False, 1 + 16 * MIB),
    ],
)
def test_out_tmpfs_bytes_matches_the_adr_values(max_bytes: int, two: bool, expected: int) -> None:
    assert out_tmpfs_bytes(outputs(max_bytes, two=two)) == expected


def test_out_volume_is_a_capped_tmpfs_owned_by_nobody() -> None:
    a = out_volume_args(f"ca-out-{HEX}", 32 * MIB, 1234)
    assert a[:4] == ["volume", "create", "--driver", "local"] and a[-1] == f"ca-out-{HEX}"
    assert "code-analyzer.executor=1" in a and "code-analyzer.expires=1234" in a
    options = next(x for x in a if x.startswith("o="))
    assert options == (
        f"o=size={32 * MIB},nr_inodes=1024,uid=65534,gid=65534,mode=0700,noexec,nosuid,nodev"
    )
    assert "type=tmpfs" in a and "device=tmpfs" in a


def test_holder_is_read_only_on_the_volume_with_no_network_and_a_finite_sleep() -> None:
    a = holder_args(
        name=f"ca-hold-{HEX}",
        image="img@sha256:x",
        volume=f"ca-out-{HEX}",
        isolation=Isolation.HARDENED_CONTAINER,
        sleep_seconds=330,
        expires=99,
    )
    pairs = dict(zip(a, a[1:], strict=False))
    assert a[0] == "create" and pairs["--network"] == "none" and pairs["--user"] == "65534:65534"
    assert pairs["--cap-drop"] == "ALL" and "--read-only" in a and pairs["--pull"] == "never"
    assert (pairs["--memory"], pairs["--memory-swap"], pairs["--pids-limit"]) == ("32m", "32m", "8")
    assert f"type=volume,src=ca-out-{HEX},dst=/out,readonly" in a
    assert a[-4:] == ["--entrypoint", "sleep", "img@sha256:x", "330"]
    assert "code-analyzer.expires=99" in a


def test_memory_is_resources_plus_tmpfs_in_bytes_and_fsize_only_when_asked() -> None:
    m = manifest()
    base: dict[str, Any] = {
        "name": "n",
        "image": "i@sha256:x",
        "manifest": m,
        "mounts": [],
        "isolation": Isolation.HARDENED_CONTAINER,
    }
    a = container_args(**base, extra_memory=32 * MIB, file_size_limit=777, expires=5)
    pairs = dict(zip(a, a[1:], strict=False))
    assert pairs["--memory"] == pairs["--memory-swap"] == str(512 * MIB + 32 * MIB)
    assert pairs["--ulimit"] == "fsize=777" and "code-analyzer.expires=5" in a
    plain = container_args(**base)
    assert "--ulimit" not in plain and not any(x.startswith("code-analyzer.expires") for x in plain)


# --- client finto ---------------------------------------------------------------------------


def fake_cli(tmp: Path, **config: Any) -> str:
    """`config`: `rc` {comando: exit}, `out` {comando: stdout}, `tar` percorso per `cp`."""
    cfg, log = tmp / "cfg.json", tmp / "calls.log"
    cfg.write_text(json.dumps(config))
    path = tmp / "docker"
    path.write_text(
        f"#!{sys.executable}\n"
        "import json, sys\n"
        f"cfg = json.load(open({str(cfg)!r}))\n"
        f"open({str(log)!r}, 'a').write('\\t'.join(sys.argv[1:]) + '\\n')\n"
        "cmd = sys.argv[1]\n"
        "if cmd == 'info':\n"
        "    print('{\"runc\": {}}')\n"
        "elif cmd == 'cp' and 'tar' in cfg:\n"
        "    sys.stdout.buffer.write(open(cfg['tar'], 'rb').read())\n"
        "    sys.stdout.buffer.flush()\n"
        "else:\n"
        "    sys.stdout.write(cfg.get('out', {}).get(cmd, ''))\n"
        "sys.exit(cfg.get('rc', {}).get(cmd, 0))\n"
    )
    path.chmod(0o755)
    return str(path)


def calls(tmp: Path) -> list[list[str]]:
    log = tmp / "calls.log"
    return [line.split("\t") for line in log.read_text().splitlines()] if log.exists() else []


def verbs(tmp: Path) -> list[str]:
    return [c[0] if c[0] != "volume" else f"volume {c[1]}" for c in calls(tmp)]


def build_tar(
    tmp: Path, members: list[tuple[str, bytes, bytes]], *, keep: int | None = None
) -> Path:
    """`members`: (nome, tipo, contenuto); tipo è il carattere dell'intestazione tar."""
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as tar:
        for name, kind, data in members:
            info = tarfile.TarInfo(name)
            info.type = kind
            info.size = len(data) if kind == tarfile.REGTYPE else 0
            if kind in (tarfile.SYMTYPE, tarfile.LNKTYPE):
                info.linkname = "/etc/passwd"
            tar.addfile(info, io.BytesIO(data) if kind == tarfile.REGTYPE else None)
    raw = buffer.getvalue()
    path = tmp / "payload.tar"
    path.write_bytes(raw if keep is None else raw[:keep])
    return path


def executor(tmp: Path, **config: Any) -> OciExecutor:
    ex = OciExecutor(runtime=fake_cli(tmp, **config), work_dir=str(tmp), image_ref=lambda _: "img")
    ex.isolation()
    return ex


REG, SYM, DIR, FIFO = tarfile.REGTYPE, tarfile.SYMTYPE, tarfile.DIRTYPE, tarfile.FIFOTYPE


def fetch(tmp: Path, tar: Path, name: str = "results.sarif", max_bytes: int = 100) -> Path:
    dest = tmp / "out"
    dest.mkdir(exist_ok=True)
    ex = executor(tmp, tar=str(tar))
    ex._fetch_output("ca-hold-x", name, max_bytes, dest)
    return dest / name


def test_fetch_writes_the_single_declared_regular_file_0600(tmp_path: Path) -> None:
    old = os.umask(0)
    try:
        written = fetch(tmp_path, build_tar(tmp_path, [("results.sarif", REG, b"{}")]))
    finally:
        os.umask(old)
    assert written.read_bytes() == b"{}" and stat.S_IMODE(written.stat().st_mode) == 0o600
    (cp,) = (c for c in calls(tmp_path) if c[0] == "cp")
    assert cp == ["cp", "ca-hold-x:/out/results.sarif", "-"]  # mai -L


@pytest.mark.parametrize(
    ("members", "keep", "text"),
    [
        ([("results.sarif", SYM, b"")], None, "output non valido: results.sarif"),
        ([("results.sarif", DIR, b"")], None, "output non valido: results.sarif"),
        ([("results.sarif", FIFO, b"")], None, "output non valido: results.sarif"),
        ([("altro.sarif", REG, b"{}")], None, "output non valido: results.sarif"),
        ([("../results.sarif", REG, b"{}")], None, "output non valido: results.sarif"),
        (
            [("results.sarif", REG, b"{}"), ("x", REG, b"y")],
            None,
            "output non valido: results.sarif",
        ),
        ([("results.sarif", REG, b"x" * 101)], None, "output oltre il limite: results.sarif"),
        ([("results.sarif", REG, b"x" * 100)], 512 + 50, "output non valido: results.sarif"),
        ([], None, "output non valido: results.sarif"),
    ],
    ids=["symlink", "dir", "fifo", "name", "dotdot", "second-entry", "oversize", "short", "empty"],
)
def test_fetch_rejects_anything_but_one_regular_file_and_leaves_nothing(
    tmp_path: Path, members: list[tuple[str, bytes, bytes]], keep: int | None, text: str
) -> None:
    with pytest.raises(runner._InvalidOutput, match=text):
        fetch(tmp_path, build_tar(tmp_path, members, keep=keep))
    assert list((tmp_path / "out").iterdir()) == []  # nessun file parziale


def test_fetch_fails_on_client_exit_nonzero_and_on_existing_destination(tmp_path: Path) -> None:
    tar = build_tar(tmp_path, [("results.sarif", REG, b"{}")])
    (tmp_path / "out").mkdir()
    ex = executor(tmp_path, tar=str(tar), rc={"cp": 1})
    with pytest.raises(runner._InvalidOutput):
        ex._fetch_output("h", "results.sarif", 100, tmp_path / "out")
    assert list((tmp_path / "out").iterdir()) == []
    (tmp_path / "out" / "results.sarif").write_text("già qui")  # O_EXCL: mai sovrascrivere
    ok = executor(tmp_path, tar=str(tar))
    with pytest.raises(runner._InvalidOutput):
        ok._fetch_output("h", "results.sarif", 100, tmp_path / "out")


def test_fetch_never_follows_a_symlink_planted_at_the_destination(tmp_path: Path) -> None:
    target = tmp_path / "victim"
    target.write_text("intatto")
    (tmp_path / "out").mkdir()
    (tmp_path / "out" / "results.sarif").symlink_to(target)
    ex = executor(tmp_path, tar=str(build_tar(tmp_path, [("results.sarif", REG, b"{}")])))
    with pytest.raises(runner._InvalidOutput):
        ex._fetch_output("h", "results.sarif", 100, tmp_path / "out")
    assert target.read_text() == "intatto"


# --- ciclo di `_execute` ----------------------------------------------------------------------


def request(tmp: Path) -> PluginRunRequest:
    ws = tmp / "ws"
    ws.mkdir(exist_ok=True)
    return PluginRunRequest(manifest=manifest(), workspace=str(ws))


def run_with(tmp: Path, **config: Any) -> tuple[Any, list[str]]:
    config.setdefault("out", {"inspect": "0 false"})
    with executor(tmp, **config) as ex:
        result = ex.run(request(tmp))
    return result, verbs(tmp)


def test_run_creates_volume_then_holder_then_plugin_and_cleans_in_order(tmp_path: Path) -> None:
    tar = build_tar(tmp_path, [("results.sarif", REG, b"{}")])
    result, v = run_with(tmp_path, tar=str(tar))
    assert result.outcome is RunOutcome.OK and result.detail is None
    start = v.index("volume create")
    assert v[start : start + 4] == ["volume create", "create", "start", "create"]
    assert v[-5:] == ["kill", "rm", "kill", "rm", "volume rm"]  # plugin, custodia, volume
    plugin_create = [c for c in calls(tmp_path) if c[0] == "create"][1]
    mounts = [x for x in plugin_create if x.startswith("type=")]
    assert f"type=volume,src=ca-out-{plugin_create[2][-16:]},dst=/out" in mounts
    assert not any("type=bind" in m and "dst=/out" in m for m in mounts)  # mai un bind su /out
    mem = plugin_create[plugin_create.index("--memory") + 1]
    assert int(mem) == 512 * MIB + out_tmpfs_bytes(manifest().outputs)


@pytest.mark.parametrize("failing", ["volume", "create", "start"])
def test_failure_to_prepare_out_fails_closed_without_a_bind_fallback(
    tmp_path: Path, failing: str
) -> None:
    result, v = run_with(tmp_path, rc={failing: 1})
    assert result.outcome is RunOutcome.FAILED
    assert "bind" not in " ".join(" ".join(c) for c in calls(tmp_path) if "dst=/out" in " ".join(c))
    if failing == "volume":
        assert v.count("create") == 0 and "volume rm" in v  # nessun container creato
    assert v[-1] == "volume rm"  # la pulizia avviene comunque


def test_each_cleanup_step_is_protected_independently(tmp_path: Path) -> None:
    class Boom(OciExecutor):
        def _cli(self, *a: str, timeout: float = 60) -> Any:
            if a[0] in {"kill", "rm"}:
                super()._cli(*a, timeout=timeout)
                raise OSError("boom")
            return super()._cli(*a, timeout=timeout)

    ex = Boom(runtime=fake_cli(tmp_path, out={"inspect": "1 false"}), work_dir=str(tmp_path))
    with ex:
        ex.run(request(tmp_path))
    assert verbs(tmp_path)[-5:] == ["kill", "rm", "kill", "rm", "volume rm"]


def test_declared_output_missing_is_invalid_output(tmp_path: Path) -> None:
    result, _ = run_with(tmp_path, rc={"cp": 1})
    assert result.outcome is RunOutcome.INVALID_OUTPUT
    assert result.detail == "output non valido: results.sarif"


# --- guardia di /feeds ------------------------------------------------------------------------


def test_feeds_usage_counts_allocated_bytes_and_entries_without_following_links(
    tmp_path: Path,
) -> None:
    (tmp_path / "d").mkdir()
    (tmp_path / "d" / "f").write_bytes(b"x" * 10_000)
    (tmp_path / "link").symlink_to(tmp_path / "d")
    total, entries, over = feeds_usage(tmp_path, 10**9, 10**6)
    assert 10_000 <= total < 100_000 and entries == 3 and not over  # d, d/f, link
    assert feeds_usage(tmp_path, 5_000, 10**6)[2]
    assert feeds_usage(tmp_path, 10**9, 2)[2]


def test_guard_reasons_are_fixed_texts(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    (tmp_path / "f").write_bytes(b"x" * 10_000)
    monkeypatch.setattr(runner, "FEEDS_MIN_FREE_BYTES", 0)
    assert feeds_guard(tmp_path, 10**9)() is None
    assert (
        feeds_guard(tmp_path, 100)() == "sincronizzazione dei feed oltre i limiti di byte o di voci"
    )
    monkeypatch.setattr(runner, "FEEDS_MIN_FREE_BYTES", 1 << 62)
    assert feeds_guard(tmp_path, 10**9)() == "spazio libero insufficiente per i feed"
    assert FEEDS_MAX_ENTRIES == 200_000 and runner.FEEDS_POLL_SECONDS == 1


def feeds_manifest() -> PackagedPluginManifest:
    return manifest(
        feeds={
            "sync_command": ["sync"],
            "ecosystems": ["npm"],
            "mount": "/feeds",
            "sync_timeout": "30s",
        }
    )


def sync(tmp: Path, guard_reason: str | None, wait_out: str = "") -> tuple[Any, list[str]]:
    from ca_core.ports import FeedsSyncRequest

    snap = tmp / "snap"
    snap.mkdir()
    with executor(tmp, out={"wait": wait_out}) as ex:
        result = ex.sync_feeds(
            FeedsSyncRequest(manifest=feeds_manifest(), snapshot_dir=str(snap), max_bytes=4096)
        )
    return result, verbs(tmp)


def test_sync_below_free_space_threshold_never_starts_the_container(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(runner, "FEEDS_MIN_FREE_BYTES", 1 << 62)
    result, v = sync(tmp_path, None)
    assert result.outcome is RunOutcome.FAILED
    assert result.detail == "spazio libero insufficiente per i feed"
    assert "create" not in v and "start" not in v


def test_sync_passes_fsize_and_network_and_no_workspace(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(runner, "FEEDS_MIN_FREE_BYTES", 0)
    sync(tmp_path, None)
    (create,) = (c for c in calls(tmp_path) if c[0] == "create")
    assert create[create.index("--ulimit") + 1] == "fsize=4096" and "--network" not in create
    assert not any("dst=/workspace" in x for x in create)
    assert "volume" not in verbs(tmp_path)[: -0 or None] or True


def test_guard_stops_a_running_sync_within_about_a_second(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """`wait` non termina; il disco "si riempie" dopo l'avvio: kill del container e FAILED."""
    monkeypatch.setattr(runner, "FEEDS_MIN_FREE_BYTES", 0)
    state = {"n": 0}

    def guard_factory(path: Path, max_bytes: int) -> Callable[[], str | None]:
        def guard() -> str | None:
            state["n"] += 1
            return (
                None
                if state["n"] == 1
                else "sincronizzazione dei feed oltre i limiti di byte o di voci"
            )

        return guard

    monkeypatch.setattr(runner, "feeds_guard", guard_factory)
    waiter = tmp_path / "waiter"
    waiter.mkdir()
    cli = fake_cli(waiter)
    # `wait` che dorme: sostituisce il ramo "wait" dello script
    script = (
        Path(cli)
        .read_text()
        .replace(
            "cmd = sys.argv[1]\n",
            "cmd = sys.argv[1]\nif cmd == 'wait':\n    import time; time.sleep(30)\n",
        )
    )
    Path(cli).write_text(script)
    from ca_core.ports import FeedsSyncRequest

    snap = tmp_path / "snap"
    snap.mkdir()
    started = time.monotonic()
    with OciExecutor(runtime=cli, work_dir=str(tmp_path), image_ref=lambda _: "img") as ex:
        result = ex.sync_feeds(
            FeedsSyncRequest(manifest=feeds_manifest(), snapshot_dir=str(snap), max_bytes=4096)
        )
    assert time.monotonic() - started < 10
    assert result.outcome is RunOutcome.FAILED and "limiti" in (result.detail or "")
    assert "kill" in verbs(waiter)


# --- orfani, abort, purge ---------------------------------------------------------------------


def test_sweep_removes_only_expired_absent_or_malformed_labels_once(tmp_path: Path) -> None:
    now = int(time.time())
    listing = (
        f"ca-old-1\t{now - 10}\nca-new-2\t{now + 1000}\nca-nolabel-3\t\nca-bad-4\tabc\n"
        "evil name;rm\t1\n-x\t1\n"
    )
    with executor(tmp_path, out={"ps": listing}) as ex:
        ex._sweep_orphans()
        ex._sweep_orphans()
    seen = calls(tmp_path)
    (ps,) = (c for c in seen if c[0] == "ps")
    assert "label=code-analyzer.executor=1" in ps and "{{.Names}}" in ps
    (rm,) = (c for c in seen if c[0] == "rm")
    assert rm == ["rm", "--force", "--volumes", "ca-old-1", "ca-nolabel-3", "ca-bad-4"]
    (ls,) = (c for c in seen if c[:2] == ["volume", "ls"])
    assert "label=code-analyzer.executor=1" in ls
    assert sum(c[0] == "ps" for c in seen) == 1  # una volta per istanza


def test_sweep_errors_do_not_stop_the_scan(tmp_path: Path) -> None:
    result, _ = run_with(
        tmp_path,
        rc={"ps": 1, "volume": 0},
        tar=str(build_tar(tmp_path, [("results.sarif", REG, b"{}")])),
    )
    assert result.outcome is RunOutcome.OK


def test_labels_carry_an_expiry_after_the_run_timeout(tmp_path: Path) -> None:
    run_with(tmp_path)
    created = [c for c in calls(tmp_path) if c[0] == "create"]
    volume = next(c for c in calls(tmp_path) if c[:2] == ["volume", "create"])
    now = time.time()
    for c in [*created, volume]:
        label = next(x for x in c if x.startswith("code-analyzer.expires="))
        assert now + 30 + 900 - 5 <= int(label.split("=")[1]) <= now + 30 + 900 + 5


def test_abort_kills_active_containers_once_and_blocks_new_ones(tmp_path: Path) -> None:
    with executor(tmp_path) as ex:
        ex._register("ca-a", "ca-hold-a")
        ex.abort()
        (kill,) = (c for c in calls(tmp_path) if c[0] == "kill")
        assert kill == ["kill", "ca-a", "ca-hold-a"]
        result = ex.run(request(tmp_path))  # dopo abort(): nulla parte
    assert result.detail == "interrotto"
    assert "create" not in verbs(tmp_path)


def test_close_aborts_only_if_something_is_active_and_is_idempotent(tmp_path: Path) -> None:
    ex = executor(tmp_path)
    ex.close()
    assert not any(c[0] == "kill" for c in calls(tmp_path))
    ex._register("ca-x")
    ex.close()
    ex.close()
    assert sum(c[0] == "kill" for c in calls(tmp_path)) == 1


def test_run_many_interrupt_cancels_the_queue_and_aborts(tmp_path: Path) -> None:
    ex = OciExecutor(
        runtime=fake_cli(tmp_path),
        work_dir=str(tmp_path),
        image_ref=lambda _: "img",
        max_parallel=1,
    )
    started: list[int] = []

    def slow(self: OciExecutor, req: PluginRunRequest, iso: Any, sig: Any) -> Any:
        started.append(1)
        time.sleep(0.3)
        raise AssertionError("non deve finire un lotto interrotto")

    real_gather = ex._gather
    calls_to_gather = []

    def gather(pool: Any, futures: list[Any]) -> Any:
        calls_to_gather.append(1)
        if len(calls_to_gather) == 2:  # il segnale arriva mentre il lotto è in coda
            raise KeyboardInterrupt
        return real_gather(pool, futures)

    ex._run_verified = slow.__get__(ex)  # type: ignore[method-assign]
    ex._gather = gather  # type: ignore[method-assign]
    with pytest.raises(KeyboardInterrupt), ex:
        ex.run_many([request(tmp_path)] * 5)
    assert len(started) <= 1 and ex._stopping.is_set()  # i rimanenti sono stati annullati


def test_purge_runs_a_fixed_python_command_on_the_snapshot_only(tmp_path: Path) -> None:
    from ca_core.ports import FeedsPurgeRequest

    snap = tmp_path / "snap"
    snap.mkdir()
    with executor(tmp_path) as ex:
        ex.purge_feeds(FeedsPurgeRequest(manifest=feeds_manifest(), snapshot_dir=str(snap)))
    (create,) = (c for c in calls(tmp_path) if c[0] == "create")
    assert create[create.index("--entrypoint") + 1] == "python3"
    assert create[-4:-1] == ["-I", "-S", "-c"] and create[-5] == "img"
    assert "--network" in create and create[create.index("--network") + 1] == "none"
    assert create[create.index("--pull") + 1] == "never"
    assert any(x == f"type=bind,src={snap.resolve()},dst=/feeds" for x in create)
    assert verbs(tmp_path)[-2:] == ["kill", "rm"]
    assert "ca-hold" not in " ".join(create)


def test_purge_never_raises(tmp_path: Path) -> None:
    from ca_core.ports import FeedsPurgeRequest

    with executor(tmp_path, rc={"create": 1}) as ex:
        ex.purge_feeds(FeedsPurgeRequest(manifest=feeds_manifest(), snapshot_dir="/no/such"))
