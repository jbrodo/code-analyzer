"""I-01 (ADR-0004, M-11) senza daemon: percorsi host, traduzione, prova di identità.

Il client del runtime è uno script: per `run` si comporta come il container di prova, leggendo i
sorgenti dei `--mount` che riceve. Si prova quindi ciò che il runner chiede al runtime e come ne
legge la risposta. L'immagine reale è in `tests/integration/test_cli_image.py`.
"""

import argparse
import json
import os
import socket
import sys
import time
from pathlib import Path
from typing import Any

import pytest
from test_runner_r09 import REG, build_tar, manifest

from ca_cli.composition import build_context
from ca_cli.main import _confine_outputs
from ca_core.ports import FeedsPurgeRequest, Isolation, PluginRunRequest, RunOutcome, ScanAborted
from ca_plugins.hostpaths import HostPaths, HostPathsError, from_env
from ca_plugins.runner import OciExecutor, probe_args

ENV = {"CA_HOST_WORKSPACE": "/srv/ws", "CA_HOST_WORK": "/srv/work", "CA_HOST_CACHE": "/srv/cache"}


# --- variabili d'ambiente -----------------------------------------------------------------------


def test_no_variable_means_host_mode_and_all_three_mean_image_mode() -> None:
    assert from_env({}) is None
    paths = from_env(ENV)
    assert paths is not None
    assert {k: str(v) for k, v in paths.hosts.items()} == {
        "workspace": "/srv/ws",
        "inputs": "/srv/work",
        "snapshot": "/srv/cache",
    }


@pytest.mark.parametrize("missing", sorted(ENV))
def test_one_missing_variable_is_an_error(missing: str) -> None:
    with pytest.raises(HostPathsError, match=missing) as err:
        from_env({k: v for k, v in ENV.items() if k != missing})
    assert err.value.exit_code == 2


def test_inside_the_image_the_variables_are_required() -> None:
    with pytest.raises(HostPathsError, match="CA_HOST_WORKSPACE"):
        from_env({"CA_CLI_IMAGE": "1"})


@pytest.mark.parametrize(
    "value", ["relative/ws", "/srv/../etc", "/srv/ws/", "/", "/run", "/var/run", "/var", "/proc"]
)
def test_unsafe_host_path_is_refused(value: str) -> None:
    with pytest.raises(HostPathsError):
        from_env({**ENV, "CA_HOST_WORKSPACE": value})


@pytest.mark.parametrize("cache", ["/srv/ws", "/srv/ws/cache", "/srv"])
def test_equal_or_nested_roots_are_refused(cache: str) -> None:
    with pytest.raises(HostPathsError, match="coincidono o sono annidati"):
        from_env({**ENV, "CA_HOST_CACHE": cache})


# --- traduzione ---------------------------------------------------------------------------------


@pytest.fixture
def paths(tmp_path: Path) -> HostPaths:
    """Radici reali in `tmp_path/ca`; i percorsi host sono link alle stesse directory, così lo
    script che fa da runtime li risolve e la traduzione resta visibile negli argomenti."""
    roots, hosts = {}, {}
    for kind in ("workspace", "inputs", "snapshot"):
        root = tmp_path / "ca" / kind
        root.mkdir(parents=True)
        host = tmp_path / "host" / kind
        host.parent.mkdir(exist_ok=True)
        host.symlink_to(root)
        roots[kind], hosts[kind] = root, host
    output = tmp_path / "ca" / "output"
    output.mkdir()
    return HostPaths(hosts=hosts, roots=roots, output=output)  # type: ignore[arg-type]


def test_translate_maps_a_path_under_its_root(paths: HostPaths) -> None:
    (paths.roots["inputs"] / "run-1").mkdir()
    assert paths.translate("workspace", paths.roots["workspace"]) == paths.hosts["workspace"]
    assert (
        paths.translate("inputs", paths.roots["inputs"] / "run-1")
        == paths.hosts["inputs"] / "run-1"
    )


def test_translate_fails_closed_outside_the_root_of_its_kind(
    paths: HostPaths, tmp_path: Path
) -> None:
    with pytest.raises(ScanAborted, match="fuori da"):
        paths.translate("workspace", paths.roots["inputs"])  # radice di un altro tipo
    with pytest.raises(ScanAborted, match="fuori da"):
        paths.translate("snapshot", tmp_path)
    with pytest.raises(ScanAborted, match="non risolvibile"):
        paths.translate("workspace", paths.roots["workspace"] / "missing")
    escape = paths.roots["workspace"] / "link"
    escape.symlink_to(tmp_path)
    with pytest.raises(ScanAborted, match="fuori da"):
        paths.translate("workspace", escape)


# --- controlli all'avvio ------------------------------------------------------------------------


def mountinfo(*mounts: Path) -> str:
    return "".join(f"36 35 98:0 / {m} rw,noatime - ext4 /dev/sda1 rw\n" for m in mounts)


def test_check_container_requires_real_mounted_roots_and_not_the_plugin_uid(
    paths: HostPaths, tmp_path: Path
) -> None:
    every = (*paths.roots.values(), paths.output)
    paths.check_container(mountinfo(*every), uid=1000)
    with pytest.raises(HostPathsError, match="uid dei plugin"):
        paths.check_container(mountinfo(*every), uid=65534)
    with pytest.raises(HostPathsError, match="non è un montaggio"):
        paths.check_container(mountinfo(*every[:-1]), uid=1000)
    linked = HostPaths(
        hosts=paths.hosts, roots={**paths.roots, "workspace": tmp_path / "host" / "workspace"}
    )
    with pytest.raises(HostPathsError, match="non è un percorso reale"):
        linked.check_container(mountinfo(tmp_path / "host" / "workspace"), uid=1000)


@pytest.mark.parametrize(
    ("docker_root", "sock"),
    [("/srv/ws", None), ("/srv/ws/docker", None), ("/var/lib/docker", "/srv/cache/docker.sock")],
)
def test_host_path_exposing_the_daemon_is_refused(docker_root: str, sock: str | None) -> None:
    paths = from_env(ENV)
    assert paths is not None
    paths.check_daemon("/var/lib/docker", "/var/run/docker.sock")
    with pytest.raises(HostPathsError, match="espone"):
        paths.check_daemon(docker_root, sock)


def test_sockets_are_found_at_any_depth_without_following_links(
    paths: HostPaths, tmp_path: Path
) -> None:
    assert list(paths.sockets()) == []
    outside = tmp_path / "outside"
    outside.mkdir()
    for folder in (paths.roots["workspace"] / "a" / "b", outside):
        folder.mkdir(parents=True, exist_ok=True)
        with socket.socket(socket.AF_UNIX) as sock:
            sock.bind(str(folder / "s.sock"))
    (paths.roots["workspace"] / "link").symlink_to(outside)
    assert list(paths.sockets()) == [paths.roots["workspace"] / "a" / "b" / "s.sock"]


def test_sweep_work_removes_only_expired_work_roots(paths: HostPaths) -> None:
    work = paths.roots["inputs"]
    old, fresh, other = work / "ca-oci-old", work / "ca-oci-new", work / "keep-me"
    for folder in (old, fresh, other):
        folder.mkdir()
    past = time.time() - 2 * 24 * 3600
    os.utime(old, (past, past))
    os.utime(other, (past, past))
    paths.sweep_work()
    assert not old.exists() and fresh.exists() and other.exists()


# --- esecutore ----------------------------------------------------------------------------------

FORBIDDEN_ARGS = ("--volumes-from", "--privileged", "--pid", "--ipc")


def fake_runtime(tmp: Path, **config: Any) -> str:
    """Come `test_runner_r09.fake_cli`, più `run`: la prova di identità sui sorgenti ricevuti."""
    cfg, log = tmp / "cfg.json", tmp / "calls.log"
    cfg.write_text(json.dumps(config))
    path = tmp / "docker"
    path.write_text(
        f"#!{sys.executable}\n"
        "import hashlib, json, os, sys\n"
        f"cfg = json.load(open({str(cfg)!r}))\n"
        f"open({str(log)!r}, 'a').write('\\t'.join(sys.argv[1:]).replace('\\n', ' ') + '\\n')\n"
        "cmd = sys.argv[1]\n"
        "if cmd == 'info':\n"
        "    root = '{{.DockerRootDir}}' in sys.argv\n"
        "    print(cfg.get('docker_root', '/var/lib/docker') if root else '{\"runc\": {}}')\n"
        "elif cmd == 'run':\n"
        "    src = {}\n"
        "    for arg in sys.argv:\n"
        "        if arg.startswith('type=bind,'):\n"
        "            f = dict(p.split('=', 1) for p in arg.split(',') if '=' in p)\n"
        "            kind = f['dst'].rsplit('/', 1)[1]\n"
        "            src[kind] = cfg.get('remap', {}).get(f['src'], f['src'])\n"
        "    s = os.stat(src['workspace'])\n"
        "    names = '\\0'.join(sorted(os.listdir(src['workspace']))).encode()\n"
        "    out = {'workspace': [s.st_dev, s.st_ino, s.st_mtime_ns,\n"
        "                         hashlib.sha256(names).hexdigest()]}\n"
        "    for kind in ('inputs', 'snapshot'):\n"
        "        out[kind] = open(os.path.join(src[kind], sys.argv[-1])).read()\n"
        "    print(json.dumps(out))\n"
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


def image_executor(tmp: Path, paths: HostPaths, **config: Any) -> OciExecutor:
    config.setdefault("out", {"inspect": "0 false"})
    config.setdefault("tar", str(build_tar(tmp, [("results.sarif", REG, b"{}")])))
    return OciExecutor(
        runtime=fake_runtime(tmp, **config),
        work_dir=str(paths.roots["inputs"]),
        image_ref=lambda _: "img",
        host_paths=paths,
    )


def request(paths: HostPaths) -> PluginRunRequest:
    return PluginRunRequest(manifest=manifest(), workspace=str(paths.roots["workspace"]))


def binds(call: list[str]) -> list[str]:
    return [arg for arg in call if arg.startswith("type=bind,")]


def test_run_proves_identity_once_then_mounts_host_paths(paths: HostPaths, tmp_path: Path) -> None:
    (paths.roots["workspace"] / "app.py").write_text("x = 1\n")
    with image_executor(tmp_path, paths) as executor:
        first = executor.run(request(paths))
        second = executor.run(request(paths))
    assert first.outcome is RunOutcome.OK and second.outcome is RunOutcome.OK
    log = calls(tmp_path)
    probes = [c for c in log if c[0] == "run"]
    assert len(probes) == 1  # una sola volta per istanza
    first_create = next(i for i, c in enumerate(log) if c[0] == "create")
    assert log.index(probes[0]) < first_create  # prima di qualunque montaggio
    assert binds(probes[0]) == [
        f"type=bind,src={paths.hosts[kind]},dst=/probe/{kind},readonly"
        for kind in ("workspace", "inputs", "snapshot")
    ]
    plugin = next(c for c in log if c[0] == "create" and binds(c))
    assert binds(plugin) == [f"type=bind,src={paths.hosts['workspace']},dst=/workspace,readonly"]
    # i file della prova non restano nelle radici
    assert not list(paths.roots["inputs"].glob(".ca-probe-*"))
    assert not list(paths.roots["snapshot"].glob(".ca-probe-*"))


def test_staged_inputs_are_mounted_from_the_host_work_root(
    paths: HostPaths, tmp_path: Path
) -> None:
    config = tmp_path / "config.json"
    config.write_text("{}")
    base = manifest()
    with_config = base.model_copy(
        update={"inputs": base.inputs.model_copy(update={"config": "optional"})}
    )
    with image_executor(tmp_path, paths) as executor:
        result = executor.run(
            request(paths).model_copy(update={"manifest": with_config, "config": str(config)})
        )
    assert result.outcome is RunOutcome.OK
    plugin = next(c for c in calls(tmp_path) if c[0] == "create" and binds(c))
    staged = [b for b in binds(plugin) if "config" in b]
    assert len(staged) == 1
    assert staged[0].startswith(f"type=bind,src={paths.hosts['inputs']}/ca-oci-")


def test_no_runtime_call_carries_the_socket_or_a_privileged_flag(
    paths: HostPaths, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("DOCKER_HOST", "unix:///var/run/docker.sock")
    with image_executor(tmp_path, paths) as executor:
        executor.run(request(paths))
    for call in calls(tmp_path):
        assert not set(call) & set(FORBIDDEN_ARGS)
        assert not any("docker.sock" in arg or "unix://" in arg for arg in call)


def test_probe_profile_has_no_network_no_capability_and_read_only_mounts() -> None:
    args = probe_args(
        name="ca-probe-1",
        image="img",
        hosts={"workspace": Path("/h/ws"), "inputs": Path("/h/work"), "snapshot": Path("/h/c")},
        isolation=Isolation.HARDENED_CONTAINER,
        user="1000:1000",
        marker=".ca-probe-x",
        expires=1,
    )
    pairs = dict(zip(args, args[1:], strict=False))
    assert pairs["--network"] == "none" and pairs["--cap-drop"] == "ALL"
    assert pairs["--user"] == "1000:1000" and pairs["--pull"] == "never"
    assert pairs["--security-opt"] == "no-new-privileges" and "--read-only" in args
    assert all(b.endswith(",readonly") for b in binds(args)) and len(binds(args)) == 3
    assert not set(args) & set(FORBIDDEN_ARGS)


def test_host_paths_pointing_elsewhere_abort_before_any_mount(
    paths: HostPaths, tmp_path: Path
) -> None:
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    remap = {str(paths.hosts["workspace"]): str(elsewhere)}  # il daemon vede un'altra directory
    with image_executor(tmp_path, paths, remap=remap) as executor:
        with pytest.raises(ScanAborted, match="non corrispondono"):
            executor.run(request(paths))
        with pytest.raises(ScanAborted):  # nessuna seconda possibilità senza una prova riuscita
            executor.run_many([request(paths)])
    assert not [c for c in calls(tmp_path) if c[0] == "create"]


def test_probe_failure_or_garbage_aborts(paths: HostPaths, tmp_path: Path) -> None:
    with (
        image_executor(tmp_path, paths, rc={"run": 125}) as executor,
        pytest.raises(ScanAborted, match="non riuscita"),
    ):
        executor.run(request(paths))
    assert not [c for c in calls(tmp_path) if c[0] == "create"]


def test_socket_in_a_mounted_root_aborts_before_the_probe(paths: HostPaths, tmp_path: Path) -> None:
    with socket.socket(socket.AF_UNIX) as sock:
        sock.bind(str(paths.roots["workspace"] / "d.sock"))
        with (
            image_executor(tmp_path, paths) as executor,
            pytest.raises(ScanAborted, match="socket"),
        ):
            executor.run(request(paths))
    assert not [c for c in calls(tmp_path) if c[0] in ("run", "create")]


def test_daemon_root_under_a_host_path_is_exit_2_at_detection(
    paths: HostPaths, tmp_path: Path
) -> None:
    root = str(paths.hosts["snapshot"] / "docker")
    with (
        image_executor(tmp_path, paths, docker_root=root) as executor,
        pytest.raises(HostPathsError, match="CA_HOST_CACHE"),
    ):
        executor.isolation()


def test_preflight_runs_before_the_runtime_is_looked_for(tmp_path: Path) -> None:
    def refuse() -> None:
        raise HostPathsError("no")

    executor = OciExecutor(runtime=fake_runtime(tmp_path), preflight=refuse)
    with pytest.raises(HostPathsError):
        executor.isolation()
    assert calls(tmp_path) == []


def test_purge_never_mounts_before_a_successful_proof(paths: HostPaths, tmp_path: Path) -> None:
    with image_executor(tmp_path, paths) as executor:
        executor.purge_feeds(
            FeedsPurgeRequest(manifest=manifest(), snapshot_dir=str(paths.roots["snapshot"]))
        )
    assert not [c for c in calls(tmp_path) if c[0] in ("create", "run")]


# --- radice di composizione e comandi -----------------------------------------------------------


def test_build_context_wires_the_image_mode_and_defers_configuration_errors() -> None:
    host = build_context(environ={})
    assert host.output_root is None and host.feeds_cache is None
    image = build_context(environ=ENV)
    assert image.output_root == Path("/ca/output") and image.feeds_cache == Path("/ca/cache")
    with pytest.raises(HostPathsError):  # fuori dall'immagine /ca/* non sono montaggi
        image.executor.isolation()
    # variabili assenti nell'immagine: `gate` e `config validate` funzionano, `scan` esce con 2
    broken = build_context(environ={"CA_CLI_IMAGE": "1"})
    assert broken.output_root == Path("/ca/output")
    with pytest.raises(HostPathsError, match="CA_HOST_WORK"):
        broken.executor.isolation()


def test_outputs_are_confined_to_the_output_root(tmp_path: Path) -> None:
    root = tmp_path / "output"
    root.mkdir()
    args = argparse.Namespace(output_dir=".", report="code-analyzer.report.json", output=None)
    _confine_outputs(args, root)
    assert args.output_dir == str(root)
    assert args.report == str(root / "code-analyzer.report.json") and args.output is None
    for outside in ("/etc", "../elsewhere", str(tmp_path)):
        with pytest.raises(HostPathsError, match="solo sotto"):
            _confine_outputs(argparse.Namespace(output_dir=outside), root)
    (root / "link").symlink_to(tmp_path)
    with pytest.raises(HostPathsError):
        _confine_outputs(argparse.Namespace(output=str(root / "link" / "sbom.json")), root)
