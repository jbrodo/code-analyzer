"""Test del plugin finto (T-02). Senza Docker, salvo la classe `TestImmagine`.

Le prove sull'immagine richiedono un daemon Docker e si attivano con `CA_TEST_DOCKER=1`
(costruiscono `localhost/ca-fake-plugin:test`, la rimuovono a fine sessione, nessuna rete).
"""

import importlib.util
import json
import os
import shutil
import subprocess
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft202012Validator

from ca_core.models import PluginManifest
from ca_core.sarif import SarifError, SarifLimits, read_sarif_file
from ca_core.schema_validation import SchemaStore

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[3]
_spec = importlib.util.spec_from_file_location("fake_plugin", HERE / "fake_plugin.py")
assert _spec and _spec.loader
fake = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(fake)

MANIFEST = json.loads((HERE / "plugin.yaml").read_text())
MAX_BYTES = MANIFEST["outputs"]["max_bytes"]


@pytest.fixture
def dirs(tmp_path: Path) -> dict[str, Path]:
    made = {name: tmp_path / name for name in ("out", "workspace", "tmp")}
    for path in made.values():
        path.mkdir()
    return made


def run(behavior: str, dirs: dict[str, Path], **kw: Any) -> tuple[int, dict[str, Any]]:
    return fake.run(
        behavior,
        out=dirs["out"],
        workspace=dirs["workspace"],
        tmp=dirs["tmp"],
        rootfs_probe=dirs["tmp"] / "no-such-dir" / "probe",
        **kw,
    )


def test_manifest_valid_for_schema_and_model() -> None:
    schema = json.loads((ROOT / "schemas" / "plugin-manifest.schema.json").read_text())
    Draft202012Validator(schema).validate(MANIFEST)
    model = PluginManifest.model_validate(MANIFEST)
    assert model.inputs.config == "optional"
    assert model.inputs.sbom == "none"
    assert model.outputs.max_bytes == MAX_BYTES
    assert "@" not in model.image  # nessun digest: immagine locale, nessun registry reale


def test_manifest_not_shipped_with_cli() -> None:
    shipped = ROOT / "packages" / "ca-plugins" / "src" / "ca_plugins" / "builtin"
    assert not list(shipped.glob("fake_plugin*"))


@pytest.mark.parametrize("behavior", fake.BEHAVIORS)
def test_every_behavior_is_declared_in_readme(behavior: str) -> None:
    assert f"`{behavior}`" in (HERE / "README.md").read_text()


def test_success_output_is_accepted_by_the_sarif_reader(dirs: dict[str, Path]) -> None:
    code, _ = run("success", dirs)
    assert code == 0
    parsed = read_sarif_file(
        dirs["out"] / "results.sarif",
        SchemaStore(ROOT / "schemas" / "vendor"),
        SarifLimits(max_bytes=MAX_BYTES),
    )
    assert len(parsed.results) == 1


def test_invalid_sarif_is_rejected_by_the_reader(dirs: dict[str, Path]) -> None:
    code, _ = run("invalid-sarif", dirs)
    assert code == 0
    with pytest.raises(SarifError):
        read_sarif_file(
            dirs["out"] / "results.sarif",
            SchemaStore(ROOT / "schemas" / "vendor"),
            SarifLimits(max_bytes=MAX_BYTES),
        )


def test_oversize_exceeds_manifest_limit(dirs: dict[str, Path]) -> None:
    run("oversize", dirs)
    assert (dirs["out"] / "results.sarif").stat().st_size > MAX_BYTES
    with pytest.raises(SarifError):
        read_sarif_file(
            dirs["out"] / "results.sarif",
            SchemaStore(ROOT / "schemas" / "vendor"),
            SarifLimits(max_bytes=MAX_BYTES),
        )


def test_exit_nonzero_writes_nothing(dirs: dict[str, Path]) -> None:
    code, _ = run("exit-nonzero", dirs)
    assert code == 3
    assert list(dirs["out"].iterdir()) == []


def test_symlink_out_is_a_symlink_the_reader_refuses(dirs: dict[str, Path]) -> None:
    run("symlink-out", dirs)
    assert (dirs["out"] / "results.sarif").is_symlink()
    with pytest.raises(SarifError):
        read_sarif_file(
            dirs["out"] / "results.sarif",
            SchemaStore(ROOT / "schemas" / "vendor"),
            SarifLimits(max_bytes=MAX_BYTES),
        )


def test_write_out_adds_regular_file_next_to_sarif(dirs: dict[str, Path]) -> None:
    code, probes = run("write-out", dirs)
    assert (code, probes) == (0, {"out_write": "ok"})
    assert (dirs["out"] / "extra.txt").is_file()


def test_write_tmp_reports_and_cleans_up(dirs: dict[str, Path]) -> None:
    code, probes = run("write-tmp", dirs)
    assert (code, probes) == (0, {"tmp_write": "ok"})
    assert list(dirs["tmp"].iterdir()) == []


def test_write_workspace_breach_is_reported_with_exit_4(dirs: dict[str, Path]) -> None:
    # Directory scrivibile (nessun isolamento): il tentativo riesce, quindi e' una violazione.
    code, probes = run("write-workspace", dirs)
    assert (code, probes) == (4, {"workspace_write": "ok"})
    assert list(dirs["workspace"].iterdir()) == []


def test_write_workspace_blocked_is_exit_0(dirs: dict[str, Path]) -> None:
    dirs["workspace"].chmod(0o500)
    try:
        if os.access(dirs["workspace"], os.W_OK):
            pytest.skip("il processo ignora i permessi (root)")
        code, probes = run("write-workspace", dirs)
    finally:
        dirs["workspace"].chmod(0o700)
    assert code == 0
    assert probes == {"workspace_write": "Permission denied"}


def test_write_rootfs_blocked_when_directory_missing(dirs: dict[str, Path]) -> None:
    code, probes = run("write-rootfs", dirs)
    assert code == 0
    assert probes["rootfs_write"] != "ok"


def test_timeout_sleeps_without_writing(
    dirs: dict[str, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    slept: list[float] = []
    monkeypatch.setattr(fake.time, "sleep", slept.append)
    assert run("timeout", dirs) == (0, {})
    assert slept == [3600]
    assert list(dirs["out"].iterdir()) == []


@pytest.mark.parametrize(
    ("content", "expected"),
    [
        (None, "success"),
        ('{"behavior": "network"}', "network"),
        ("{}", "success"),
    ],
)
def test_read_behavior(tmp_path: Path, content: str | None, expected: str) -> None:
    path = tmp_path / "config.json"
    if content is not None:
        path.write_text(content)
    assert fake.read_behavior(path) == expected


@pytest.mark.parametrize("content", ['{"behavior": "rm-rf"}', "[]", "not json", "x" * 5000])
def test_read_behavior_rejects_bad_input(tmp_path: Path, content: str) -> None:
    path = tmp_path / "config.json"
    path.write_text(content)
    with pytest.raises(ValueError):
        fake.read_behavior(path)


def test_network_probe_targets_only_a_non_routable_address() -> None:
    assert fake.UNREACHABLE[0].startswith("192.0.2.")  # RFC 5737 TEST-NET-1


# --- Prove sull'immagine reale (Docker) -------------------------------------------------------

IMAGE = "localhost/ca-fake-plugin:test"
PROFILE = [
    "--network", "none", "--read-only", "--cap-drop", "ALL",
    "--security-opt", "no-new-privileges", "--user", "65534:65534",
    "--pids-limit", "64", "--memory", "256m", "--cpus", "1",
    "--tmpfs", "/tmp:rw,noexec,nosuid", "-e", "HOME=/tmp",
]  # fmt: skip
needs_docker = pytest.mark.skipif(
    os.environ.get("CA_TEST_DOCKER") != "1" or shutil.which("docker") is None,
    reason="richiede un daemon Docker: CA_TEST_DOCKER=1",
)


@pytest.fixture(scope="module")
def image() -> Any:
    subprocess.run(["docker", "build", "-q", "-t", IMAGE, str(HERE)], check=True)
    yield IMAGE
    subprocess.run(["docker", "rmi", "-f", IMAGE], check=False, capture_output=True)


@needs_docker
class TestImmagine:
    def container(
        self, image: str, behavior: str, tmp_path: Path
    ) -> tuple[int, dict[str, Any], Path]:
        run_dir = tmp_path / "run"
        run_dir.mkdir(mode=0o700, parents=True)
        out = run_dir / "out"
        out.mkdir()
        out.chmod(0o777)
        (workspace := tmp_path / "ws").mkdir()
        (workspace / "app.py").write_text("print(1)\n")
        config = run_dir / "config.json"
        config.write_text(json.dumps({"behavior": behavior}))
        config.chmod(0o644)
        cmd = [
            "docker", "run", "--rm", *PROFILE,
            "-v", f"{workspace}:/workspace:ro", "-v", f"{out}:/out",
            "-v", f"{config}:/inputs/config.json:ro", image,
        ]  # fmt: skip
        done = subprocess.run(cmd, capture_output=True, text=True, timeout=60, check=False)
        report = json.loads(done.stdout) if done.stdout.strip() else {}
        return done.returncode, report, out

    def test_success_is_nobody_and_valid(self, image: str, tmp_path: Path) -> None:
        code, report, out = self.container(image, "success", tmp_path)
        assert (code, report["uid"], report["gid"], report["home"]) == (0, 65534, 65534, "/tmp")
        read_sarif_file(
            out / "results.sarif",
            SchemaStore(ROOT / "schemas" / "vendor"),
            SarifLimits(max_bytes=MAX_BYTES),
        )

    @pytest.mark.parametrize(
        ("behavior", "probe", "blocked"),
        [
            ("network", "network", "Network is unreachable"),
            ("write-workspace", "workspace_write", "Read-only file system"),
            ("write-rootfs", "rootfs_write", "Read-only file system"),
            ("exec-tmp", "tmp_exec", "Permission denied"),
        ],
    )
    def test_hostile_attempts_are_blocked(
        self, image: str, tmp_path: Path, behavior: str, probe: str, blocked: str
    ) -> None:
        code, report, _ = self.container(image, behavior, tmp_path)
        assert (code, report["probes"][probe]) == (0, blocked)

    def test_tmp_and_out_are_writable(self, image: str, tmp_path: Path) -> None:
        assert self.container(image, "write-tmp", tmp_path)[1]["probes"] == {"tmp_write": "ok"}
        _, report, out = self.container(image, "write-out", tmp_path / "b")
        assert report["probes"] == {"out_write": "ok"}
        assert (out / "extra.txt").is_file()

    def test_exit_nonzero_symlink_and_invalid_input(self, image: str, tmp_path: Path) -> None:
        assert self.container(image, "exit-nonzero", tmp_path / "a")[0] == 3
        _, _, out = self.container(image, "symlink-out", tmp_path / "b")
        assert (out / "results.sarif").is_symlink()
        assert self.container(image, "rm-rf", tmp_path / "c")[0] == 64

    def test_oversize_exceeds_limit(self, image: str, tmp_path: Path) -> None:
        _, _, out = self.container(image, "oversize", tmp_path)
        assert (out / "results.sarif").stat().st_size > MAX_BYTES
