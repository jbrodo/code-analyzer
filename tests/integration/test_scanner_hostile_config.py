"""N-01 di S-01: i file di configurazione del repository non spengono trivy, syft e osv-scanner.

Sull'immagine reale (`CA_TEST_DOCKER=1`) con i feed congelati (`CA_TEST_TRIVY_FEEDS`,
`CA_TEST_OSV_FEEDS`). Per ogni vettore, il controllo positivo e' lo scanner lanciato direttamente
nell'immagine con il profilo del runner e la directory corrente nel workspace (la strada
scartata): sul repository pulito trova risultati, su quello con la configurazione ostile zero.
Poi lo stesso repository ostile, sotto il plugin (`OciExecutor`, profilo completo), da' gli stessi
risultati del repository pulito. Se un vettore non spegnesse lo scanner diretto, il test fallisce:
la prova non passa per un vettore spento.
"""

import json
import os
import shutil
import subprocess
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import pytest
from plugin_image_support import ROOT, build_image, leftovers, manifest, needs_docker

from ca_core.ports import PluginRunRequest, RunOutcome
from ca_plugins.runner import OciExecutor, OutputReader

pytestmark = needs_docker
REPO = ROOT / "tests/fixtures/repos/js-ts-app"
TRIVY_FEEDS = os.environ.get("CA_TEST_TRIVY_FEEDS", "")
OSV_FEEDS = os.environ.get("CA_TEST_OSV_FEEDS", "")
PACKAGES = ("axios", "express", "lodash", "minimist", "fixture-copyleft-lib")
OSV_TOML = "".join(
    f'[[PackageOverrides]]\nname = "{p}"\necosystem = "npm"\nignore = true\n\n' for p in PACKAGES
)
needs_trivy_feeds = pytest.mark.skipif(
    not TRIVY_FEEDS or not (Path(TRIVY_FEEDS) / "trivy/db/trivy.db").is_file(),
    reason="richiede CA_TEST_TRIVY_FEEDS",
)
needs_osv_feeds = pytest.mark.skipif(
    not OSV_FEEDS or not (Path(OSV_FEEDS) / "osv-scalibr/npm/all.zip").is_file(),
    reason="richiede CA_TEST_OSV_FEEDS",
)


def image(plugin: str) -> Iterator[str]:
    yield from build_image(plugin, f"localhost/ca-plugin-{plugin}:hostile-config")


@pytest.fixture(scope="module")
def trivy_image() -> Iterator[str]:
    yield from image("trivy")


@pytest.fixture(scope="module")
def syft_image() -> Iterator[str]:
    yield from image("syft")


@pytest.fixture(scope="module")
def osv_image() -> Iterator[str]:
    yield from image("osv_scanner")


def workspace(tmp_path: Path, name: str) -> Path:
    ws = tmp_path / name
    shutil.copytree(REPO, ws)
    return ws


def direct(
    image_id: str, ws: Path, tmp_path: Path, feeds: str | None, env: dict[str, str], *argv: str
) -> dict[str, Any]:
    """Lo scanner nell'immagine con il profilo del runner e `/workspace` come directory corrente."""
    out = tmp_path / "direct-out"
    shutil.rmtree(out, ignore_errors=True)
    out.mkdir()
    out.chmod(0o777)
    cmd = [
        "docker", "run", "--rm", "--network", "none", "--read-only", "--cap-drop", "ALL",
        "--security-opt", "no-new-privileges", "--user", "65534:65534",
        "--tmpfs", "/tmp:rw,noexec,nosuid", "--env", "HOME=/tmp", "--workdir", "/workspace",
        "--mount", f"type=bind,src={ws},dst=/workspace,readonly",
        "--mount", f"type=bind,src={out},dst=/out",
        *(["--mount", f"type=bind,src={feeds},dst=/feeds,readonly"] if feeds else []),
        *(a for k, v in env.items() for a in ("--env", f"{k}={v}")),
        "--entrypoint", argv[0], image_id, *argv[1:],
    ]  # fmt: skip
    subprocess.run(cmd, capture_output=True, check=False, timeout=600)  # noqa: S603
    report = out / "native.json"  # assente: lo scanner e' uscito senza scrivere (osv, exit 128)
    result: dict[str, Any] = json.loads(report.read_text()) if report.exists() else {}
    return result


def plugin(
    plugin_name: str, image_id: str, ws: Path, tmp_path: Path, feeds: str | None
) -> dict[str, Any]:
    tag = f"localhost/ca-plugin-{plugin_name}:hostile-config"
    request = PluginRunRequest(
        manifest=manifest(plugin_name, f"{tag}@{image_id}"),
        workspace=str(ws),
        feeds_snapshot=feeds,
    )
    work = tmp_path / f"work-{ws.name}"
    work.mkdir()
    with OciExecutor(work_dir=str(work), image_ref=lambda _: image_id) as executor:
        result = executor.run(request)
        assert result.outcome is RunOutcome.OK, result.detail
        assert result.output_dir is not None
        reader = OutputReader()
        (name,) = reader.list_files(result.output_dir)
        raw = reader.read_file(result.output_dir, name, request.manifest.outputs.max_bytes)
        executor.release(result.output_dir)
    assert leftovers() == []
    document: dict[str, Any] = json.loads(raw)
    return document


def trivy_count(document: dict[str, Any]) -> int:
    return sum(
        len(r.get("Vulnerabilities") or []) + len(r.get("Misconfigurations") or [])
        for r in document.get("Results") or []
    )


TRIVY_ARGV = (
    "/usr/local/bin/trivy", "fs", "--scanners", "vuln,misconfig", "--offline-scan",
    "--skip-db-update", "--skip-check-update", "--skip-version-check", "--disable-telemetry",
    "--quiet", "--cache-dir", "/feeds/trivy", "--format", "json", "--output", "/out/native.json",
    "/workspace",
)  # fmt: skip


def trivy_ids(document: dict[str, Any]) -> list[str]:
    ids = {
        v["VulnerabilityID"] for r in document["Results"] for v in r.get("Vulnerabilities") or []
    }
    ids |= {m["ID"] for r in document["Results"] for m in r.get("Misconfigurations") or []}
    return sorted(ids)


def hostile_trivyignore(ws: Path, ids: list[str]) -> None:
    (ws / ".trivyignore").write_text("\n".join(ids) + "\n")


def hostile_trivy_yaml(ws: Path, ids: list[str]) -> None:
    del ids
    (ws / "trivy.yaml").write_text("scan:\n  skip-dirs:\n    - '**'\n")


@needs_trivy_feeds
@pytest.mark.parametrize("hostile", [hostile_trivyignore, hostile_trivy_yaml])
def test_trivy_ignores_repository_ignore_and_config_files(
    trivy_image: str, tmp_path: Path, hostile: Callable[[Path, list[str]], None]
) -> None:
    clean = workspace(tmp_path, "clean")
    baseline = direct(trivy_image, clean, tmp_path, TRIVY_FEEDS, {}, *TRIVY_ARGV)
    assert trivy_count(baseline) > 0
    ws = workspace(tmp_path, "ostile")
    hostile(ws, trivy_ids(baseline))
    # controllo positivo: lo scanner diretto, con il repository come directory corrente, tace
    assert trivy_count(direct(trivy_image, ws, tmp_path, TRIVY_FEEDS, {}, *TRIVY_ARGV)) == 0
    expected = plugin("trivy", trivy_image, clean, tmp_path, TRIVY_FEEDS)
    found = plugin("trivy", trivy_image, ws, tmp_path, TRIVY_FEEDS)
    assert len(found["runs"][0]["results"]) == len(expected["runs"][0]["results"]) > 0


SYFT_ARGV = (
    "/usr/local/bin/syft", "scan", "dir:/workspace", "-q", "-o",
    "cyclonedx-json@1.7=/out/native.json",
)  # fmt: skip


def test_syft_ignores_the_repository_configuration(syft_image: str, tmp_path: Path) -> None:
    clean = workspace(tmp_path, "clean")
    baseline = direct(syft_image, clean, tmp_path, None, {}, *SYFT_ARGV)
    assert len(baseline["components"]) > 0
    ws = workspace(tmp_path, "ostile")
    (ws / ".syft.yaml").write_text('exclude:\n  - "./**"\n')
    hostile = direct(syft_image, ws, tmp_path, None, {}, *SYFT_ARGV)
    assert len(hostile.get("components") or []) == 0  # controllo positivo
    expected = plugin("syft", syft_image, clean, tmp_path, None)
    found = plugin("syft", syft_image, ws, tmp_path, None)
    purls = {c["purl"] for c in found["components"] if "purl" in c}
    assert purls == {c["purl"] for c in expected["components"] if "purl" in c} != set()


OSV_ARGV = (
    "/usr/local/bin/osv-scanner", "scan", "source", "--offline-vulnerabilities", "--no-resolve",
    "-r", "--format", "json", "--output-file", "/out/native.json", "/workspace",
)  # fmt: skip


def osv_groups(document: dict[str, Any]) -> int:
    return sum(len(p.get("groups", [])) for r in document.get("results", []) for p in r["packages"])


@needs_osv_feeds
@pytest.mark.parametrize("where", ["root", "subdirectory"])
def test_osv_scanner_ignores_every_repository_toml(
    osv_image: str, tmp_path: Path, where: str
) -> None:
    env = {"OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY": "/feeds"}
    clean = workspace(tmp_path, "clean")
    if where == "subdirectory":  # il toml sta accanto al lockfile, in un sottoalbero
        (clean / "sub").mkdir()
        shutil.move(clean / "package-lock.json", clean / "sub/package-lock.json")
        shutil.copy(clean / "package.json", clean / "sub/package.json")
    baseline = direct(osv_image, clean, tmp_path, OSV_FEEDS, env, *OSV_ARGV)
    assert osv_groups(baseline) > 0
    ws = tmp_path / "ostile"
    shutil.copytree(clean, ws)
    (ws / ("sub" if where == "subdirectory" else ".") / "osv-scanner.toml").write_text(OSV_TOML)
    hostile = direct(osv_image, ws, tmp_path, OSV_FEEDS, env, *OSV_ARGV)
    assert osv_groups(hostile) == 0  # controllo positivo
    expected = plugin("osv_scanner", osv_image, clean, tmp_path, OSV_FEEDS)
    found = plugin("osv_scanner", osv_image, ws, tmp_path, OSV_FEEDS)
    assert len(found["runs"][0]["results"]) == len(expected["runs"][0]["results"]) > 0


@needs_osv_feeds
@pytest.mark.parametrize("pattern", ["package-lock.json", "*"])
@pytest.mark.parametrize("with_git", [False, True])
def test_osv_scanner_ignores_the_repository_gitignore(
    osv_image: str, tmp_path: Path, pattern: str, with_git: bool
) -> None:
    """N-06: un `.gitignore` con il lockfile fa uscire osv-scanner con 128 senza risultati."""
    env = {"OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY": "/feeds"}
    clean = workspace(tmp_path, "clean")
    baseline = direct(osv_image, clean, tmp_path, OSV_FEEDS, env, *OSV_ARGV)
    assert osv_groups(baseline) > 0
    ws = tmp_path / "ostile"
    shutil.copytree(clean, ws)
    (ws / ".gitignore").write_text(pattern + "\n")
    if with_git:
        subprocess.run(["git", "init", "-q", str(ws)], check=True, capture_output=True)  # noqa: S603, S607
    hostile = direct(osv_image, ws, tmp_path, OSV_FEEDS, env, *OSV_ARGV)
    assert osv_groups(hostile) == 0  # controllo positivo: lo scanner diretto non vede il lockfile
    expected = plugin("osv_scanner", osv_image, clean, tmp_path, OSV_FEEDS)
    found = plugin("osv_scanner", osv_image, ws, tmp_path, OSV_FEEDS)
    assert len(found["runs"][0]["results"]) == len(expected["runs"][0]["results"]) > 0
