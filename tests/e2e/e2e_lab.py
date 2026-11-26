"""Laboratorio comune degli E2E (T-05..T-08). Non e' un test.

Costruisce, firma e pubblica su un registry locale (127.0.0.1) le immagini dei plugin con gli
script del progetto (`build-image.sh` per licenze e SBOM, `sign-local.sh` per build, push e firma
con una chiave di prova in una cartella temporanea FUORI dal repository), poi genera manifest
impacchettati di prova con il digest vero. Il pacchetto `ca_plugins` non si tocca: i manifest
arrivano al processo figlio da `Context.manifests` (vedi `_cli_child.py`). E' il meccanismo che I-04
dovra' sostituire con un manifest impacchettato vero.

Attivazione: `CA_TEST_DOCKER=1`, `COSIGN`, `SYFT`; per le scansioni con CVE `CA_TEST_OSV_FEEDS` e
`CA_TEST_TRIVY_FEEDS` (cartella con `osv-scalibr/` e `trivy/`, vedi `tests/fixtures/feeds`).
"""

import json
import os
import re
import shutil
import socket
import subprocess
import sys
import time
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tests/fixtures/feeds"))
sys.path.insert(0, str(ROOT / "tests/fixtures/builders"))
BUILTIN = ROOT / "packages/ca-plugins/src/ca_plugins/builtin"
REPOS = ROOT / "tests/fixtures/repos"
DEPLOY = ROOT / "deploy/docker"
COMPOSE = ROOT / "deploy/compose/registry.yaml"
CHILD = Path(__file__).with_name("_cli_child.py")
COSIGN = os.environ.get("COSIGN", "")
SYFT = os.environ.get("SYFT", "")
OSV_FEEDS = os.environ.get("CA_TEST_OSV_FEEDS", "")
TRIVY_FEEDS = os.environ.get("CA_TEST_TRIVY_FEEDS", "")
TAG = "1.0.0"

import snapshot  # noqa: E402  (tests/fixtures/feeds)

needs_docker = pytest.mark.skipif(
    os.environ.get("CA_TEST_DOCKER") != "1" or shutil.which("docker") is None,
    reason="richiede un daemon Docker: CA_TEST_DOCKER=1",
)
needs_cosign = pytest.mark.skipif(
    not COSIGN or not os.access(COSIGN, os.X_OK),
    reason="richiede cosign v3.1.4 verificato: COSIGN=/percorso/cosign",
)
needs_syft = pytest.mark.skipif(
    not SYFT or not os.access(SYFT, os.X_OK),
    reason="richiede syft 1.57.0 (build-image.sh): SYFT=/percorso/syft",
)
needs_feeds = pytest.mark.skipif(
    not (OSV_FEEDS and TRIVY_FEEDS)
    or not (Path(OSV_FEEDS) / "osv-scalibr/npm/all.zip").is_file()
    or not (Path(TRIVY_FEEDS) / "trivy/db/trivy.db").is_file(),
    reason="richiede lo snapshot dei feed (F-05): CA_TEST_OSV_FEEDS e CA_TEST_TRIVY_FEEDS",
)
e2e_marks = [needs_docker, needs_cosign, needs_syft]


def sh(*args: str, env: dict[str, str] | None = None, timeout: int = 1800) -> str:
    return subprocess.run(
        args,
        capture_output=True,
        text=True,
        check=True,
        timeout=timeout,
        env={**os.environ, **(env or {})},
    ).stdout.strip()


def free_port() -> str:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return str(probe.getsockname()[1])


def container_leftovers() -> list[str]:
    return sh("docker", "ps", "-aq", "--filter", "label=code-analyzer.executor=1").split()


@dataclass
class CliResult:
    returncode: int
    stdout: str
    stderr: str
    seconds: float
    out_dir: Path | None = None

    @property
    def report(self) -> dict[str, Any]:
        assert self.out_dir is not None
        data: dict[str, Any] = json.loads((self.out_dir / "code-analyzer.report.json").read_text())
        return data

    def all_text(self) -> str:
        """Tutto cio' che il comando ha lasciato: stdout, stderr e ogni artefatto scritto."""
        parts = [self.stdout, self.stderr]
        if self.out_dir is not None and self.out_dir.exists():
            parts += [p.read_text(errors="replace") for p in sorted(self.out_dir.rglob("*"))
                      if p.is_file()]  # fmt: skip
        return "\n".join(parts)


@dataclass
class Fleet:
    """Registry locale, chiavi di prova e manifest impacchettati dei plugin firmati."""

    work: Path
    port: str = field(default_factory=free_port)
    project: str = field(default_factory=lambda: f"ca-e2e-{uuid.uuid4().hex[:8]}")
    manifests: dict[str, Path] = field(default_factory=dict)
    digests: dict[str, str] = field(default_factory=dict)
    refs: list[str] = field(default_factory=list)
    build_seconds: dict[str, float] = field(default_factory=dict)
    gate_sboms: dict[str, Path] = field(default_factory=dict)
    _up: bool = False

    def __post_init__(self) -> None:
        self.keys = self.work / "keys"  # fuori dal repository (tmp di pytest)
        self.other_keys = self.work / "other-keys"
        self.env = {"CA_REGISTRY_PORT": self.port, "COSIGN": COSIGN, "CA_KEY_DIR": str(self.keys)}

    @property
    def public_key(self) -> Path:
        return self.keys / "cosign.pub"

    @property
    def other_public_key(self) -> Path:
        """Chiave valida ma diversa: la firma dell'immagine non le corrisponde."""
        if not (self.other_keys / "cosign.pub").exists():
            self.other_keys.mkdir(parents=True, exist_ok=True)
            subprocess.run(
                [COSIGN, "generate-key-pair"],
                cwd=self.other_keys,
                env={**os.environ, "COSIGN_PASSWORD": ""},
                check=True,
                capture_output=True,
            )
        return self.other_keys / "cosign.pub"

    def _compose(self) -> list[str]:
        return ["docker", "compose", "-p", self.project, "-f", str(COMPOSE)]

    def add(
        self, name: str, context: Path, data: dict[str, Any], *, gate_image: bool = True
    ) -> Path:
        """Costruisce (gate licenze e SBOM), firma e scrive il manifest impacchettato di `name`."""
        if name in self.manifests:
            return self.manifests[name]
        started = time.monotonic()
        if not self._up:
            sh(*self._compose(), "up", "-d", "--wait", env=self.env)
            self._up = True
        if gate_image:
            local = f"localhost/ca-e2e-gate-{name}:{self.project}"
            sbom_dir = self.work / "sbom" / name
            sbom = sh(str(DEPLOY / "build-image.sh"), str(context), local, str(sbom_dir),
                      env={"SYFT": SYFT}).splitlines()[-1]  # fmt: skip
            self.gate_sboms[name] = Path(sbom)
            subprocess.run(["docker", "rmi", "-f", local], capture_output=True, check=False)
        image = f"ca-plugins/{name}"
        ref = sh(
            str(DEPLOY / "sign-local.sh"), str(context), image, TAG, env=self.env
        ).splitlines()[-1]
        digest = ref.split("@")[1]
        self.digests[name] = digest
        self.refs += [f"127.0.0.1:{self.port}/{image}:{TAG}", ref]
        data = {**data, "image": f"127.0.0.1:{self.port}/{image}:{TAG}@{digest}"}
        path = self.work / "manifests" / f"{name}.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(data))
        self.manifests[name] = path
        self.build_seconds[name] = round(time.monotonic() - started, 1)
        return path

    def add_builtin(self, name: str) -> Path:
        directory = {"osv-scanner": "osv_scanner", "ca-graph": "ca_graph"}.get(name, name)
        data = yaml.safe_load((BUILTIN / directory / "plugin.yaml").read_text())
        return self.add(name, BUILTIN / directory, data)

    def close(self) -> None:
        subprocess.run([*self._compose(), "down", "--volumes"], env={**os.environ, **self.env},
                       capture_output=True, check=False)  # fmt: skip
        if self.refs:
            subprocess.run(["docker", "rmi", "-f", *self.refs], capture_output=True, check=False)
        for leftover in container_leftovers():
            subprocess.run(["docker", "rm", "-f", leftover], capture_output=True, check=False)
        shutil.rmtree(self.work, ignore_errors=True)

    # -- esecuzione ---------------------------------------------------------------------------

    def run(
        self,
        cwd: Path,
        *argv: str,
        plugins: list[str],
        feeds_cache: Path | None = None,
        inject_config: dict[str, Path] | None = None,
        key: Path | None = None,
        env: dict[str, str] | None = None,
        out_dir: Path | None = None,
        network_guard: bool = True,
        timeout: int = 1200,
    ) -> CliResult:
        spec = {
            "manifests": [str(self.manifests[p]) for p in plugins],
            "feeds_cache": str(feeds_cache) if feeds_cache else None,
            "inject_config": {k: str(v) for k, v in (inject_config or {}).items()},
            "network_guard": network_guard,
        }
        spec_file = cwd / f".spec-{uuid.uuid4().hex[:6]}.json"
        spec_file.write_text(json.dumps(spec))
        child_env = {
            **os.environ,
            "COSIGN": COSIGN,
            "CA_COSIGN_PUBLIC_KEY": str(key or self.public_key),
            "XDG_CACHE_HOME": str(self.work / "xdg-cache"),  # mai la cache dell'utente
            **(env or {}),
        }
        if env is None or "CA_INSECURE_ALLOW_UNSIGNED" not in env:
            child_env.pop("CA_INSECURE_ALLOW_UNSIGNED", None)
        started = time.monotonic()
        try:
            done = subprocess.run(
                [sys.executable, str(CHILD), str(spec_file), *argv],
                capture_output=True,
                text=True,
                timeout=timeout,
                env=child_env,
                cwd=cwd,
            )
        finally:
            spec_file.unlink(missing_ok=True)
        return CliResult(done.returncode, done.stdout, done.stderr,
                         round(time.monotonic() - started, 1), out_dir)  # fmt: skip

    def scan(self, path: Path, out_dir: Path, *extra: str, plugins: list[str],
             **kwargs: Any) -> CliResult:  # fmt: skip
        return self.run(path.parent, "scan", str(path), "--output-dir", str(out_dir),
                        "--format", "json", *extra, plugins=plugins, out_dir=out_dir,
                        **kwargs)  # fmt: skip


def link_tree(source: Path, dest: Path) -> None:
    """Hard link dei file di `source` (sola lettura nel container), copia se e' un altro volume."""
    for current, dirs, names in os.walk(source, followlinks=False):
        target = dest / Path(current).relative_to(source)
        target.mkdir(parents=True, exist_ok=True)
        target.chmod(0o755)
        for name in names:
            try:
                os.link(Path(current) / name, target / name)
            except OSError:
                shutil.copy2(Path(current) / name, target / name)
        del dirs


def make_feeds_cache(cache: Path, digests: dict[str, str]) -> dict[str, Any]:
    """Cache per utente (formato di `feeds.py`) da due cartelle di feed gia' scaricati.

    Verifica prima gli SHA-256 di `SNAPSHOT.json` (se c'e'). Il puntatore porta la data dello
    snapshot: con `--offline` il prodotto lo usa anche se vecchio (avviso `feeds-stale`).
    """
    info: dict[str, Any] = {"created_at": None}
    for root, only in ((Path(OSV_FEEDS), ("osv-scalibr/",)), (Path(TRIVY_FEEDS), ("trivy/",))):
        if (root / snapshot.MANIFEST).exists():
            manifest = snapshot.verify(root, only=only)  # SnapshotError = test in errore
            info["created_at"] = manifest["created_at"]
    cache.mkdir(mode=0o700, parents=True, exist_ok=True)
    cache.chmod(0o700)
    synced = info["created_at"] or datetime.now(UTC).isoformat()
    for plugin, subtree, root in (
        ("osv-scanner", "osv-scalibr", Path(OSV_FEEDS)),
        ("trivy", "trivy", Path(TRIVY_FEEDS)),
    ):
        plugin_dir = cache / plugin
        plugin_dir.mkdir(mode=0o700)
        snap = plugin_dir / "snap-frozen01"
        snap.mkdir(mode=0o755)
        link_tree(root / subtree, snap / subtree)
        (plugin_dir / "current.json").write_text(
            json.dumps({"dir": snap.name, "synced_at": synced, "image_digest": digests[plugin]})
        )
    return info


def copy_fixture(name: str, dest: Path, *, license_policy: bool = False) -> Path:
    """Copia di una fixture fuori dal repository; la policy di licenze come `.code-analyzer.yml`."""
    target = dest / name
    shutil.copytree(REPOS / name, target, ignore=shutil.ignore_patterns("__pycache__"))
    if license_policy:
        shutil.copyfile(REPOS / "license-policy.yml", target / ".code-analyzer.yml")
    return target


_DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
