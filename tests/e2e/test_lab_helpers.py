"""Gli attrezzi degli E2E sono codice: se sbagliassero, le prove sarebbero vuote. Senza Docker."""

import json
import os
import subprocess
from datetime import UTC, datetime
from pathlib import Path

import pytest
import snapshot

from ca_core.models import PackagedPluginManifest
from ca_core.models.scan_report import Isolation
from ca_plugins.feeds import ensure_snapshot

from . import e2e_lab
from .test_secret_sentinel import Sentinel, build_repo

DIGEST = "sha256:" + "ab" * 32


def test_sentinel_detector_catches_the_value_a_fragment_and_the_json_escaped_form() -> None:
    sentinel = Sentinel()
    assert sentinel.leaks_in("niente") == []
    assert sentinel.leaks_in(f"x {sentinel.value} y") == [*sentinel.needles]
    assert sentinel.leaks_in(f"frammento {sentinel.value[8:24]}") == [sentinel.needles[1]]
    assert sentinel.leaks_in(json.dumps({"k": sentinel.value})) == [*sentinel.needles]


def test_sentinel_repo_really_contains_the_value_in_history_and_in_head(tmp_path: Path) -> None:
    sentinel = Sentinel()
    repo = build_repo(tmp_path, sentinel)
    history = subprocess.run(["git", "-C", str(repo), "log", "-p", "--all"], capture_output=True,
                             text=True, check=True).stdout  # fmt: skip
    assert history.count(sentinel.value) >= 3  # commit 1 (aggiunta e rimozione) e commit 3
    assert sentinel.value in (repo / "app.py").read_text()  # B105 la attiverebbe
    assert sentinel.value not in (repo / "settings.py").read_text()  # solo nella storia
    assert "$VALUE" in (repo / "rules/leak.yaml").read_text()  # metavariabile nel messaggio
    assert sentinel.value not in (repo / ".code-analyzer.yml").read_text()


def test_feeds_cache_is_read_by_the_product_as_a_fresh_enough_offline_snapshot(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    osv, trivy = tmp_path / "osv", tmp_path / "trivy"
    for eco in ("npm", "PyPI"):
        (osv / "osv-scalibr" / eco).mkdir(parents=True)
        (osv / "osv-scalibr" / eco / "all.zip").write_bytes(b"z")
    (trivy / "trivy/db").mkdir(parents=True)
    (trivy / "trivy/db/trivy.db").write_bytes(b"db")
    root = tmp_path / "frozen"
    snapshot.freeze(osv=osv, trivy=trivy, dest=root, now=datetime(2026, 1, 1, tzinfo=UTC))
    monkeypatch.setattr(e2e_lab, "OSV_FEEDS", str(root))
    monkeypatch.setattr(e2e_lab, "TRIVY_FEEDS", str(root))
    cache = tmp_path / "cache"
    info = e2e_lab.make_feeds_cache(cache, {"osv-scanner": DIGEST, "trivy": DIGEST})
    assert info["created_at"].startswith("2026-01-01")

    manifest = PackagedPluginManifest.model_validate(
        {**_manifest(), "image": f"127.0.0.1:5000/ca-plugins/trivy:1.0.0@{DIGEST}"}
    )

    class NoExecutor:
        def sync_feeds(self, request: object) -> object:
            raise AssertionError("offline: nessuna sincronizzazione")

        def isolation(self) -> Isolation:
            return Isolation.HARDENED_CONTAINER

        def __getattr__(self, name: str) -> object:
            raise AssertionError(name)

    class Clock:
        def now(self) -> datetime:
            return datetime(2026, 11, 9, tzinfo=UTC)

    outcome = ensure_snapshot(manifest, NoExecutor(), cache, Clock(), offline=True)  # type: ignore[arg-type]
    assert outcome.failure is None and outcome.snapshot_dir is not None
    assert [w.code for w in outcome.warnings] == ["feeds-stale"]  # congelato: vecchio per scelta
    assert (Path(outcome.snapshot_dir) / "trivy/db/trivy.db").read_bytes() == b"db"
    assert (
        os.stat(root / "trivy/db/trivy.db").st_ino
        == os.stat(Path(outcome.snapshot_dir) / "trivy/db/trivy.db").st_ino
    )  # hard link: lo snapshot congelato non si copia a ogni prova


def _manifest() -> dict[str, object]:
    return {
        "apiVersion": "code-analyzer/v1",
        "name": "trivy",
        "version": "1.0.0",
        "image": "x",
        "capabilities": ["detect"],
        "languages": [],
        "categories": ["dependency"],
        "inputs": {"workspace": "readonly", "config": "none", "sbom": "none"},
        "outputs": {"sarif": "/out/results.sarif", "max_bytes": 1048576},
        "resources": {"cpu": "1", "memory": "256Mi", "pids": 64, "timeout": "10s"},
        "network": "none",
        "feeds": {
            "sync_command": ["true"],
            "ecosystems": [],
            "mount": "/feeds",
            "sync_timeout": "60s",
        },
    }


def test_cli_result_text_collects_stdout_stderr_and_every_artifact(tmp_path: Path) -> None:
    out = tmp_path / "out"
    (out / "sub").mkdir(parents=True)
    (out / "a.json").write_text("AAA")
    (out / "sub" / "b.txt").write_text("BBB")
    text = e2e_lab.CliResult(0, "STDOUT", "STDERR", 0.1, out).all_text()
    assert all(part in text for part in ("STDOUT", "STDERR", "AAA", "BBB"))
