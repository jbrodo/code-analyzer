"""N-10, N-10b, N-17, N-18 (S-01): i file come symlink azzerano gli scanner senza traccia.

`count_skipped_symlinks` li conta sull'host (mai i nomi) e `scan` li dichiara con `partial`.
"""

import json
import os
from pathlib import Path

import pytest
from test_cli_scan_gate import REPORT, Env

from ca_core.fakes import FakePluginExecutor
from ca_core.pipeline.exclusions import coverage_exclusions
from ca_core.ports import SourceError
from ca_plugins import source
from ca_plugins.source import count_skipped_symlinks

EXCLUDES = coverage_exclusions([])


def link(root: Path, name: str, target: str = "real/x.txt") -> None:
    (root / "real").mkdir(exist_ok=True)
    (root / "real/x.txt").write_text("x")
    path = root / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.symlink_to(root / target)


@pytest.mark.parametrize(
    "name",
    [
        "package-lock.json", "yarn.lock", "poetry.lock", "requirements.txt",
        "sub/package-lock.json", "a.js", "a.ts", "a.py", "A.PY",
        "bun.lock", "requirements-dev.txt", "dev-requirements.txt", "pylock.toml",  # N-17
        "Dockerfile", "api.Dockerfile", "main.tf", "deploy.yaml", "pod.yml",  # N-18
        "Cargo.lock", "go.mod", "Gemfile.lock", "composer.lock",
        "notes.txt", "senza-estensione",  # il nome non conta
    ],
)  # fmt: skip
def test_every_file_link_counts_whatever_its_name(tmp_path: Path, name: str) -> None:
    link(tmp_path, name)
    assert count_skipped_symlinks(str(tmp_path), EXCLUDES) == 1


@pytest.mark.parametrize("target", ["manca", "link"])  # rotto, in ciclo
def test_broken_and_looping_links_count(tmp_path: Path, target: str) -> None:
    (tmp_path / "link").symlink_to(target)
    assert count_skipped_symlinks(str(tmp_path), EXCLUDES) == 1


def test_directory_links_regular_files_and_excluded_paths_do_not_count(tmp_path: Path) -> None:
    link(tmp_path, "kept.py")
    (tmp_path / "dir.py").mkdir()  # una directory vera con estensione sorgente
    (tmp_path / "ok.py").write_text("x")
    (tmp_path / "to-dir.py").symlink_to(tmp_path / "dir.py")  # la destinazione resta analizzata
    link(tmp_path, "node_modules/p/package-lock.json")  # esclusa di default
    assert count_skipped_symlinks(str(tmp_path), EXCLUDES) == 1  # solo `kept.py`
    assert count_skipped_symlinks(str(tmp_path), [*EXCLUDES, "kept.py"]) == 0


def test_directory_link_leaving_the_scanned_root_counts(tmp_path: Path) -> None:
    (tmp_path / "elsewhere").mkdir()
    root = tmp_path / "services/api"
    root.mkdir(parents=True)
    (root / "app").symlink_to("../../elsewhere")  # N-20
    assert count_skipped_symlinks(str(root), EXCLUDES) == 1


@pytest.mark.parametrize("kind", ["dir", "file", "missing"])
def test_link_leaving_the_root_does_not_reveal_the_target_type(tmp_path: Path, kind: str) -> None:
    root = tmp_path / "r"
    root.mkdir()
    target = tmp_path / "t"  # N-22: stesso numero qualunque sia la destinazione
    if kind == "dir":
        target.mkdir()
    elif kind == "file":
        target.write_text("x")
    (root / "link").symlink_to(target)
    assert count_skipped_symlinks(str(root), EXCLUDES) == 1


def test_directory_link_into_an_excluded_path_counts(tmp_path: Path) -> None:
    (tmp_path / "dist/app").mkdir(parents=True)
    (tmp_path / "app").symlink_to("dist/app")  # esclusa di default
    (tmp_path / "vendor/lib").mkdir(parents=True)
    (tmp_path / "lib").symlink_to("vendor/lib")
    assert count_skipped_symlinks(str(tmp_path), EXCLUDES) == 1
    assert count_skipped_symlinks(str(tmp_path), [*EXCLUDES, "vendor"]) == 2


def test_directory_link_into_dot_git_counts(tmp_path: Path) -> None:
    (tmp_path / ".git/x").mkdir(parents=True)
    (tmp_path / "app").symlink_to(".git/x")  # N-25
    assert count_skipped_symlinks(str(tmp_path), EXCLUDES) == 1


def test_link_to_the_root_or_to_an_analyzed_directory_does_not_count(tmp_path: Path) -> None:
    (tmp_path / "self").symlink_to(".")
    (tmp_path / "a/b").mkdir(parents=True)
    (tmp_path / "a/up").symlink_to("..")
    assert count_skipped_symlinks(str(tmp_path), EXCLUDES) == 0


def test_long_chains_stop_at_the_kernel_limit_before_realpath(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / "real").mkdir()
    (tmp_path / "l0").symlink_to("real")
    for i in range(1, 45):
        (tmp_path / f"l{i}").symlink_to(f"l{i - 1}")
    resolved: list[str] = []
    real = os.path.realpath
    monkeypatch.setattr(os.path, "realpath", lambda p: resolved.append(p) or real(p))  # N-23
    assert count_skipped_symlinks(str(tmp_path), EXCLUDES) == 5  # oltre 40 livelli
    assert len(resolved) == 41  # la radice e i 40 link risolti dal kernel


def test_links_are_not_followed_and_limits_are_source_errors(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    outside = tmp_path / "outside"
    (outside / "deep").mkdir(parents=True)
    (outside / "deep/a.js").symlink_to(outside / "deep")
    root = tmp_path / "r"
    root.mkdir()
    (root / "dirlink").symlink_to(outside)  # conta il link, ma non si scende in `deep/a.js`
    assert count_skipped_symlinks(str(root), EXCLUDES) == 1
    monkeypatch.setattr(source, "MAX_FILES", 1)
    link(root, "a.js")
    with pytest.raises(SourceError):
        count_skipped_symlinks(str(root), EXCLUDES)
    monkeypatch.setattr(source, "MAX_FILES", 100)
    monkeypatch.setattr(source, "MAX_DEPTH", 1)
    (root / "1/2/3").mkdir(parents=True)
    with pytest.raises(SourceError):
        count_skipped_symlinks(str(root), EXCLUDES)


def test_scan_with_skipped_symlinks_is_partial_with_only_the_count(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    env = Env(tmp_path)
    link(env.repo, "package-lock.json")
    link(env.repo, "TOP-SECRET-NAME.js")
    executor = FakePluginExecutor({"bandit": env.ok()})
    assert env.scan(env.context(executor), "--format", "json") == 0
    captured = capsys.readouterr()
    report = json.loads((env.out / REPORT).read_text())
    assert report["status"] == "partial"
    (warning,) = (w for w in report["warnings"] if w["code"] == "workspace-symlinks")
    text = "2 collegamenti simbolici con contenuto non analizzato: analisi incompleta"
    assert warning["message"] == text and text in captured.err
    for blob in (captured.out, captured.err, json.dumps(report)):
        assert "TOP-SECRET-NAME" not in blob
    assert len(executor.runs) == 1  # i plugin girano comunque


def test_scan_without_such_symlinks_is_complete(tmp_path: Path) -> None:
    env = Env(tmp_path)
    assert env.scan(env.context(FakePluginExecutor({"bandit": env.ok()}))) == 0
    report = json.loads((env.out / REPORT).read_text())
    assert report["status"] == "complete"
    assert all(w["code"] != "workspace-symlinks" for w in report["warnings"])
