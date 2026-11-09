"""N-10, N-10b (S-01): lockfile e sorgenti come symlink azzerano gli scanner senza traccia.

`count_skipped_symlinks` li conta sull'host (mai i nomi) e `scan` li dichiara con `partial`.
"""

import json
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
        "package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml", "poetry.lock",
        "Pipfile.lock", "uv.lock", "pdm.lock", "requirements.txt", "sub/package-lock.json",
        "a.js", "a.jsx", "a.mjs", "a.cjs", "a.ts", "a.tsx", "a.mts", "a.cts", "a.py", "a.pyi",
        "A.PY",
    ],
)  # fmt: skip
def test_analyzed_names_count_one_each(tmp_path: Path, name: str) -> None:
    link(tmp_path, name)
    assert count_skipped_symlinks(str(tmp_path), EXCLUDES) == 1


def test_other_links_regular_files_and_excluded_paths_do_not_count(tmp_path: Path) -> None:
    link(tmp_path, "notes.txt")  # nome non analizzato
    link(tmp_path, "dirlink.py")
    (tmp_path / "dir.py").mkdir()  # una directory vera con estensione sorgente
    (tmp_path / "ok.py").write_text("x")
    link(tmp_path, "node_modules/p/package-lock.json")  # esclusa di default
    assert count_skipped_symlinks(str(tmp_path), EXCLUDES) == 1  # solo `dirlink.py`
    assert count_skipped_symlinks(str(tmp_path), [*EXCLUDES, "dirlink.py"]) == 0


def test_links_are_not_followed_and_limits_are_source_errors(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    outside = tmp_path / "outside"
    (outside / "deep").mkdir(parents=True)
    (outside / "deep/a.js").symlink_to(outside / "deep")
    root = tmp_path / "r"
    root.mkdir()
    (root / "dirlink").symlink_to(outside)  # non si scende: `deep/a.js` non conta
    assert count_skipped_symlinks(str(root), EXCLUDES) == 0
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
    text = "2 collegamenti simbolici a lockfile o sorgenti non analizzati: analisi incompleta"
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
