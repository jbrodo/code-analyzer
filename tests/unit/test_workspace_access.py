"""A-02 (ADR-0004, R-09): `count_unreadable`, `coverage_exclusions` e l'esito di `scan`.

Il plugin gira come 65534; i test girano come un utente comune, quindi nessun file è del
proprietario 65534: vale la classe "altri" (`mode & 7`). La regola per le tre classi è provata con
la funzione pura `plugin_can_read`. Nessun Docker.
"""

import json
import os
from pathlib import Path

import pytest
from test_cli_scan_gate import REPORT, Env

from ca_core.fakes import FakePluginExecutor
from ca_core.pipeline.exclusions import DEFAULT_EXCLUDES, coverage_exclusions
from ca_core.ports import SourceError
from ca_plugins import source
from ca_plugins.source import count_unreadable, plugin_can_read

pytestmark = pytest.mark.skipif(os.geteuid() == 0, reason="root legge tutto")

EXCLUDES = coverage_exclusions([])


def tree(root: Path, files: dict[str, int]) -> Path:
    """`files`: percorso relativo -> permessi del file; le directory restano 0755."""
    for name, mode in files.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("x")
        path.chmod(mode)
    return root


@pytest.fixture(autouse=True)
def restore_modes(tmp_path: Path) -> object:
    yield
    for path in [tmp_path, *tmp_path.rglob("*")]:
        if not path.is_symlink():
            path.chmod(0o755 if path.is_dir() else 0o644)


def test_plugin_class_is_decided_by_uid_then_gid_then_others() -> None:
    f = {"is_dir": False}
    assert plugin_can_read(0o604, 1000, 1000, **f) and not plugin_can_read(0o640, 1000, 1000, **f)
    # proprietario 65534: contano solo i bit proprietario
    assert plugin_can_read(0o400, 65534, 1000, **f) and not plugin_can_read(0o044, 65534, 1000, **f)
    # gruppo 65534 (non proprietario): un 0604 non è leggibile, Linux non somma le classi
    assert not plugin_can_read(0o604, 1000, 65534, **f)
    assert plugin_can_read(0o640, 1000, 65534, **f)
    # directory: servono r e x
    assert plugin_can_read(0o755, 1000, 1000, is_dir=True)
    assert not plugin_can_read(0o754, 1000, 1000, is_dir=True)  # altri: solo r
    assert not plugin_can_read(0o751, 1000, 1000, is_dir=True)  # altri: solo x


def test_readable_tree_counts_zero(tmp_path: Path) -> None:
    root = tree(tmp_path / "r", {"a.py": 0o644, "d/b.py": 0o644, "d/e/c.py": 0o604})
    assert count_unreadable(str(root), EXCLUDES) == 0


def test_file_without_other_read_counts_once(tmp_path: Path) -> None:
    root = tree(tmp_path / "r", {"a.py": 0o600, "b.py": 0o640, "c.py": 0o644})
    assert count_unreadable(str(root), EXCLUDES) == 2


def test_everything_below_an_unreadable_directory_counts(tmp_path: Path) -> None:
    root = tree(tmp_path / "r", {"d/a.py": 0o644, "d/s/b.py": 0o644, "ok.py": 0o644})
    (root / "d").chmod(0o700)  # altri: nessun bit
    # d (non leggibile) + a.py + s + b.py, visitati dall'host che è il proprietario
    assert count_unreadable(str(root), EXCLUDES) == 4


def test_directory_without_x_counts_even_if_readable(tmp_path: Path) -> None:
    root = tree(tmp_path / "r", {"d/a.py": 0o644})
    (root / "d").chmod(0o744)
    assert count_unreadable(str(root), EXCLUDES) == 2


def test_unreadable_root_counts_itself_and_its_content(tmp_path: Path) -> None:
    root = tree(tmp_path / "r", {"a.py": 0o644})
    root.chmod(0o700)
    assert count_unreadable(str(root), EXCLUDES) == 2


def test_excluded_paths_are_neither_counted_nor_visited(tmp_path: Path) -> None:
    root = tree(tmp_path / "r", {"node_modules/x/a.js": 0o600, "secret.env": 0o600, "a.py": 0o644})
    assert count_unreadable(str(root), EXCLUDES) == 1  # solo secret.env
    assert count_unreadable(str(root), coverage_exclusions(["secret.env"])) == 0


def test_git_counts_even_though_it_is_a_default_exclusion(tmp_path: Path) -> None:
    root = tree(tmp_path / "r", {".git/objects/aa": 0o600, "a.py": 0o644})
    assert "**/.git" in DEFAULT_EXCLUDES and "**/.git" not in EXCLUDES
    assert count_unreadable(str(root), EXCLUDES) == 1


def test_symlinks_and_special_files_are_not_followed_or_counted(tmp_path: Path) -> None:
    root = tree(tmp_path / "r", {"a.py": 0o644})
    secret = tree(tmp_path / "outside", {"s.txt": 0o600})
    (root / "link").symlink_to(secret / "s.txt")
    (root / "dirlink").symlink_to(secret)
    os.mkfifo(root / "fifo", 0o600)
    assert count_unreadable(str(root), EXCLUDES) == 0


def test_limits_are_source_errors(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    root = tree(tmp_path / "r", {"a": 0o644, "b": 0o644, "c": 0o644})
    monkeypatch.setattr(source, "MAX_FILES", 2)
    with pytest.raises(SourceError):
        count_unreadable(str(root), EXCLUDES)
    monkeypatch.setattr(source, "MAX_FILES", 100)
    monkeypatch.setattr(source, "MAX_DEPTH", 1)
    deep = tree(tmp_path / "d", {"1/2/3/f": 0o644})
    with pytest.raises(SourceError):
        count_unreadable(str(deep), EXCLUDES)


def test_coverage_exclusions_drop_tool_exemptions_and_keep_user_patterns() -> None:
    assert coverage_exclusions(["build", "**/dist"]) == [
        *(p for p in DEFAULT_EXCLUDES if p != "**/.git"),
        "build",
    ]


# --- esito di `scan` -----------------------------------------------------------------------


def test_scan_with_unreadable_paths_is_partial_with_only_the_count(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    env = Env(tmp_path)
    (env.repo / "app.py").chmod(0o600)
    (env.repo / "TOP-SECRET-NAME.py").write_text("x")
    (env.repo / "TOP-SECRET-NAME.py").chmod(0o600)
    executor = FakePluginExecutor({"bandit": env.ok()})
    assert env.scan(env.context(executor), "--format", "json") == 0
    captured = capsys.readouterr()
    report = json.loads((env.out / REPORT).read_text())
    assert report["status"] == "partial"
    (warning,) = (w for w in report["warnings"] if w["code"] == "workspace-unreadable")
    assert warning["message"] == "2 percorsi non leggibili dai plugin: analisi incompleta"
    assert "subject" not in warning or warning["subject"] is None
    assert warning["message"] in captured.err  # una riga su stderr
    for text in (captured.out, captured.err, json.dumps(report)):
        assert "TOP-SECRET-NAME" not in text  # mai i nomi dei file non leggibili
    assert len(executor.runs) == 1  # i plugin girano comunque


def test_scan_of_a_readable_tree_has_no_unreadable_warning(tmp_path: Path) -> None:
    env = Env(tmp_path)
    assert env.scan(env.context(FakePluginExecutor({"bandit": env.ok()}))) == 0
    report = json.loads((env.out / REPORT).read_text())
    assert report["status"] == "complete"
    assert all(w["code"] != "workspace-unreadable" for w in report["warnings"])
