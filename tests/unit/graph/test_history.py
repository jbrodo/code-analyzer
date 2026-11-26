"""G-11: churn per file dalla storia git, letta con la git dir ombra (ADR-0012, ADR-0022)."""

import os
import shutil
import stat
import subprocess
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from ca_core.models.graph import Graph
from ca_graph.treesitter import history as hist
from ca_graph.treesitter.extract import extract_graph

GIT = shutil.which("git") or "/usr/bin/git"
HEAD_DAY = datetime(2026, 1, 1, 12, 0, tzinfo=UTC)


def git(repo: Path, *argv: str, when: datetime | None = None) -> str:
    env = {
        **os.environ,
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_AUTHOR_NAME": "t",
        "GIT_AUTHOR_EMAIL": "t@example.invalid",
        "GIT_COMMITTER_NAME": "t",
        "GIT_COMMITTER_EMAIL": "t@example.invalid",
    }
    if when is not None:
        env["GIT_AUTHOR_DATE"] = env["GIT_COMMITTER_DATE"] = when.isoformat()
    done = subprocess.run(
        [GIT, "-C", str(repo), *argv], env=env, capture_output=True, text=True, check=True
    )
    return done.stdout.strip()


def commit(repo: Path, files: dict[str, str], days_before_head: float, message: str = "c") -> None:
    for name, text in files.items():
        path = repo / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
    git(repo, "add", "-A")
    git(repo, "commit", "-q", "-m", message, when=HEAD_DAY - timedelta(days=days_before_head))


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    root = tmp_path / "repo"
    root.mkdir()
    git(root, "init", "-q", "-b", "main")
    return root


def read(root: Path, **kv: object) -> hist.History:
    return hist.read_history(str(root), git=GIT, tmp_dir=str(root.parent), **kv)  # type: ignore[arg-type]


def test_counts_commits_per_file_inside_the_window_ending_at_the_head_commit(repo: Path) -> None:
    commit(repo, {"a.py": "1"}, 200)  # fuori finestra
    commit(repo, {"a.py": "2", "b.py": "1"}, 78)  # dentro: 78 giorni prima della testa
    commit(repo, {"a.py": "3"}, 30)
    commit(repo, {"a.py": "4"}, 0)
    result = read(repo)
    assert result.status == "completa" and result.commits_read == 3
    assert result.churn == {"a.py": 3, "b.py": 1}
    assert result.head_time == HEAD_DAY


def test_the_window_is_anchored_to_the_head_commit_not_to_today(repo: Path) -> None:
    commit(repo, {"a.py": "1"}, 100)
    commit(repo, {"a.py": "2"}, 0)
    assert read(repo).churn == {"a.py": 1}  # il commit di 100 giorni prima è fuori
    assert read(repo, window_days=120).churn == {"a.py": 2}


def test_merge_commits_are_not_counted_and_renames_are_not_followed(repo: Path) -> None:
    commit(repo, {"old.py": "x" * 50}, 20)
    git(repo, "checkout", "-q", "-b", "side")
    commit(repo, {"s.py": "1"}, 10)
    git(repo, "checkout", "-q", "main")
    git(repo, "merge", "-q", "--no-ff", "side", "-m", "merge", when=HEAD_DAY - timedelta(days=5))
    git(repo, "mv", "old.py", "new.py")
    git(repo, "commit", "-q", "-m", "rename", when=HEAD_DAY)
    result = read(repo)
    assert result.churn["s.py"] == 1  # il commit del ramo, non il merge
    assert result.churn["new.py"] == 1 and result.churn["old.py"] == 2  # la rinomina conta come
    # una cancellazione di `old.py` e una creazione di `new.py`: la storia non si trasferisce
    assert result.commits_read == 3


def test_unusual_file_names_are_counted_exactly(repo: Path) -> None:
    names = ['we ird "q".py', "caffè/é.py", "tab\there.py"]
    commit(repo, {n: "1" for n in names}, 1)
    assert read(repo).churn == {n: 1 for n in names}


def test_a_shallow_clone_that_does_not_cover_the_window_has_unknown_churn(
    repo: Path, tmp_path: Path
) -> None:
    commit(repo, {"a.py": "1"}, 40)
    commit(repo, {"a.py": "2"}, 0)
    clone = tmp_path / "shallow"
    subprocess.run(
        [GIT, "clone", "-q", "--depth", "1", f"file://{repo}", str(clone)],
        check=True,
        env={**os.environ, "GIT_CONFIG_GLOBAL": os.devnull},
    )
    result = read(clone)
    assert result.status == "superficiale" and result.churn == {} and result.commits_read == 0
    assert result.head_time == HEAD_DAY


def test_a_shallow_clone_whose_boundary_is_older_than_the_window_is_complete(
    repo: Path, tmp_path: Path
) -> None:
    commit(repo, {"a.py": "1"}, 200)
    commit(repo, {"a.py": "2"}, 150)  # sarà il commit di confine, più vecchio di 90 giorni
    commit(repo, {"a.py": "3"}, 10)
    commit(repo, {"b.py": "1"}, 0)
    clone = tmp_path / "shallow2"
    subprocess.run(
        [GIT, "clone", "-q", "--depth", "3", f"file://{repo}", str(clone)],
        check=True,
        env={**os.environ, "GIT_CONFIG_GLOBAL": os.devnull},
    )
    assert (clone / ".git" / "shallow").exists()
    result = read(clone)
    assert result.status == "completa" and result.churn == {"a.py": 1, "b.py": 1}


def test_no_git_dir_is_absent(tmp_path: Path) -> None:
    (tmp_path / "w").mkdir()
    result = read(tmp_path / "w")
    assert result.status == "assente" and result.churn == {} and result.head_time is None


@pytest.mark.parametrize(
    "kind", ["gitdir-file", "symlink", "no-objects", "head-symlink", "bad-head"]
)
def test_a_git_dir_that_cannot_be_replicated_safely_is_absent(
    repo: Path, tmp_path: Path, kind: str
) -> None:
    commit(repo, {"a.py": "1"}, 0)
    dot = repo / ".git"
    if kind == "gitdir-file":
        shutil.rmtree(dot)
        dot.write_text("gitdir: /elsewhere\n")
    elif kind == "symlink":
        moved = tmp_path / "moved.git"
        dot.rename(moved)
        dot.symlink_to(moved)
    elif kind == "no-objects":
        shutil.rmtree(dot / "objects")
    elif kind == "head-symlink":
        (dot / "HEAD").unlink()
        (dot / "HEAD").symlink_to("/etc/passwd")
    else:
        (dot / "HEAD").write_text("ref: refs/heads/main; touch /tmp/x\n")
    assert read(repo).status == "assente"


def test_a_hostile_git_config_is_never_read_or_executed(repo: Path, tmp_path: Path) -> None:
    commit(repo, {"a.py": "1"}, 0)
    marker = tmp_path / "executed"
    script = tmp_path / "evil.sh"
    script.write_text(f"#!/bin/sh\ntouch {marker}\n")
    script.chmod(script.stat().st_mode | stat.S_IXUSR)
    with (repo / ".git" / "config").open("a") as config:
        config.write(
            f"[core]\n\tfsmonitor = {script}\n\tpager = {script}\n\thooksPath = {tmp_path}\n"
            f"\tsshCommand = {script}\n\teditor = {script}\n"
            f"[alias]\n\tlog = !{script}\n"
            f"[diff]\n\texternal = {script}\n[log]\n\tshowSignature = true\n"
            f"[gpg]\n\tprogram = {script}\n[include]\n\tpath = {script}\n"
            f"[uploadpack]\n\tpackObjectsHook = {script}\n"
        )
    result = read(repo)
    assert result.status == "completa" and result.churn == {"a.py": 1}
    assert not marker.exists()


def test_an_unknown_repository_extension_is_refused(repo: Path) -> None:
    commit(repo, {"a.py": "1"}, 0)
    with (repo / ".git" / "config").open("a") as config:
        config.write("[extensions]\n\tobjectformat = evil\n")
    assert read(repo).status == "assente"


def test_caps_make_the_history_absent_instead_of_truncated(
    repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    commit(repo, {"a.py": "1"}, 2)
    commit(repo, {"a.py": "2"}, 1)
    monkeypatch.setattr(hist, "MAX_COMMITS", 1)
    assert read(repo).status == "assente"
    monkeypatch.setattr(hist, "MAX_COMMITS", 100)
    monkeypatch.setattr(hist, "MAX_OUTPUT_BYTES", 10)
    assert read(repo).status == "assente"


def test_a_slow_git_times_out_and_is_absent(
    repo: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    commit(repo, {"a.py": "1"}, 0)
    slow = tmp_path / "slow-git"
    slow.write_text(f'#!/bin/sh\ncase "$*" in *" log "*) sleep 5;; esac\nexec {GIT} "$@"\n')
    slow.chmod(slow.stat().st_mode | stat.S_IXUSR)
    monkeypatch.setattr(hist, "TIMEOUT_SECONDS", 1)
    result = hist.read_history(str(repo), git=str(slow), tmp_dir=str(tmp_path))
    assert result.status == "assente"


def test_a_missing_git_binary_is_absent(repo: Path, tmp_path: Path) -> None:
    commit(repo, {"a.py": "1"}, 0)
    result = hist.read_history(str(repo), git="/nonexistent/git", tmp_dir=str(tmp_path))
    assert result.status == "assente"


def test_the_scratch_directory_is_always_removed(repo: Path) -> None:
    commit(repo, {"a.py": "1"}, 0)
    read(repo)
    assert not [p for p in repo.parent.iterdir() if p.name.startswith("ca-history-")]


def test_garbage_output_is_refused() -> None:
    with pytest.raises(hist.ReadFailed):
        hist.parse_log(b"\x01abc")


def test_history_document_omits_nothing_the_contract_requires() -> None:
    assert hist.History("assente", 90).document() == {"status": "assente", "window_days": 90}


# --- nel grafo ---------------------------------------------------------------------------------


def test_the_graph_carries_churn_for_every_module_and_conforms(repo: Path) -> None:
    commit(repo, {"app/a.py": "import app.b\n", "app/b.py": "x = 1\n", "app/c.py": ""}, 200)
    commit(repo, {"app/a.py": "import app.b\n# 2\n"}, 5)
    commit(repo, {"app/a.py": "import app.b\n# 3\n", "app/b.py": "x = 2\n"}, 0)
    # il file non toccato nella finestra ha churn 0, non None: la storia è completa
    document = extract_graph(str(repo), history=read(repo))
    churn = {m["path"]: m["churn"] for m in document["modules"]}
    assert churn == {"app/a.py": 2, "app/b.py": 1, "app/c.py": 0}
    assert document["history"] == {
        "status": "completa",
        "window_days": 90,
        "head_time": HEAD_DAY.isoformat(),
        "commits_read": 2,
    }
    Graph.model_validate(document)


def test_the_graph_has_no_churn_when_the_history_is_not_complete(
    repo: Path, tmp_path: Path
) -> None:
    commit(repo, {"a.py": "1"}, 40)
    commit(repo, {"a.py": "2"}, 0)
    clone = tmp_path / "s"
    subprocess.run(
        [GIT, "clone", "-q", "--depth", "1", f"file://{repo}", str(clone)],
        check=True,
        env={**os.environ, "GIT_CONFIG_GLOBAL": os.devnull},
    )
    document = extract_graph(str(clone), history=read(clone))
    assert all("churn" not in m for m in document["modules"])
    assert document["history"]["status"] == "superficiale"
    Graph.model_validate(document)


def test_extract_graph_reads_the_history_itself_when_none_is_given(
    repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    commit(repo, {"a.py": "1"}, 0)
    monkeypatch.setattr(hist, "GIT", GIT)
    monkeypatch.setattr(hist, "TMP_DIR", str(repo.parent))
    monkeypatch.setattr(
        hist.read_history, "__kwdefaults__", {"git": GIT, "tmp_dir": str(repo.parent)}
    )
    assert extract_graph(str(repo))["modules"][0]["churn"] == 1
