"""Test del costruttore della storia con segreti finti (F-04) e verifica con gitleaks reale."""

import json
import os
import re
import shutil
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Any

import pytest
import yaml
from jsonschema import Draft202012Validator
from secrets_history import (
    EXPECTED_HITS,
    HISTORY,
    MARKER,
    REPO_FIXTURE,
    SEED,
    SecretsHistory,
    build_history,
    fake_secrets,
    foreign_owner_env,
    git,
    safe_directory_env,
    shallow_clone,
)

ROOT = Path(__file__).resolve().parents[3]
SCHEMA = ROOT / "tests/fixtures/expected-findings.schema.json"
PINNED_SHAS = (
    "d60da917f0c059cce612b1da2bb2cb9204b7ce5a",
    "124f457f5c14fb64a5aeb12a36a570aa5f176804",
    "91313c142cc72c157094fcb3db8dca1fd8b260a7",
    "462cb7860d8e86d0a77aa0d9d1c426ac4c4d1f15",
)
# Forme complete dei due servizi, composte a pezzi per non scriverle nel sorgente.
FULL_FORMS = (
    re.compile("gh" + "p_[0-9A-Za-z]{36}"),
    re.compile("gl" + "pat-[0-9A-Za-z_-]{20}"),
)


@pytest.fixture(scope="module")
def history(tmp_path_factory: pytest.TempPathFactory) -> SecretsHistory:
    return build_history(tmp_path_factory.mktemp("sh") / "repo")


# --- costruttore -----------------------------------------------------------------------------


def test_history_is_deterministic_and_shas_are_pinned(
    history: SecretsHistory, tmp_path: Path
) -> None:
    again = build_history(tmp_path / "again")
    assert history.commits == again.commits == PINNED_SHAS
    log = git(history.path, "log", "--format=%an|%ae|%cn|%ce|%at|%s", "--reverse").splitlines()
    assert len(log) == len(HISTORY)
    for line, step in zip(log, HISTORY, strict=True):
        an, ae, cn, ce, date, subject = line.split("|", 5)
        assert (an, ae, cn, ce) == ("Fixture Author", "fixture@example.invalid") * 2
        assert (int(date), subject) == (
            int(datetime.fromisoformat(step.date).timestamp()),
            step.message,
        )


def test_secrets_are_deterministic_marked_and_seed_dependent() -> None:
    first, again = fake_secrets(), fake_secrets()
    assert {k: v.value for k, v in first.items()} == {k: v.value for k, v in again.items()}
    assert fake_secrets(SEED + "-other")["PAT"].value != first["PAT"].value
    assert FULL_FORMS[0].fullmatch(first["PAT"].value)
    assert FULL_FORMS[1].fullmatch(first["GITLAB"].value)
    assert all(MARKER in s.value for s in first.values())
    assert all(s.value not in repr(s) for s in first.values())  # il repr non rivela il valore


def test_secret_in_head_and_removed_secret_only_in_history(history: SecretsHistory) -> None:
    pat, gitlab = history.secrets["PAT"], history.secrets["GITLAB"]
    head = git(history.path, "grep", "-l", "-F", pat.value, "HEAD")
    assert head == "HEAD:app/settings.py"
    assert (
        subprocess.run(
            ["git", "-C", str(history.path), "grep", "-q", "-F", gitlab.value, "HEAD"]
        ).returncode
        == 1
    )
    assert not (history.path / "deploy/.env").exists()
    in_history = git(history.path, "log", "--format=%H", "-S", gitlab.value, "--all").split()
    assert in_history == [history.commits[3], history.commits[1]]  # rimosso e aggiunto
    pat_commits = git(history.path, "log", "--format=%H", "-S", pat.value, "--all").split()
    assert history.commits[0] in pat_commits  # stesso valore ricompare piu volte nel file
    for sha in (history.commits[0], history.commits[2]):
        assert pat.value in git(history.path, "show", f"{sha}:app/settings.py")


def test_shallow_clone_keeps_only_head(history: SecretsHistory, tmp_path: Path) -> None:
    clone = shallow_clone(history.path, tmp_path / "shallow")
    assert git(clone, "rev-parse", "--is-shallow-repository") == "true"
    assert git(clone, "rev-list", "--count", "HEAD") == "1"
    assert git(clone, "rev-parse", "HEAD") == history.commits[-1]
    assert history.secrets["GITLAB"].value not in git(clone, "log", "-p", "--all")


def test_expected_findings_are_valid_and_point_at_the_history(history: SecretsHistory) -> None:
    data: dict[str, Any] = yaml.safe_load(
        (REPO_FIXTURE / "expected-findings.yaml").read_text(encoding="utf-8")
    )
    validator = Draft202012Validator(json.loads(SCHEMA.read_text(encoding="utf-8")))
    assert [e.message for e in validator.iter_errors(data)] == []
    for entry in data["expected"]:
        assert entry["category"] == "secret" and entry["tools"] == ["gitleaks"]
        in_history = git(
            history.path, "log", "--all", "--format=%H", "--", entry["path"]
        ).splitlines()
        assert in_history, f"{entry['path']} non compare nella storia"
    head_entry = next(e for e in data["expected"] if e["rule_id"] == "github-pat")
    lines = (history.path / head_entry["path"]).read_text(encoding="utf-8").splitlines()
    assert history.secrets["PAT"].value in lines[head_entry["start_line"] - 1]


def test_committable_files_never_contain_a_full_secret(history: SecretsHistory) -> None:
    """Ricerca su tutti i file committabili: nessuna forma completa e nessun valore generato."""
    listing = subprocess.run(
        ["git", "-C", str(ROOT), "ls-files", "-z", "--cached", "--others", "--exclude-standard"],
        capture_output=True,
        check=True,
    ).stdout.split(b"\0")
    values = [s.value.encode() for s in history.secrets.values()]
    scanned = 0
    for name in filter(None, listing):
        path = ROOT / name.decode()
        if not path.is_file():
            continue  # cancellato nel working tree ma ancora nell'indice
        data = path.read_bytes()
        scanned += 1
        for pattern in FULL_FORMS:
            assert not pattern.search(data.decode("latin-1")), f"forma completa in {path}"
        assert not any(v in data for v in values), f"valore generato in {path}"
    assert scanned > 50


# --- gitleaks reale --------------------------------------------------------------------------


def _gitleaks() -> str | None:
    return os.environ.get("CA_GITLEAKS_BIN") or shutil.which("gitleaks")


needs_gitleaks = pytest.mark.skipif(
    _gitleaks() is None, reason="gitleaks assente: imposta CA_GITLEAKS_BIN"
)


def scan(
    repo: Path, tmp_path: Path, extra_env: dict[str, str] | None = None
) -> tuple[int, list[dict[str, Any]], str]:
    """Esegue gitleaks sulla storia; restituisce exit, risultati e log."""
    report = tmp_path / f"{repo.name}-report.json"
    env = {**os.environ, "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_NOSYSTEM": "1"}
    env.update(extra_env or {})
    proc = subprocess.run(
        [str(_gitleaks()), "git", "--no-banner", "--no-color", "--report-format", "json",
         "--report-path", str(report), str(repo)],
        env=env, capture_output=True, text=True, check=False, timeout=120,
    )  # fmt: skip
    findings = json.loads(report.read_text()) if report.exists() else []
    return proc.returncode, findings, proc.stdout + proc.stderr


def _hits(
    findings: list[dict[str, Any]], history: SecretsHistory
) -> set[tuple[str, str, str, str]]:
    """(regola, file, commit, sha256 del valore): il valore e' confrontato solo per hash."""
    import hashlib

    return {
        (f["RuleID"], f["File"], f["Commit"], hashlib.sha256(f["Secret"].encode()).hexdigest())
        for f in findings
    }


def _expected(history: SecretsHistory) -> set[tuple[str, str, str, str]]:
    return {
        (history.secrets[name].rule_id, path, history.commits[idx], history.secrets[name].sha256)
        for name, path, idx in EXPECTED_HITS
    }


@needs_gitleaks
def test_gitleaks_finds_every_expected_secret_in_the_full_history(
    history: SecretsHistory, tmp_path: Path
) -> None:
    code, findings, _ = scan(history.path, tmp_path)
    assert code == 1  # exit 1: perdite trovate
    assert _hits(findings, history) == _expected(history)


@needs_gitleaks
def test_gitleaks_on_a_shallow_clone_sees_only_the_secret_in_head(
    history: SecretsHistory, tmp_path: Path
) -> None:
    clone = shallow_clone(history.path, tmp_path / "shallow")
    code, findings, _ = scan(clone, tmp_path)
    assert code == 1
    rules = {f["RuleID"] for f in findings}
    assert rules == {"github-pat"}  # il segreto rimosso non e' piu raggiungibile
    assert {f["File"] for f in findings} == {"app/settings.py"}
    assert {f["Commit"] for f in findings} == {history.commits[-1]}
    assert git(clone, "rev-parse", "--is-shallow-repository") == "true"


@needs_gitleaks
def test_foreign_owner_is_a_silent_false_negative_without_safe_directory(
    history: SecretsHistory, tmp_path: Path
) -> None:
    """Exit 0 e zero risultati: il test lo distingue da un repository pulito dal log."""
    code, findings, log = scan(history.path, tmp_path, foreign_owner_env())
    assert (code, findings) == (0, [])
    assert "dubious ownership" in log

    clean = build_clean_repo(tmp_path / "clean")
    clean_code, clean_findings, clean_log = scan(clean, tmp_path, foreign_owner_env())
    assert (clean_code, clean_findings) == (0, [])  # stesso esito apparente di un repo pulito
    assert "dubious ownership" in clean_log  # solo il log dice che non ha letto nulla

    honest = build_clean_repo(tmp_path / "honest")
    h_code, h_findings, h_log = scan(honest, tmp_path)
    assert (h_code, h_findings) == (0, [])
    assert "dubious ownership" not in h_log  # repository pulito davvero


@needs_gitleaks
def test_foreign_owner_with_safe_directory_finds_everything(
    history: SecretsHistory, tmp_path: Path
) -> None:
    env = {**foreign_owner_env(), **safe_directory_env(history.path)}
    code, findings, log = scan(history.path, tmp_path, env)
    assert code == 1 and "dubious ownership" not in log
    assert _hits(findings, history) == _expected(history)


def build_clean_repo(dest: Path) -> Path:
    """Repository senza segreti, per distinguere 'pulito' da 'non letto'."""
    dest.mkdir(parents=True)
    env = {
        "PATH": os.environ["PATH"], "HOME": str(dest.parent), "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_CONFIG_NOSYSTEM": "1", "GIT_AUTHOR_NAME": "a", "GIT_AUTHOR_EMAIL": "a@example.invalid",
        "GIT_COMMITTER_NAME": "a", "GIT_COMMITTER_EMAIL": "a@example.invalid",
    }  # fmt: skip
    git(dest, "init", "-q", "-b", "main", env=env)
    (dest / "README.md").write_text("nothing here\n", encoding="utf-8")
    git(dest, "add", "-A", env=env)
    git(dest, "-c", "commit.gpgsign=false", "commit", "-q", "-m", "init", env=env)
    return dest
