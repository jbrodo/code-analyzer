"""Test del costruttore del repository per le PR (F-06).

Non eseguono scanner: provano che la storia e' quella dichiarata e che ogni caso ha davvero la
proprieta' per cui esiste, calcolata con le funzioni di fingerprint del nucleo (ADR-0008). Che gli
scanner e la modalita' PR trattino i casi come ADR-0025 prescrive lo prova T-04.
"""

import json
from pathlib import Path

import pytest
import yaml
from jsonschema import Draft202012Validator
from pr_repository import (
    BASE_CONFIG,
    BASE_TREE,
    CONFIG_PATH,
    EXPECTED,
    PR_TREE,
    WEAKENED_CONFIG,
    Expected,
    PrRepository,
    build_pr_repository,
    export,
    line_of,
)
from secrets_history import git

from ca_core.fingerprint import context_hash, fingerprint_code

ROOT = Path(__file__).resolve().parents[3]
CONFIG_SCHEMA = ROOT / "schemas" / "code-analyzer-config.schema.json"
PINNED = {
    "base": "00d5bfd579033a860c3a14fdcd2c70241982ca84",
    "main_head": "be150417e708898e2fed55a3828246469d3ecb6c",
    "pr_head": "7b440974016c2b4ad164db79649a919317540a20",
    "weaken_head": "5756c732f60d3ac381d61536b984cfd14d39bdb5",
}
BY_NAME = {entry.name: entry for entry in EXPECTED}


@pytest.fixture(scope="module")
def repo(tmp_path_factory: pytest.TempPathFactory) -> PrRepository:
    return build_pr_repository(tmp_path_factory.mktemp("pr") / "repo")


def show(repo: PrRepository, commit: str, path: str) -> str:
    return git(repo.path, "show", f"{commit}:{path}") + "\n"


def fingerprint(entry: Expected, path: str, source: str) -> str:
    return fingerprint_code(
        rule_id=entry.rule_id,
        tool="bandit",
        path=path,
        source=source,
        start_line=line_of(source, entry.needle),
    )


def test_history_is_deterministic_and_shas_are_pinned(repo: PrRepository, tmp_path: Path) -> None:
    again = build_pr_repository(tmp_path / "again")
    for name, sha in PINNED.items():
        assert getattr(repo, name) == getattr(again, name) == sha


def test_topology_is_one_base_with_main_and_two_stacked_prs(repo: PrRepository) -> None:
    assert git(repo.path, "rev-parse", "main") == repo.main_head
    assert git(repo.path, "rev-parse", "pr/findings") == repo.pr_head
    assert git(repo.path, "rev-parse", "pr/weaken-gate") == repo.weaken_head
    assert git(repo.path, "merge-base", "main", "pr/findings") == repo.base
    assert git(repo.path, "rev-parse", f"{repo.main_head}^") == repo.base
    assert git(repo.path, "rev-parse", f"{repo.pr_head}^") == repo.base
    assert git(repo.path, "rev-parse", f"{repo.weaken_head}^") == repo.pr_head
    assert git(repo.path, "status", "--porcelain") == ""


def test_trees_match_the_declared_content(repo: PrRepository) -> None:
    for commit, tree in ((repo.base, BASE_TREE), (repo.pr_head, PR_TREE)):
        listed = set(git(repo.path, "ls-tree", "-r", "--name-only", commit).splitlines())
        assert listed == set(tree)


def test_each_state_is_covered_once_and_located(repo: PrRepository) -> None:
    assert sorted(BY_NAME) == ["existing", "moved", "new", "renamed", "resolved"]
    for entry in EXPECTED:
        for commit, path in ((repo.base, entry.base_path), (repo.pr_head, entry.pr_path)):
            if path is not None:
                assert line_of(show(repo, commit, path), entry.needle) >= 1
    assert (BY_NAME["new"].base_path, BY_NAME["resolved"].pr_path) == (None, None)


def test_new_problem_is_absent_from_the_base_and_resolved_one_from_the_pr(
    repo: PrRepository,
) -> None:
    new, resolved = BY_NAME["new"], BY_NAME["resolved"]
    assert new.pr_path not in BASE_TREE
    assert all(new.needle not in text for text in BASE_TREE.values())
    assert resolved.base_path is not None
    assert resolved.needle not in show(repo, repo.pr_head, resolved.base_path)


def test_unchanged_problem_keeps_line_and_fingerprint(repo: PrRepository) -> None:
    entry = BY_NAME["existing"]
    assert entry.base_path is not None
    base = show(repo, repo.base, entry.base_path)
    assert base == show(repo, repo.pr_head, entry.base_path)


def test_moved_problem_changes_line_but_not_fingerprint(repo: PrRepository) -> None:
    entry = BY_NAME["moved"]
    assert entry.base_path is not None and not entry.renamed
    base = show(repo, repo.base, entry.base_path)
    head = show(repo, repo.pr_head, entry.base_path)
    assert line_of(base, entry.needle) != line_of(head, entry.needle)
    assert fingerprint(entry, entry.base_path, base) == fingerprint(entry, entry.base_path, head)


def test_renamed_file_changes_fingerprint_but_not_the_pathless_key(repo: PrRepository) -> None:
    """ADR-0025: stessa regola e stesso hash del contesto, percorso diverso."""
    entry = BY_NAME["renamed"]
    assert entry.renamed and entry.base_path is not None and entry.pr_path is not None
    base = show(repo, repo.base, entry.base_path)
    head = show(repo, repo.pr_head, entry.pr_path)
    assert base == head
    assert entry.base_path not in PR_TREE
    line = line_of(base, entry.needle)
    assert context_hash(base, line) == context_hash(head, line)
    assert fingerprint(entry, entry.base_path, base) != fingerprint(entry, entry.pr_path, head)


def test_no_two_cases_share_the_pathless_key(repo: PrRepository) -> None:
    """Altrimenti il secondo passaggio di ADR-0025 potrebbe accoppiare i casi sbagliati."""
    keys = []
    for entry in EXPECTED:
        commit, path = (
            (repo.base, entry.base_path) if entry.base_path else (repo.pr_head, entry.pr_path)
        )
        assert path is not None
        source = show(repo, commit, path)
        keys.append((entry.rule_id, context_hash(source, line_of(source, entry.needle))))
    assert len(keys) == len(set(keys))


def test_weakening_pr_changes_only_the_configuration(repo: PrRepository) -> None:
    changed = git(repo.path, "diff", "--name-only", repo.pr_head, repo.weaken_head)
    assert changed == CONFIG_PATH
    assert show(repo, repo.pr_head, CONFIG_PATH) == BASE_CONFIG
    assert show(repo, repo.weaken_head, CONFIG_PATH) == WEAKENED_CONFIG


def test_both_configurations_are_valid_and_the_second_is_weaker() -> None:
    validator = Draft202012Validator(json.loads(CONFIG_SCHEMA.read_text(encoding="utf-8")))
    base, weak = yaml.safe_load(BASE_CONFIG), yaml.safe_load(WEAKENED_CONFIG)
    for config in (base, weak):
        assert [e.message for e in validator.iter_errors(config)] == []
    assert set(weak["gate"]["block_on"]) < set(base["gate"]["block_on"])
    assert weak["plugins"]["disable"] == ["bandit"]
    assert weak["paths"]["exclude"] == [BY_NAME["new"].pr_path]


def test_main_moved_on_without_touching_the_code(repo: PrRepository) -> None:
    """Una baseline di `main_head` ha un commit diverso da `base`, ma gli stessi finding."""
    assert repo.main_head != repo.base
    assert git(repo.path, "diff", "--name-only", repo.base, repo.main_head) == "README.md"


def test_export_gives_a_detached_clone_of_the_commit(repo: PrRepository, tmp_path: Path) -> None:
    clone = export(repo, repo.base, tmp_path / "base")
    assert git(clone, "rev-parse", "HEAD") == repo.base
    assert (clone / "app/legacy_client.py").is_file() and not (clone / "app/new.py").exists()
    assert git(repo.path, "rev-parse", "--abbrev-ref", "HEAD") == "pr/findings"
