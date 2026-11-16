"""Costruttore di un repository con un branch base e due PR (F-06, ADR-0008, 0014, 0025).

Come per `secrets_history`, un `.git` annidato non e' versionabile: la storia si genera a ogni
test in una cartella temporanea, con SHA stabili perche' autore, date e contenuti sono fissi.

Storia:

    base ---- main_head                 (main: il secondo commit non tocca il codice)
       \\
        pr_head ---- weaken_head        (pr/findings, poi pr/weaken-gate)

Rispetto a `base`, `pr_head` contiene un finding per ciascuno stato di ADR-0025: nuovo, esistente,
esistente spostato di riga, esistente in un file rinominato, risolto. `weaken_head` aggiunge solo
una modifica a `.code-analyzer.yml` che indebolisce il gate. `main_head` serve alla baseline di
un commit diverso da quello passato con `--base`.

Il codice generato e' insicuro di proposito e non va eseguito. Ogni problema e' una regola di
bandit che non dipende da un `import`, cosi' nessun file porta finding in piu' di quelli elencati.
"""

import subprocess
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from secrets_history import AUTHOR, _git_env, git

State = Literal["new", "existing", "resolved"]

CONFIG_PATH = ".code-analyzer.yml"
BASE_CONFIG = """\
version: 1
gate:
  mode: new-findings-only
  block_on: [critico, alto]
"""
# Tre modi di indebolire il gate dalla PR: soglia piu' alta, plugin spento, file nuovo escluso.
WEAKENED_CONFIG = """\
version: 1
paths:
  exclude: ["app/new.py"]
plugins:
  disable: [bandit]
gate:
  mode: new-findings-only
  block_on: [critico]
"""

EXISTING = """\
import hashlib


def digest(value: bytes) -> str:
    return hashlib.md5(value).hexdigest()
"""
MOVED_BASE = """\
def compute(expression: str) -> object:
    return eval(expression)
"""
# Righe aggiunte sopra, non adiacenti al problema: stesso contesto, stessa impronta, riga diversa.
MOVED_PR = """\
LIMIT = 1024
RETRIES = 3


def compute(expression: str) -> object:
    return eval(expression)
"""
RESOLVED_BASE = """\
import yaml


def parse(text: str) -> object:
    return yaml.load(text)
"""
RESOLVED_PR = """\
import yaml


def parse(text: str) -> object:
    return yaml.safe_load(text)
"""
RENAMED = """\
import requests


def fetch(url: str) -> bytes:
    return requests.get(url, verify=False).content
"""
NEW = """\
def run(code: str) -> None:
    exec(code)
"""

BASE_TREE: Mapping[str, str] = {
    CONFIG_PATH: BASE_CONFIG,
    "README.md": "# Fixture F-06\n",
    "app/__init__.py": "",
    "app/existing.py": EXISTING,
    "app/moved.py": MOVED_BASE,
    "app/resolved.py": RESOLVED_BASE,
    "app/legacy_client.py": RENAMED,
}
PR_TREE: Mapping[str, str] = {
    **{path: text for path, text in BASE_TREE.items() if path != "app/legacy_client.py"},
    "app/moved.py": MOVED_PR,
    "app/resolved.py": RESOLVED_PR,
    "app/client.py": RENAMED,
    "app/new.py": NEW,
}


@dataclass(frozen=True)
class Expected:
    """Un problema noto e il suo stato in `pr_head` rispetto a `base` (ADR-0025)."""

    name: str
    state: State
    rule_id: str  # regola di bandit
    needle: str  # testo che individua la riga del problema
    base_path: str | None  # None: assente in `base`
    pr_path: str | None  # None: assente in `pr_head`

    @property
    def renamed(self) -> bool:
        return None not in (self.base_path, self.pr_path) and self.base_path != self.pr_path


EXPECTED = (
    Expected("new", "new", "B102", "exec(code)", None, "app/new.py"),
    Expected("existing", "existing", "B324", "hashlib.md5(", "app/existing.py", "app/existing.py"),
    Expected("moved", "existing", "B307", "eval(expression)", "app/moved.py", "app/moved.py"),
    Expected(
        "renamed", "existing", "B501", "verify=False", "app/legacy_client.py", "app/client.py"
    ),
    Expected("resolved", "resolved", "B506", "yaml.load(text)", "app/resolved.py", None),
)

DATES = {
    "base": "2026-02-02T09:00:00+00:00",
    "pr": "2026-02-03T09:00:00+00:00",
    "weaken": "2026-02-03T12:00:00+00:00",
    "main": "2026-02-04T09:00:00+00:00",
}


@dataclass(frozen=True)
class PrRepository:
    path: Path
    base: str  # commit da passare a `--base`
    main_head: str  # commit successivo su main: una baseline fatta qui ha il commit sbagliato
    pr_head: str
    weaken_head: str


def line_of(text: str, needle: str) -> int:
    """Numero (da 1) dell'unica riga che contiene `needle`."""
    hits = [number for number, line in enumerate(text.splitlines(), 1) if needle in line]
    if len(hits) != 1:
        raise ValueError(f"{needle!r}: attesa una riga, trovate {len(hits)}")
    return hits[0]


def _write_tree(repo: Path, tree: Mapping[str, str]) -> None:
    for tracked in git(repo, "ls-files").splitlines():
        (repo / tracked).unlink()
    for path, text in tree.items():
        target = repo / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text, encoding="utf-8", newline="\n")


def _commit(repo: Path, env: Mapping[str, str], message: str, date: str) -> str:
    git(repo, "add", "-A", env=env)
    commit_env = {**env, "GIT_AUTHOR_DATE": date, "GIT_COMMITTER_DATE": date}
    git(
        repo,
        "-c", "commit.gpgsign=false",
        "-c", "core.autocrlf=false",
        "commit", "-q", "--no-verify", "-m", message,
        env=commit_env,
    )  # fmt: skip
    return git(repo, "rev-parse", "HEAD", env=env)


def build_pr_repository(dest: Path) -> PrRepository:
    """Crea il repository in `dest` (cartella inesistente o vuota). Resta su `pr/findings`."""
    dest.mkdir(parents=True, exist_ok=True)
    env = {
        **_git_env(dest.parent),
        "GIT_AUTHOR_NAME": AUTHOR[0],
        "GIT_AUTHOR_EMAIL": AUTHOR[1],
        "GIT_COMMITTER_NAME": AUTHOR[0],
        "GIT_COMMITTER_EMAIL": AUTHOR[1],
    }
    git(dest, "init", "-q", "-b", "main", env=env)

    _write_tree(dest, BASE_TREE)
    base = _commit(dest, env, "chore: initial import", DATES["base"])

    git(dest, "checkout", "-q", "-b", "pr/findings", env=env)
    _write_tree(dest, PR_TREE)
    pr_head = _commit(dest, env, "feat: runner, client rename, safe yaml", DATES["pr"])

    git(dest, "checkout", "-q", "-b", "pr/weaken-gate", env=env)
    (dest / CONFIG_PATH).write_text(WEAKENED_CONFIG, encoding="utf-8", newline="\n")
    weaken_head = _commit(dest, env, "chore: relax the analyzer gate", DATES["weaken"])

    git(dest, "checkout", "-q", "main", env=env)
    (dest / "README.md").write_text("# Fixture F-06\n\nNote.\n", encoding="utf-8", newline="\n")
    main_head = _commit(dest, env, "docs: readme note", DATES["main"])

    git(dest, "checkout", "-q", "pr/findings", env=env)
    return PrRepository(dest, base, main_head, pr_head, weaken_head)


def export(repo: PrRepository, commit: str, dest: Path) -> Path:
    """Clone separato fermo su `commit`: la directory da passare a `scan`."""
    subprocess.run(
        ["git", "clone", "-q", "--no-checkout", f"file://{repo.path}", str(dest)],
        env=_git_env(dest.parent),
        capture_output=True,
        check=True,
    )
    git(dest, "checkout", "-q", "--detach", commit, env=_git_env(dest.parent))
    return dest
