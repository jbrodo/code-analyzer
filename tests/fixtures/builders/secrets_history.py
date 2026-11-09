"""Costruttore della storia git con segreti finti (F-04, ADR-0012).

Un `.git` annidato non e' versionabile: la storia si genera a ogni test in una cartella temporanea.
Gli SHA sono stabili perche' autore, data, messaggi e contenuto sono fissi.

I segreti finti non esistono nel repository in forma completa. Il costruttore li compone a runtime
da un seme fisso: prefisso del servizio (scritto a pezzi), marcatore `FAKE` e corpo pseudo-casuale
riproducibile. Il valore compare solo nella cartella temporanea, mai in un file committabile, e
non e' una credenziale: nessun servizio lo ha emesso.
"""

import hashlib
import os
import random
import shutil
import string
import subprocess
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path

REPO_FIXTURE = Path(__file__).resolve().parents[1] / "repos" / "secrets-history"
TEMPLATES = REPO_FIXTURE / "template"
SEED = "code-analyzer/fixtures/secrets-history/v1"
MARKER = "FAKE"
AUTHOR = ("Fixture Author", "fixture@example.invalid")
_ALNUM = string.ascii_letters + string.digits
_PLACEHOLDER = "@@SECRET_{}@@"


@dataclass(frozen=True)
class FakeSecret:
    """Segreto finto: `value` non compare nel repr, per non finire nei messaggi di errore."""

    name: str
    rule_id: str  # regola gitleaks che deve riconoscerlo
    value: str = field(repr=False)

    @property
    def sha256(self) -> str:
        return hashlib.sha256(self.value.encode()).hexdigest()


def _body(rng: random.Random, length: int) -> str:
    return MARKER + "".join(rng.choice(_ALNUM) for _ in range(length - len(MARKER)))


def fake_secrets(seed: str = SEED) -> dict[str, FakeSecret]:
    """Valori deterministici per un seme; forma completa solo in memoria."""
    rng = random.Random(seed)
    # prefissi spezzati: nemmeno il sorgente contiene il pattern di un servizio
    github_prefix = "gh" + "p" + "_"
    gitlab_prefix = "gl" + "pat" + "-"
    return {
        "PAT": FakeSecret("PAT", "github-pat", github_prefix + _body(rng, 36)),
        "GITLAB": FakeSecret("GITLAB", "gitlab-pat", gitlab_prefix + _body(rng, 20)),
    }


@dataclass(frozen=True)
class Step:
    message: str
    date: str  # ISO 8601 fissa
    write: Mapping[str, str]  # destinazione -> modello in `template/`
    remove: tuple[str, ...] = ()


HISTORY = (
    Step(
        "chore: initial import",
        "2026-01-05T09:00:00+00:00",
        {"README.md": "README.md", "app/settings.py": "app/settings.py"},
    ),
    Step("feat: deploy settings", "2026-01-06T09:00:00+00:00", {"deploy/.env": "deploy/.env"}),
    Step(
        "refactor: settings read the environment",
        "2026-01-07T09:00:00+00:00",
        {"app/settings.py": "app/settings_v2.py"},
    ),
    Step(
        "fix: drop the gitlab token from the tree",
        "2026-01-08T09:00:00+00:00",
        {"app/settings.py": "app/settings_final.py"},
        remove=("deploy/.env",),
    ),
)

# Dove ci si aspetta ciascun segreto: (nome, percorso, indice del commit in HISTORY).
EXPECTED_HITS = (
    ("PAT", "app/settings.py", 0),
    ("GITLAB", "deploy/.env", 1),
    ("PAT", "app/settings.py", 2),
)


def _git_env(home: Path) -> dict[str, str]:
    """Ambiente isolato da configurazione utente e di sistema."""
    return {
        "PATH": os.environ["PATH"],
        "HOME": str(home),
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_CONFIG_NOSYSTEM": "1",
        "LC_ALL": "C",
    }


def git(repo: Path, *args: str, env: Mapping[str, str] | None = None) -> str:
    result = subprocess.run(
        ["git", "-C", str(repo), *args],
        env=dict(env) if env is not None else _git_env(repo.parent),
        capture_output=True,
        text=True,
        check=True,
    )
    return result.stdout.strip()


def _render(template: str, secrets: Mapping[str, FakeSecret]) -> str:
    text = (TEMPLATES / template).read_text(encoding="utf-8")
    for name, secret in secrets.items():
        text = text.replace(_PLACEHOLDER.format(name), secret.value)
    assert "@@SECRET_" not in text, f"segnaposto non risolto in {template}"
    return text


@dataclass(frozen=True)
class SecretsHistory:
    path: Path
    commits: tuple[str, ...]  # SHA nell'ordine di HISTORY
    secrets: Mapping[str, FakeSecret] = field(repr=False)


def build_history(dest: Path, seed: str = SEED) -> SecretsHistory:
    """Crea la storia in `dest` (cartella inesistente o vuota). Gli SHA dipendono solo dal seme."""
    dest.mkdir(parents=True, exist_ok=True)
    secrets = fake_secrets(seed)
    env = {
        **_git_env(dest.parent),
        "GIT_AUTHOR_NAME": AUTHOR[0],
        "GIT_AUTHOR_EMAIL": AUTHOR[1],
        "GIT_COMMITTER_NAME": AUTHOR[0],
        "GIT_COMMITTER_EMAIL": AUTHOR[1],
    }
    git(dest, "init", "-q", "-b", "main", env=env)
    shas: list[str] = []
    for step in HISTORY:
        for target, template in step.write.items():
            out = dest / target
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_text(_render(template, secrets), encoding="utf-8", newline="\n")
        for target in step.remove:
            (dest / target).unlink()
        git(dest, "add", "-A", env=env)
        commit_env = {**env, "GIT_AUTHOR_DATE": step.date, "GIT_COMMITTER_DATE": step.date}
        git(
            dest,
            "-c", "commit.gpgsign=false",
            "-c", "core.autocrlf=false",
            "commit", "-q", "--no-verify", "-m", step.message,
            env=commit_env,
        )  # fmt: skip
        shas.append(git(dest, "rev-parse", "HEAD", env=env))
    return SecretsHistory(dest, tuple(shas), secrets)


def shallow_clone(source: Path, dest: Path, depth: int = 1) -> Path:
    """Clone superficiale (`file://`: `--depth` e' ignorato sui percorsi locali semplici)."""
    subprocess.run(
        ["git", "clone", "-q", "--depth", str(depth), "--branch", "main", f"file://{source}",
         str(dest)],
        env=_git_env(dest.parent),
        capture_output=True,
        check=True,
    )  # fmt: skip
    return dest


def clone_full(source: Path, dest: Path) -> Path:
    shutil.copytree(source, dest, symlinks=True)
    return dest


def foreign_owner_env() -> dict[str, str]:
    """Fa credere a git che il repository sia di un altro utente (`dubious ownership`).

    `GIT_TEST_ASSUME_DIFFERENT_OWNER` e' previsto da git per i propri test: permette di provare il
    caso senza privilegi di root. Non cambia il proprietario reale dei file.
    """
    return {"GIT_TEST_ASSUME_DIFFERENT_OWNER": "1"}


def safe_directory_env(path: Path) -> dict[str, str]:
    """Stessa impostazione dell'adattatore di ADR-0012: `safe.directory` via ambiente."""
    return {
        "GIT_CONFIG_COUNT": "1",
        "GIT_CONFIG_KEY_0": "safe.directory",
        "GIT_CONFIG_VALUE_0": str(path),
    }
