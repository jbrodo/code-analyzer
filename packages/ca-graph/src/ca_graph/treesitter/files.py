"""Elenco e lettura dei file sorgente del workspace (G-02, G-03, S-02).

Solo la libreria standard: questo pacchetto gira nell'immagine di estrazione e non importa
`ca_core` (ADR-0020). Il workspace è un input non fidato: si leggono solo file regolari, senza
seguire collegamenti simbolici (`lstat`, `O_NOFOLLOW`, `O_NONBLOCK`), sotto un tetto di dimensione
e di numero. Un file oltre il tetto di dimensione si conta e non fa fallire l'estrazione.
"""

import os
import re
import stat
from collections.abc import Iterator
from dataclasses import dataclass, field

MAX_FILE_BYTES = 2 * 1024 * 1024  # V-07: il file più grande dei pilota è 972 KB
MAX_FILES = 200_000  # come `MAX_MODULES` di `graph`
_CONTROL = re.compile(r"[\x00-\x1f\x7f]")

SKIP_DIRS = frozenset(
    {
        ".git",
        "node_modules",
        ".venv",
        "venv",
        "site-packages",
        "__pycache__",
        ".tox",
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
        "dist",
        "build",
        ".terraform",
    }
)

# Estensione -> linguaggio del contratto. `.pyi` e `.d.ts` sono dichiarazioni, non moduli.
LANGUAGES = {
    ".py": "python",
    ".js": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".jsx": "javascript",
    ".ts": "typescript",
    ".mts": "typescript",
    ".cts": "typescript",
    ".tsx": "tsx",
}
DECLARATION_SUFFIXES = (".d.ts", ".d.mts", ".d.cts")
TEST_DIRS = frozenset({"test", "tests", "testing", "__tests__", "__mocks__"})


class LimitExceeded(ValueError):
    """Un limite globale (numero di file) è superato: l'estrazione fallisce, non si tronca."""


@dataclass
class Listing:
    files: list[str] = field(default_factory=list)  # percorsi relativi POSIX, ordinati
    skipped_size: int = 0
    skipped_name: int = 0  # nomi con caratteri di controllo: il contratto li rifiuta (S-02)


def language_of(name: str) -> str | None:
    lowered = name.lower()
    if lowered.endswith(DECLARATION_SUFFIXES):
        return None
    for suffix, language in LANGUAGES.items():
        if lowered.endswith(suffix):
            return language
    return None


def is_test_path(path: str) -> bool:
    """File di test dal percorso relativo, con regole fisse (stesse idee di bandit, P-07)."""
    *dirs, name = path.casefold().split("/")
    stem = name.rsplit(".", 1)[0]
    return (
        not TEST_DIRS.isdisjoint(dirs)
        or name == "conftest.py"
        or name.startswith("test_")
        or stem.endswith(("_test", ".test", ".spec"))
    )


def _walk(root: str) -> Iterator[tuple[str, list[str]]]:
    for current, dirs, files in os.walk(root, followlinks=False):
        dirs[:] = sorted(d for d in dirs if d not in SKIP_DIRS)
        yield current, sorted(files)


def list_sources(root: str, max_files: int | None = None) -> Listing:
    max_files = MAX_FILES if max_files is None else max_files
    listing = Listing()
    for current, names in _walk(root):
        for name in names:
            if language_of(name) is None:
                continue
            path = os.path.join(current, name)
            relative = os.path.relpath(path, root).replace(os.sep, "/")
            if _CONTROL.search(relative):
                listing.skipped_name += 1
                continue
            try:
                info = os.lstat(path)
            except OSError:
                continue
            if not stat.S_ISREG(info.st_mode):
                continue
            if info.st_size > MAX_FILE_BYTES:
                listing.skipped_size += 1
                continue
            if len(listing.files) >= max_files:
                raise LimitExceeded("troppi file sorgente")
            listing.files.append(relative)
    listing.files.sort()
    return listing


def read_file(root: str, relative: str, limit: int = MAX_FILE_BYTES) -> bytes | None:
    """Byte del file, `None` se non si può leggere in sicurezza (collegamento, non regolare...)."""
    path = os.path.join(root, relative)
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except OSError:
        return None
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_size > limit:
            return None
        with os.fdopen(fd, "rb", closefd=False) as handle:
            data = handle.read(limit + 1)
    except OSError:
        return None
    finally:
        os.close(fd)
    return data if len(data) <= limit else None


CONFIG_NAMES = frozenset(
    {"package.json", "tsconfig.json", "jsconfig.json", "pyproject.toml", "setup.cfg"}
)
MAX_CONFIG_BYTES = 256 * 1024
MAX_CONFIGS = 5_000


def list_configs(root: str) -> list[str]:
    """File di configurazione del workspace (JS e Python): dati non fidati, mai eseguiti."""
    found: list[str] = []
    for current, names in _walk(root):
        for name in names:
            if name not in CONFIG_NAMES:
                continue
            path = os.path.join(current, name)
            try:
                regular = stat.S_ISREG(os.lstat(path).st_mode)
            except OSError:
                continue
            if regular and len(found) < MAX_CONFIGS:
                found.append(os.path.relpath(path, root).replace(os.sep, "/"))
    return sorted(found)
