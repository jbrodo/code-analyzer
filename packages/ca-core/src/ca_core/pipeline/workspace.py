"""Passo `prepare_workspace` (K-15, ADR-0002): rilevamento dei linguaggi su un percorso locale.

Nessun clone né accesso diretto al disco: tutto passa da `SourceReader.list_files`. Ingresso e
uscita sono modelli serializzabili, quindi il passo è idempotente e invocabile come activity.

Linguaggi riportati con i nomi dei manifest: `python`, `javascript`, `typescript` (JS e TS
sono distinti, la corrispondenza con i plugin è di `run_plugins`). Il rilevamento usa
estensioni e file indicatori, ignorando i percorsi esclusi (ADR-0014): senza, `node_modules`
farebbe risultare JavaScript ogni progetto. `languages` del file di configurazione si
aggiungono ai rilevati (più scansione, non meno).
"""

import re
from pathlib import PurePosixPath

from pydantic import BaseModel, ConfigDict, Field

from ca_core.pipeline.exclusions import effective_exclusions, is_excluded
from ca_core.ports import SourceError, SourceReader

_EXTENSIONS = {
    "python": {".py", ".pyi"},
    "javascript": {".js", ".jsx", ".mjs", ".cjs"},
    "typescript": {".ts", ".tsx", ".mts", ".cts"},
}
_MARKERS = {
    "python": {"pyproject.toml", "setup.py", "setup.cfg", "pipfile", "poetry.lock", "uv.lock"},
    "javascript": {"package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml"},
    "typescript": {"tsconfig.json"},
}
_REMOTE = re.compile(r"^(?:[A-Za-z][A-Za-z0-9+.-]*://|[\w.-]+@[\w.-]+:)")


class WorkspaceError(Exception):
    """Percorso non utilizzabile come workspace locale."""


class _Frozen(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class PrepareWorkspaceRequest(_Frozen):
    path: str = Field(min_length=1)  # directory locale; un URL non è ammesso
    declared_languages: list[str] = Field(default_factory=list)  # `languages` della config
    exclude: list[str] = Field(default_factory=list)  # `paths.exclude`


class Workspace(_Frozen):
    path: str
    detected_languages: list[str]
    languages: list[str]  # rilevati più dichiarati, ordinati
    file_count: int  # file regolari non esclusi


def _languages_of(files: list[str]) -> set[str]:
    found: set[str] = set()
    for file in files:
        name = PurePosixPath(file).name.lower()
        suffix = PurePosixPath(file).suffix.lower()
        for language in _EXTENSIONS:
            if suffix in _EXTENSIONS[language] or name in _MARKERS[language]:
                found.add(language)
    return found


def prepare_workspace(request: PrepareWorkspaceRequest, reader: SourceReader) -> Workspace:
    if _REMOTE.match(request.path):
        raise WorkspaceError("solo percorsi locali: nessun clone in Fase 1")
    try:
        listed = reader.list_files(request.path)
    except SourceError as exc:
        raise WorkspaceError("workspace non leggibile") from exc
    patterns = effective_exclusions(request.exclude)
    files = [f for f in listed if not is_excluded(f, patterns)]
    detected = sorted(_languages_of(files))
    return Workspace(
        path=request.path,
        detected_languages=detected,
        languages=sorted(set(detected) | set(request.declared_languages)),
        file_count=len(files),
    )
