"""K-15: passo `prepare_workspace`."""

import pytest

from ca_core.fakes import InMemorySourceReader
from ca_core.pipeline.workspace import (
    PrepareWorkspaceRequest,
    Workspace,
    WorkspaceError,
    prepare_workspace,
)
from ca_core.ports import SourceError


def reader(*files: str) -> InMemorySourceReader:
    return InMemorySourceReader({"/w": {f: b"" for f in files}})


def run(*files: str, **kv: object) -> Workspace:
    return prepare_workspace(PrepareWorkspaceRequest(path="/w", **kv), reader(*files))  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("files", "expected"),
    [
        (["app/main.py"], ["python"]),
        (["pyproject.toml"], ["python"]),
        (["src/a.ts", "src/b.tsx"], ["typescript"]),
        (["index.js", "lib/x.mjs"], ["javascript"]),
        (["package.json", "tsconfig.json"], ["javascript", "typescript"]),
        (["a.py", "web/b.ts", "web/c.js"], ["javascript", "python", "typescript"]),
        (["README.md", "Makefile"], []),
        (["A.PY"], ["python"]),
    ],
)
def test_detects_languages(files: list[str], expected: list[str]) -> None:
    assert run(*files).detected_languages == expected


def test_excluded_paths_do_not_count() -> None:
    result = run("node_modules/x/index.js", ".venv/lib/a.py", "vendor/v.go", exclude=["vendor"])

    assert (result.detected_languages, result.file_count) == ([], 0)


def test_declared_languages_are_added_not_replaced() -> None:
    result = run("a.py", declared_languages=["typescript"])

    assert (result.detected_languages, result.languages) == (["python"], ["python", "typescript"])


@pytest.mark.parametrize("path", ["https://x/y.git", "git@host:o/r.git", "ssh://h/r", "file:///a"])
def test_remote_paths_are_refused_without_clone(path: str) -> None:
    with pytest.raises(WorkspaceError):
        prepare_workspace(PrepareWorkspaceRequest(path=path), reader("a.py"))


def test_unreadable_workspace_is_a_workspace_error() -> None:
    class Broken:
        def list_files(self, root: str) -> list[str]:
            raise SourceError("no")

        def read_file(self, root: str, path: str, max_bytes: int) -> bytes:
            raise SourceError("no")

    with pytest.raises(WorkspaceError):
        prepare_workspace(PrepareWorkspaceRequest(path="/w"), Broken())


def test_io_is_serializable_and_idempotent() -> None:
    request = PrepareWorkspaceRequest(path="/w", exclude=["x/"], declared_languages=["python"])
    r = reader("a.py", "b.ts")

    first = prepare_workspace(
        PrepareWorkspaceRequest.model_validate_json(request.model_dump_json()), r
    )

    assert prepare_workspace(request, r) == first
    assert Workspace.model_validate_json(first.model_dump_json()) == first
