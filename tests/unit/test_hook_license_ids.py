"""Hook `license-ids`: righe aggiunte con un identificatore di licenza copyleft (AGENTS.md)."""

import importlib.util
from pathlib import Path

import pytest

SOURCE = Path(__file__).resolve().parents[2] / "scripts/hooks/check_license_ids.py"
spec = importlib.util.spec_from_file_location("check_license_ids", SOURCE)
assert spec is not None and spec.loader is not None
hook = importlib.util.module_from_spec(spec)
spec.loader.exec_module(hook)


def diff(path: str, *lines: str, start: int = 10) -> str:
    body = "\n".join(f"+{t}" for t in lines)
    head = f"diff --git a/{path} b/{path}\n--- a/{path}\n+++ b/{path}\n"
    return f"{head}@@ -9,0 +{start},{len(lines)} @@\n{body}\n"


@pytest.mark.parametrize(
    "text",
    ["un repository AGPL", "GPL-3.0-only", "LGPL-2.1-or-later", "GPL", "SSPL", "MPL-2.0", "EUPL"],
)
def test_a_copyleft_identifier_in_an_added_line_is_reported(text: str) -> None:
    assert hook.offending(diff("doc/adr/0099-x.md", "testo", f"Scartato {text}.")) == [
        ("doc/adr/0099-x.md", 11, text.split()[-1])
    ]


@pytest.mark.parametrize(
    "text",
    ["licenza copyleft di rete", "GPLv", "the GPLOT library", "una licenza permissiva", "EPLAN"],
)
def test_words_and_lookalikes_pass(text: str) -> None:
    assert hook.offending(diff("doc/a.md", text)) == []


@pytest.mark.parametrize(
    "path", ["LICENSE", "deploy/docker/cli/licenses/THIRD-PARTY-NOTICES.md",
             "deploy/docker/LICENSES-SBOM.md", "COPYING.LESSER"],
)  # fmt: skip
def test_license_files_are_exempt(path: str) -> None:
    assert hook.offending(diff(path, "GPL-3.0-only")) == []


def test_removed_lines_and_deleted_files_do_not_count() -> None:
    removed = "diff --git a/d.md b/d.md\n--- a/d.md\n+++ b/d.md\n@@ -3 +2,0 @@\n-GPL-3.0-only\n"
    deleted = "diff --git a/d.md b/d.md\n--- a/d.md\n+++ /dev/null\n@@ -1 +0,0 @@\n-GPL\n"
    assert hook.offending(removed) == [] and hook.offending(deleted) == []
