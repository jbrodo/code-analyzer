"""R-08: `LocalSourceReader` confinato nella radice. Nessun Docker."""

import os
from pathlib import Path

import pytest

from ca_core.ports import SourceError, SourceReader, SourceTooLarge
from ca_plugins.source import LocalSourceReader


@pytest.fixture
def ws(tmp_path: Path) -> Path:
    root = tmp_path / "ws"
    (root / "a" / "b").mkdir(parents=True)
    (root / "a" / "b" / "x.py").write_bytes(b"print(1)\n")
    (root / "top.txt").write_bytes(b"1234567890")
    (tmp_path / "secret").write_bytes(b"s3cret")
    return root


def test_is_a_source_reader() -> None:
    assert isinstance(LocalSourceReader(), SourceReader)


def test_lists_regular_files_recursively_and_skips_the_rest(ws: Path) -> None:
    (ws / "inside").symlink_to("top.txt")
    (ws / "dirlink").symlink_to("a")
    (ws / "out").symlink_to("../secret")
    os.mkfifo(ws / "fifo")
    assert LocalSourceReader().list_files(str(ws)) == ["a/b/x.py", "top.txt"]


def test_reads_nested_file(ws: Path) -> None:
    assert LocalSourceReader().read_file(str(ws), "a/b/x.py", 100) == b"print(1)\n"


def test_limit_is_inclusive_and_over_limit_is_source_too_large(ws: Path) -> None:
    reader = LocalSourceReader()
    assert reader.read_file(str(ws), "top.txt", 10) == b"1234567890"
    with pytest.raises(SourceTooLarge):
        reader.read_file(str(ws), "top.txt", 9)


@pytest.mark.parametrize(
    "path",
    ["../secret", "a/../../secret", "/etc/passwd", "", ".", "..", "a//b", "./top.txt", "a\x00b"],
)
def test_dotdot_absolute_and_odd_paths_are_refused(ws: Path, path: str) -> None:
    with pytest.raises(SourceError):
        LocalSourceReader().read_file(str(ws), path, 100)


def test_every_symlink_is_refused_even_inside_the_root(ws: Path) -> None:
    (ws / "inside").symlink_to("top.txt")
    (ws / "outside").symlink_to("../secret")
    (ws / "abs").symlink_to("/etc/passwd")
    (ws / "dirlink").symlink_to("a")
    (ws / "outdir").symlink_to(ws.parent)
    for path in ("inside", "outside", "abs", "dirlink/b/x.py", "outdir/secret"):
        with pytest.raises(SourceError):
            LocalSourceReader().read_file(str(ws), path, 100)


def test_not_regular_missing_and_directory_are_refused_without_blocking(ws: Path) -> None:
    os.mkfifo(ws / "fifo")
    for path in ("fifo", "a", "a/b", "missing", "a/missing/x", "top.txt/x"):
        with pytest.raises(SourceError):
            LocalSourceReader().read_file(str(ws), path, 100)


def test_root_must_be_a_real_directory(ws: Path, tmp_path: Path) -> None:
    (tmp_path / "link").symlink_to(ws)
    for root in (str(tmp_path / "link"), str(tmp_path / "nope"), str(ws / "top.txt")):
        with pytest.raises(SourceError):
            LocalSourceReader().list_files(root)
        with pytest.raises(SourceError):
            LocalSourceReader().read_file(root, "x", 1)


def test_directory_swapped_for_symlink_after_listing_cannot_escape(ws: Path) -> None:
    reader = LocalSourceReader()
    assert "a/b/x.py" in reader.list_files(str(ws))
    for child in list((ws / "a" / "b").iterdir()):
        child.unlink()
    (ws / "a" / "b").rmdir()
    (ws / "a" / "b").symlink_to(ws.parent)  # TOCTOU simulato: ora `b` esce dalla radice
    (ws.parent / "x.py").write_bytes(b"outside")
    with pytest.raises(SourceError):
        reader.read_file(str(ws), "a/b/x.py", 100)


def test_file_that_grows_after_fstat_is_not_read_past_the_limit(
    ws: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import ca_plugins.source as source

    real = source._open_regular
    monkeypatch.setattr(source, "_open_regular", lambda d, n, m: (real(d, n, 10**6)[0], 0))
    with pytest.raises(SourceTooLarge):
        LocalSourceReader().read_file(str(ws), "top.txt", 9)


def test_depth_and_file_count_limits_fail_closed(ws: Path) -> None:
    with pytest.raises(SourceError):
        LocalSourceReader(max_depth=1).list_files(str(ws))
    with pytest.raises(SourceError):
        LocalSourceReader(max_files=1).list_files(str(ws))


def test_non_utf8_name_round_trips(ws: Path) -> None:
    raw = os.fsencode(str(ws)) + b"/caf\xe9.py"
    with open(raw, "wb") as f:
        f.write(b"x")
    reader = LocalSourceReader()
    name = next(p for p in reader.list_files(str(ws)) if p.startswith("caf"))
    assert reader.read_file(str(ws), name, 10) == b"x"
