"""T-03: i lettori dell'host (`OutputReader` per `/out`, `LocalSourceReader` per il workspace) di
fronte a contenuto ostile. Nessun Docker: usano il file system locale e girano sempre.

Il segreto dei test e' falso e riconoscibile: `CA-FAKE-OUTSIDE-SECRET`, scritto fuori dalla radice
letta. Un lettore che lo restituisce, in qualunque scenario, ha attraversato il confine.
"""

import os
import socket
import threading
import tracemalloc
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from ca_core.ports import SourceError, SourceTooLarge
from ca_plugins.runner import OutputReader
from ca_plugins.source import LocalSourceReader

OUTSIDE = b"CA-FAKE-OUTSIDE-SECRET"
MIB = 1 << 20

READERS: list[Callable[[], Any]] = [OutputReader, LocalSourceReader]
reader_ids = ["out-reader", "workspace-reader"]
pytestmark = pytest.mark.skipif(os.geteuid() == 0, reason="i permessi 000 non valgono per root")


@pytest.fixture
def outside(tmp_path: Path) -> Path:
    """Directory FUORI dalla radice, con un file segreto finto."""
    d = tmp_path / "outside"
    d.mkdir()
    (d / "secret.txt").write_bytes(OUTSIDE)
    return d


@pytest.fixture
def root(tmp_path: Path) -> Path:
    r = tmp_path / "root"
    r.mkdir()
    (r / "ok.txt").write_bytes(b"inside")
    return r


def within(seconds: float, action: Callable[[], Any]) -> Any:
    """Esegue `action` in un thread: se non finisce in `seconds` il lettore e' bloccato."""
    box: dict[str, Any] = {}

    def target() -> None:
        try:
            box["value"] = action()
        except BaseException as exc:  # noqa: BLE001 - lo si rilancia nel thread principale
            box["error"] = exc

    thread = threading.Thread(target=target, daemon=True)
    thread.start()
    thread.join(seconds)
    assert not thread.is_alive(), "il lettore si e' bloccato (FIFO o dispositivo?)"
    if "error" in box:
        raise box["error"]
    return box.get("value")


# --- percorsi e URI ----------------------------------------------------------------------------

BAD_PATHS = [
    "..",
    "../outside/secret.txt",
    "../../etc/passwd",
    "/etc/passwd",
    "/abs/path",
    "file:///etc/passwd",
    "a/../ok.txt",
    "./ok.txt",
    "",
    ".",
    "ok.txt\x00.png",
]


@pytest.mark.parametrize("factory", READERS, ids=reader_ids)
@pytest.mark.parametrize("path", BAD_PATHS, ids=lambda p: repr(p)[:30])
def test_paths_that_escape_or_are_not_relative_are_rejected(
    factory: Callable[[], Any], root: Path, outside: Path, path: str
) -> None:
    with pytest.raises(SourceError):
        factory().read_file(str(root), path, MIB)


def test_workspace_reader_rejects_nested_escapes(root: Path, outside: Path) -> None:
    (root / "d").mkdir()
    for path in ("d/../ok.txt", "d/../../outside/secret.txt", "d//ok.txt", "d/./x"):
        with pytest.raises(SourceError):
            LocalSourceReader().read_file(str(root), path, MIB)


def test_out_reader_accepts_only_first_level_names(root: Path) -> None:
    (root / "d").mkdir()
    (root / "d" / "f").write_bytes(b"x")
    with pytest.raises(SourceError):
        OutputReader().read_file(str(root), "d/f", MIB)
    assert OutputReader().list_files(str(root)) == ["ok.txt"]  # la sottodirectory non e' elencata


# --- symlink -----------------------------------------------------------------------------------


@pytest.mark.parametrize("factory", READERS, ids=reader_ids)
def test_symlink_to_an_outside_file_is_not_followed(
    factory: Callable[[], Any], root: Path, outside: Path
) -> None:
    (root / "link").symlink_to(outside / "secret.txt")
    (root / "abs-link").symlink_to("/etc/passwd")
    reader = factory()
    for name in ("link", "abs-link"):
        with pytest.raises(SourceError):
            reader.read_file(str(root), name, MIB)
    assert "link" not in reader.list_files(str(root))
    assert "abs-link" not in reader.list_files(str(root))


@pytest.mark.parametrize("factory", READERS, ids=reader_ids)
def test_symlink_staying_inside_the_root_is_not_followed_either(
    factory: Callable[[], Any], root: Path
) -> None:
    (root / "inner").symlink_to("ok.txt")
    with pytest.raises(SourceError):
        factory().read_file(str(root), "inner", MIB)


@pytest.mark.parametrize("factory", READERS, ids=reader_ids)
def test_root_that_is_a_symlink_is_refused(
    factory: Callable[[], Any], tmp_path: Path, outside: Path
) -> None:
    link = tmp_path / "rootlink"
    link.symlink_to(outside)
    with pytest.raises(SourceError):
        factory().list_files(str(link))
    with pytest.raises(SourceError):
        factory().read_file(str(link), "secret.txt", MIB)


def test_symlinked_directory_is_neither_listed_nor_traversed(root: Path, outside: Path) -> None:
    (root / "sub").mkdir()
    (root / "sub" / "real.txt").write_bytes(b"real")
    (root / "linkdir").symlink_to(outside)
    reader = LocalSourceReader()
    assert reader.list_files(str(root)) == ["ok.txt", "sub/real.txt"]
    with pytest.raises(SourceError):
        reader.read_file(str(root), "linkdir/secret.txt", MIB)


def test_directory_swapped_for_a_symlink_never_leaks_the_outside_file(
    root: Path, outside: Path
) -> None:
    """Corsa: una directory e' scambiata con un symlink verso l'esterno mentre si legge.

    Il thread ostile alterna `sub` (vera, con `secret.txt` = "inside") e un symlink a `outside`
    (che ha un `secret.txt` con il segreto finto). Ogni lettura deve dare "inside" o un
    `SourceError`: mai il segreto, mai un'eccezione di altro tipo.
    """
    sub = root / "sub"
    sub.mkdir()
    (sub / "secret.txt").write_bytes(b"inside")
    hold = root / "hold"
    stop = threading.Event()

    def swap() -> None:
        while not stop.is_set():
            os.rename(sub, hold)
            os.symlink(outside, sub)
            os.unlink(sub)
            os.rename(hold, sub)

    attacker = threading.Thread(target=swap, daemon=True)
    attacker.start()
    reader = LocalSourceReader()
    seen = {"inside": 0, "refused": 0}
    try:
        for _ in range(4000):
            try:
                data = reader.read_file(str(root), "sub/secret.txt", MIB)
            except SourceError:
                seen["refused"] += 1
                continue
            assert data == b"inside", data
            seen["inside"] += 1
            for name in reader.list_files(str(root)):
                assert name in {"ok.txt", "sub/secret.txt", "hold/secret.txt"}, (
                    name
                )  # hold = la stessa directory vera
    finally:
        stop.set()
        attacker.join(5)
    assert sum(seen.values()) == 4000
    print(f"\nT-03 race: {seen}")  # noqa: T201
    assert seen["inside"] > 0  # la prova ha anche letto davvero, non ha solo rifiutato


# --- file speciali -----------------------------------------------------------------------------


@pytest.mark.parametrize("factory", READERS, ids=reader_ids)
def test_fifo_is_refused_without_blocking(factory: Callable[[], Any], root: Path) -> None:
    os.mkfifo(root / "pipe")
    reader = factory()
    with pytest.raises(SourceError):
        within(5, lambda: reader.read_file(str(root), "pipe", MIB))
    assert "pipe" not in within(5, lambda: reader.list_files(str(root)))


def test_socket_is_not_listed_and_not_read(root: Path) -> None:
    server = socket.socket(socket.AF_UNIX)
    try:
        server.bind(str(root / "sock"))
        assert LocalSourceReader().list_files(str(root)) == ["ok.txt"]
        with pytest.raises(SourceError):
            LocalSourceReader().read_file(str(root), "sock", MIB)
    finally:
        server.close()


@pytest.mark.parametrize("factory", READERS, ids=reader_ids)
def test_device_file_is_refused_not_read_forever(factory: Callable[[], Any]) -> None:
    with pytest.raises(SourceError):
        within(5, lambda: factory().read_file("/dev", "zero", MIB))


@pytest.mark.parametrize("factory", READERS, ids=reader_ids)
def test_directory_where_a_file_is_expected_is_refused(
    factory: Callable[[], Any], root: Path
) -> None:
    (root / "d").mkdir()
    with pytest.raises(SourceError):
        factory().read_file(str(root), "d", MIB)


# --- dimensioni --------------------------------------------------------------------------------


@pytest.mark.parametrize("factory", READERS, ids=reader_ids)
def test_limit_is_inclusive_and_one_more_byte_is_too_large(
    factory: Callable[[], Any], root: Path
) -> None:
    (root / "exact").write_bytes(b"x" * 1000)
    (root / "plus1").write_bytes(b"x" * 1001)
    assert len(factory().read_file(str(root), "exact", 1000)) == 1000
    with pytest.raises(SourceTooLarge):
        factory().read_file(str(root), "plus1", 1000)


@pytest.mark.parametrize("factory", READERS, ids=reader_ids)
def test_huge_sparse_file_is_refused_without_reading_it(
    factory: Callable[[], Any], root: Path
) -> None:
    with (root / "huge.bin").open("wb") as handle:
        handle.truncate(8 << 30)  # 8 GiB apparenti, nessun blocco su disco
    reader = factory()
    tracemalloc.start()
    try:
        with pytest.raises(SourceTooLarge):
            within(10, lambda: reader.read_file(str(root), "huge.bin", MIB))
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert peak < 8 * MIB  # rifiutato dalla dimensione: niente lettura, niente memoria
    assert reader.list_files(str(root)) == ["huge.bin", "ok.txt"]  # elencarlo non lo legge


@pytest.mark.parametrize("factory", READERS, ids=reader_ids)
def test_check_or_read_never_exceeds_limit_plus_one_chunk_of_memory(
    factory: Callable[[], Any], root: Path
) -> None:
    (root / "big.bin").write_bytes(b"\0" * (4 * MIB))
    tracemalloc.start()
    try:
        with pytest.raises(SourceTooLarge):
            factory().read_file(str(root), "big.bin", MIB)
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert peak < 2 * MIB


# --- struttura del workspace -------------------------------------------------------------------


def test_nesting_beyond_the_default_depth_is_refused(root: Path) -> None:
    deep = root
    for _ in range(140):
        deep = deep / "d"
        deep.mkdir()
    with pytest.raises(SourceError):
        LocalSourceReader().list_files(str(root))


def test_too_many_files_is_refused(root: Path) -> None:
    for i in range(11):
        (root / f"f{i}").write_bytes(b"")
    with pytest.raises(SourceError):
        LocalSourceReader(max_files=10).list_files(str(root))


def test_symlink_loop_and_dangling_symlink_do_not_hang_or_fail_the_listing(root: Path) -> None:
    (root / "loop").symlink_to("loop")
    (root / "dangling").symlink_to("/nonexistent/CA-FAKE-OUTSIDE-SECRET")
    assert within(5, lambda: LocalSourceReader().list_files(str(root))) == ["ok.txt"]


def test_unreadable_file_is_listed_but_not_readable(root: Path) -> None:
    (root / "locked.txt").write_bytes(b"x")
    (root / "locked.txt").chmod(0)
    assert "locked.txt" in LocalSourceReader().list_files(str(root))
    with pytest.raises(SourceError):
        LocalSourceReader().read_file(str(root), "locked.txt", MIB)


def test_unreadable_directory_is_silently_omitted_characterization(root: Path) -> None:
    """Osservazione, non requisito: una sottodirectory 000 sparisce dall'elenco senza errore.

    E' il comportamento dichiarato in `source.py` ("omessa"), ma per uno scanner e' un falso
    negativo silenzioso: vedi il report di T-03. Fissa il comportamento attuale.
    """
    (root / "locked").mkdir()
    (root / "locked" / "app.py").write_bytes(b"x")
    (root / "locked").chmod(0)
    try:
        assert LocalSourceReader().list_files(str(root)) == ["ok.txt"]
    finally:
        (root / "locked").chmod(0o755)


def test_directory_replaced_by_a_file_after_listing_is_a_clean_error(root: Path) -> None:
    (root / "d").mkdir()
    (root / "d" / "f").write_bytes(b"x")
    reader = LocalSourceReader()
    assert reader.list_files(str(root)) == ["d/f", "ok.txt"]
    (root / "d" / "f").unlink()
    (root / "d").rmdir()
    (root / "d").write_bytes(b"ora e' un file")
    with pytest.raises(SourceError):
        reader.read_file(str(root), "d/f", MIB)
