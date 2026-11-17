"""B-07: file system e fake in memoria superano la stessa batteria di contratto."""

import io
import os
import stat
import threading
from collections.abc import Callable
from pathlib import Path

import pytest
from store_battery import KEY, run_battery

from ca_api.storage.filesystem import FileSystemArtifactStore, StorageError
from ca_core.fakes import InMemoryArtifactStore
from ca_core.ports import ArtifactConflict, ArtifactNotFound, ArtifactStore, ArtifactTooLarge


def filesystem(tmp_path: Path) -> Callable[[], ArtifactStore]:
    counter = iter(range(10_000))
    return lambda: FileSystemArtifactStore(tmp_path / f"store-{next(counter)}")


@pytest.fixture(params=["memory", "filesystem"])
def factory(request: pytest.FixtureRequest, tmp_path: Path) -> Callable[[], ArtifactStore]:
    return InMemoryArtifactStore if request.param == "memory" else filesystem(tmp_path)


def test_the_contract_battery(factory: Callable[[], ArtifactStore]) -> None:
    for case in run_battery(factory):
        case()


def test_adapters_implement_the_port() -> None:
    assert isinstance(InMemoryArtifactStore(), ArtifactStore)


# --- file system: sicurezza dei percorsi --------------------------------------------------------


@pytest.fixture
def store(tmp_path: Path) -> FileSystemArtifactStore:
    return FileSystemArtifactStore(tmp_path / "root")


def test_files_and_directories_are_private(store: FileSystemArtifactStore, tmp_path: Path) -> None:
    store.put(KEY, io.BytesIO(b"x"), max_bytes=10)
    root = tmp_path / "root"
    assert stat.S_IMODE(root.stat().st_mode) == 0o700
    for path in root.rglob("*"):
        mode = stat.S_IMODE(path.stat().st_mode)
        assert mode == (0o700 if path.is_dir() else 0o600), path


def test_a_root_that_others_can_use_is_an_environment_error(tmp_path: Path) -> None:
    shared = tmp_path / "shared"
    shared.mkdir(mode=0o755)
    shared.chmod(0o755)
    with pytest.raises(StorageError):
        FileSystemArtifactStore(shared)


def test_a_root_that_is_a_symlink_is_refused(tmp_path: Path) -> None:
    real = tmp_path / "real"
    real.mkdir(mode=0o700)
    link = tmp_path / "link"
    link.symlink_to(real)
    with pytest.raises(StorageError):
        FileSystemArtifactStore(link)


def test_a_symlinked_directory_component_does_not_lead_outside(
    store: FileSystemArtifactStore, tmp_path: Path
) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "report").write_bytes(b"secret")
    (tmp_path / "root" / "t_abc123").symlink_to(outside)
    with pytest.raises(ArtifactNotFound):
        store.open("t_abc123/0192f3a2/report")
    with pytest.raises(ArtifactNotFound):
        store.open("t_abc123/report")
    with pytest.raises(OSError):
        store.put("t_abc123/0192f3a2/report", io.BytesIO(b"x"), max_bytes=10)
    assert sorted(p.name for p in outside.iterdir()) == ["report"]  # nulla scritto fuori


def test_a_symlink_in_place_of_the_object_is_not_followed(
    store: FileSystemArtifactStore, tmp_path: Path
) -> None:
    store.put(KEY, io.BytesIO(b"real"), max_bytes=10)
    target = tmp_path / "root" / "t_abc123" / "0192f3a2" / "report"
    victim = tmp_path / "victim"
    victim.write_bytes(b"outside")
    target.unlink()
    target.symlink_to(victim)
    with pytest.raises(ArtifactNotFound):
        store.open(KEY)
    assert not store.exists(KEY)
    with pytest.raises(OSError):
        store.put(KEY, io.BytesIO(b"x"), max_bytes=10)
    assert victim.read_bytes() == b"outside"


def test_a_directory_in_place_of_the_object_is_not_readable_as_one(
    store: FileSystemArtifactStore, tmp_path: Path
) -> None:
    (tmp_path / "root" / "t_abc123" / "0192f3a2" / "report").mkdir(parents=True)
    assert not store.exists(KEY)


def test_no_temporary_file_is_left_after_success_or_failure(
    store: FileSystemArtifactStore, tmp_path: Path
) -> None:
    store.put(KEY, io.BytesIO(b"x"), max_bytes=10)
    with pytest.raises(ArtifactConflict):
        store.put(KEY, io.BytesIO(b"y"), max_bytes=10)
    with pytest.raises(ArtifactTooLarge):
        store.put("t_abc123/0192f3a2/big", io.BytesIO(b"x" * 100), max_bytes=10)
    names = [p.name for p in (tmp_path / "root").rglob("*")]
    assert not any(n.startswith(".tmp-") for n in names)


def test_concurrent_writers_of_the_same_content_all_succeed_and_one_object_remains(
    store: FileSystemArtifactStore, tmp_path: Path
) -> None:
    results: list[object] = []

    def put() -> None:
        results.append(store.put(KEY, io.BytesIO(b"same" * 1000), max_bytes=10_000))

    threads = [threading.Thread(target=put) for _ in range(12)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert len(results) == 12 and len(set(map(str, results))) == 1
    files = [p for p in (tmp_path / "root").rglob("*") if p.is_file()]
    assert len(files) == 1 and files[0].name == "report"


def test_concurrent_writers_of_different_content_leave_exactly_one_winner(
    store: FileSystemArtifactStore,
) -> None:
    outcomes: list[str] = []

    def put(i: int) -> None:
        try:
            store.put(KEY, io.BytesIO(f"v{i}".encode()), max_bytes=10)
            outcomes.append("ok")
        except ArtifactConflict:
            outcomes.append("conflict")

    threads = [threading.Thread(target=put, args=(i,)) for i in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert outcomes.count("ok") == 1 and outcomes.count("conflict") == 7
    with store.open(KEY) as handle:
        assert handle.read().startswith(b"v")


def test_the_object_survives_reopening_the_store(tmp_path: Path) -> None:
    FileSystemArtifactStore(tmp_path / "r").put(KEY, io.BytesIO(b"persist"), max_bytes=10)
    again = FileSystemArtifactStore(tmp_path / "r")
    with again.open(KEY) as handle:
        assert handle.read() == b"persist"
    assert os.listdir(tmp_path / "r") == ["t_abc123"]
