"""Batteria di contratto della porta `ArtifactStore` (B-07, ADR-0030), per ogni adattatore."""

import hashlib
import io
from collections.abc import Callable
from typing import BinaryIO

import pytest

from ca_core.ports import (
    ArtifactConflict,
    ArtifactIntegrityError,
    ArtifactNotFound,
    ArtifactStore,
    ArtifactTooLarge,
)

KEY = "t_abc123/0192f3a2/report"
LIMIT = 1024 * 1024


class CountingStream(io.RawIOBase):
    """Un flusso che conta i byte letti: il limite deve fermare la lettura, non solo il rifiuto."""

    def __init__(self, size: int) -> None:
        self.remaining, self.read_total = size, 0

    def readable(self) -> bool:
        return True

    def readinto(self, buffer: bytearray) -> int:  # type: ignore[override]
        count = min(len(buffer), self.remaining)
        buffer[:count] = b"x" * count
        self.remaining -= count
        self.read_total += count
        return count


def run_battery(make: Callable[[], ArtifactStore]) -> list[Callable[[], None]]:
    """Le prove, come funzioni senza argomenti su un archivio nuovo ciascuna."""

    def case(fn: Callable[[ArtifactStore], None]) -> Callable[[], None]:
        def runner() -> None:
            fn(make())

        runner.__name__ = fn.__name__
        return runner

    def roundtrip(store: ArtifactStore) -> None:
        data = b"contenuto " * 1000
        stored = store.put(KEY, io.BytesIO(data), max_bytes=LIMIT)
        assert (stored.key, stored.size) == (KEY, len(data))
        assert stored.sha256 == hashlib.sha256(data).hexdigest()
        with store.open(KEY) as handle:
            assert handle.read() == data

    def empty_content(store: ArtifactStore) -> None:
        assert store.put(KEY, io.BytesIO(b""), max_bytes=1).size == 0
        with store.open(KEY) as handle:
            assert handle.read() == b""

    def large_content(store: ArtifactStore) -> None:
        data = b"0123456789abcdef" * (300 * 1024)  # circa 4,6 MiB
        store.put(KEY, io.BytesIO(data), max_bytes=len(data))
        with store.open(KEY) as handle:
            assert hashlib.sha256(handle.read()).hexdigest() == hashlib.sha256(data).hexdigest()

    def declared_digest_is_checked_while_writing(store: ArtifactStore) -> None:
        data = b"abc"
        good = hashlib.sha256(data).hexdigest()
        assert store.put(KEY, io.BytesIO(data), max_bytes=10, sha256=good).sha256 == good
        with pytest.raises(ArtifactIntegrityError):
            store.put("t_abc123/x/other", io.BytesIO(data), max_bytes=10, sha256="0" * 64)
        assert not store.exists("t_abc123/x/other")  # niente a metà

    def too_large_is_refused_and_the_read_is_bounded(store: ArtifactStore) -> None:
        stream = CountingStream(50 * 1024 * 1024)
        with pytest.raises(ArtifactTooLarge):
            store.put(KEY, io.BufferedReader(stream, buffer_size=4096), max_bytes=1000)
        assert stream.read_total <= 1000 + 2 * 4096  # al più un blocco oltre il limite
        assert not store.exists(KEY)

    def exactly_the_limit_is_fine(store: ArtifactStore) -> None:
        assert store.put(KEY, io.BytesIO(b"x" * 100), max_bytes=100).size == 100
        with pytest.raises(ArtifactTooLarge):
            store.put("t_abc123/x/b", io.BytesIO(b"x" * 101), max_bytes=100)

    def same_content_is_a_repetition_different_is_a_conflict(store: ArtifactStore) -> None:
        first = store.put(KEY, io.BytesIO(b"one"), max_bytes=10)
        again = store.put(KEY, io.BytesIO(b"one"), max_bytes=10)
        assert first == again
        with pytest.raises(ArtifactConflict):
            store.put(KEY, io.BytesIO(b"two"), max_bytes=10)
        with store.open(KEY) as handle:
            assert handle.read() == b"one"  # l'originale è intatto

    def missing_keys(store: ArtifactStore) -> None:
        with pytest.raises(ArtifactNotFound):
            store.open("t_abc123/none/report")
        assert store.exists("t_abc123/none/report") is False
        store.delete("t_abc123/none/report")  # idempotente

    def delete_removes_and_is_idempotent(store: ArtifactStore) -> None:
        store.put(KEY, io.BytesIO(b"x"), max_bytes=10)
        store.delete(KEY)
        store.delete(KEY)
        assert not store.exists(KEY)
        store.put(
            KEY, io.BytesIO(b"y"), max_bytes=10
        )  # la chiave si può riscrivere dopo la cancellazione
        with store.open(KEY) as handle:
            assert handle.read() == b"y"

    def keys_are_independent(store: ArtifactStore) -> None:
        store.put("t_a/1/report", io.BytesIO(b"a"), max_bytes=10)
        store.put("t_b/1/report", io.BytesIO(b"b"), max_bytes=10)
        with store.open("t_a/1/report") as one, store.open("t_b/1/report") as two:
            assert (one.read(), two.read()) == (b"a", b"b")

    def invalid_keys_never_reach_the_storage(store: ArtifactStore) -> None:
        bad = [
            "",
            "/abs/path",
            "a//b",
            "a/../b",
            "../escape",
            "a/./b",
            "a/b/",
            "a b/c",
            "a/b\x00c",
            "a/é/c",
            "/".join(["s"] * 13),
            "a/" + "x" * 300,
        ]
        for key in bad:
            with pytest.raises(ValueError):
                store.put(key, io.BytesIO(b"x"), max_bytes=10)
            with pytest.raises(ValueError):
                store.open(key)
            with pytest.raises(ValueError):
                store.exists(key)
            with pytest.raises(ValueError):
                store.delete(key)

    def max_bytes_must_be_positive(store: ArtifactStore) -> None:
        with pytest.raises(ValueError):
            store.put(KEY, io.BytesIO(b"x"), max_bytes=0)

    def a_failed_put_leaves_nothing(store: ArtifactStore) -> None:
        with pytest.raises(ArtifactIntegrityError):
            store.put(KEY, io.BytesIO(b"abc"), max_bytes=10, sha256="f" * 64)
        assert not store.exists(KEY)
        store.put(KEY, io.BytesIO(b"abc"), max_bytes=10)  # e la chiave resta usabile

    cases = [
        roundtrip,
        empty_content,
        large_content,
        declared_digest_is_checked_while_writing,
        too_large_is_refused_and_the_read_is_bounded,
        exactly_the_limit_is_fine,
        same_content_is_a_repetition_different_is_a_conflict,
        missing_keys,
        delete_removes_and_is_idempotent,
        keys_are_independent,
        invalid_keys_never_reach_the_storage,
        max_bytes_must_be_positive,
        a_failed_put_leaves_nothing,
    ]
    return [case(c) for c in cases]


def stream(data: bytes) -> BinaryIO:
    return io.BytesIO(data)
