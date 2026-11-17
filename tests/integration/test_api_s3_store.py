"""B-07: l'adattatore S3 supera la stessa batteria, su un server compatibile in container.

`CA_TEST_DOCKER=1`. Il server di prova è SeaweedFS (licenza Apache 2.0, verificata il 2026-11-17):
è uno strumento di prova, mai distribuito con il prodotto (ADR-0030). Nessun servizio esterno.
"""

import io
import os
import sys
import time
import uuid
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

# La batteria sta con i test unitari dell'API: la stessa per ogni adattatore.
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "unit" / "api"))
from store_battery import KEY, run_battery  # noqa: E402

from ca_api.storage.s3 import S3ArtifactStore, StorageUnavailable, make_client
from ca_core.ports import ArtifactConflict, ArtifactNotFound

pytestmark = pytest.mark.skipif(
    os.environ.get("CA_TEST_DOCKER") != "1", reason="richiede Docker (CA_TEST_DOCKER=1)"
)
IMAGE = "chrislusf/seaweedfs:latest"


@pytest.fixture(scope="module")
def client() -> Iterator[Any]:
    from testcontainers.core.container import DockerContainer

    container = (
        DockerContainer(IMAGE).with_command("server -s3 -dir=/data").with_exposed_ports(8333)
    )
    with container:
        endpoint = f"http://{container.get_container_host_ip()}:{container.get_exposed_port(8333)}"
        os.environ.setdefault("AWS_ACCESS_KEY_ID", "test")
        os.environ.setdefault("AWS_SECRET_ACCESS_KEY", "test")
        s3 = make_client(endpoint_url=endpoint, region="us-east-1", allow_http=True, timeout=10)
        deadline = time.monotonic() + 90
        while True:
            try:
                s3.list_buckets()
                break
            except Exception:
                if time.monotonic() > deadline:
                    raise
                time.sleep(1)
        yield s3


def fresh_store(client: Any, prefix: str = "") -> S3ArtifactStore:
    bucket = f"b{uuid.uuid4().hex[:12]}"
    client.create_bucket(Bucket=bucket)
    return S3ArtifactStore(client, bucket, prefix=prefix)


def test_the_s3_adapter_passes_the_contract_battery(client: Any) -> None:
    for case in run_battery(lambda: fresh_store(client)):
        case()


def test_the_battery_also_passes_with_a_key_prefix(client: Any) -> None:
    for case in run_battery(lambda: fresh_store(client, prefix="tenants/acme")):
        case()


def test_a_prefix_isolates_two_stores_on_the_same_bucket(client: Any) -> None:
    bucket = f"b{uuid.uuid4().hex[:12]}"
    client.create_bucket(Bucket=bucket)
    one = S3ArtifactStore(client, bucket, prefix="one")
    two = S3ArtifactStore(client, bucket, prefix="two")
    one.put(KEY, io.BytesIO(b"1"), max_bytes=10)
    assert one.exists(KEY) and not two.exists(KEY)
    two.put(KEY, io.BytesIO(b"2"), max_bytes=10)
    with one.open(KEY) as a, two.open(KEY) as b:
        assert (a.read(), b.read()) == (b"1", b"2")


def test_overwriting_is_refused_by_the_service_not_only_by_a_head_check(client: Any) -> None:
    """Due scrittori in corsa con contenuto diverso: la condizione `If-None-Match` ne lascia uno."""
    import threading

    store = fresh_store(client)
    outcomes: list[str] = []

    def put(i: int) -> None:
        try:
            store.put(KEY, io.BytesIO(f"v{i}".encode()), max_bytes=10)
            outcomes.append("ok")
        except ArtifactConflict:
            outcomes.append("conflict")

    threads = [threading.Thread(target=put, args=(i,)) for i in range(6)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert outcomes.count("ok") == 1 and outcomes.count("conflict") == 5


def test_a_repetition_is_recognised_from_the_metadata_without_downloading(client: Any) -> None:
    store = fresh_store(client)
    first = store.put(KEY, io.BytesIO(b"same"), max_bytes=10)
    assert store.put(KEY, io.BytesIO(b"same"), max_bytes=10) == first


def test_a_missing_bucket_is_an_unavailable_storage_not_a_crash(client: Any) -> None:
    store = S3ArtifactStore(client, "bucket-that-does-not-exist")
    with pytest.raises((StorageUnavailable, ArtifactNotFound)):
        store.put(KEY, io.BytesIO(b"x"), max_bytes=10)


def test_an_unreachable_service_is_an_unavailable_storage_without_credentials_in_the_message() -> (
    None
):
    os.environ.setdefault("AWS_ACCESS_KEY_ID", "AKIA-SECRET-DO-NOT-LEAK")
    dead = make_client(
        endpoint_url="http://127.0.0.1:1", region="us-east-1", allow_http=True, timeout=1
    )
    store = S3ArtifactStore(dead, "b")
    with pytest.raises(StorageUnavailable) as caught:
        store.exists(KEY)
    assert "SECRET" not in str(caught.value) and "127.0.0.1" not in str(caught.value)


def test_a_plain_http_endpoint_is_refused_unless_allowed() -> None:
    with pytest.raises(ValueError):
        make_client(endpoint_url="http://s3.example", region="us-east-1")
