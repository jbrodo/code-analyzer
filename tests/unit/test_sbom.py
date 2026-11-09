import copy
import json
from pathlib import Path
from typing import Any

import pytest

from ca_core.sbom import (
    SbomError,
    SbomErrorCode,
    parse_cyclonedx,
    serialize_cyclonedx,
)
from ca_core.schema_validation import SchemaStore

ROOT = Path(__file__).resolve().parents[2]
SAMPLES = sorted((ROOT / "tests" / "fixtures" / "plugin-output").glob("*.cdx.json"))


@pytest.fixture(scope="module")
def store() -> SchemaStore:
    return SchemaStore(ROOT / "schemas" / "vendor")


def code_of(store: SchemaStore, data: bytes, version: str = "1.7") -> SbomErrorCode:
    with pytest.raises(SbomError) as info:
        parse_cyclonedx(data, store, version)
    return info.value.code


@pytest.mark.parametrize("sample", SAMPLES, ids=lambda p: p.name)
def test_real_samples_are_valid_1_7(store: SchemaStore, sample: Path) -> None:
    parsed = parse_cyclonedx(sample.read_bytes(), store, "1.7")

    assert parsed.version == "1.7" and parsed.document["components"]


@pytest.mark.parametrize("sample", SAMPLES, ids=lambda p: p.name)
def test_writer_keeps_components_purl_and_licenses(store: SchemaStore, sample: Path) -> None:
    document = json.loads(sample.read_bytes())

    written = serialize_cyclonedx(document, store)

    assert json.loads(written) == document  # nessuna perdita
    assert written == serialize_cyclonedx(copy.deepcopy(document), store)  # deterministico
    assert parse_cyclonedx(written, store, "1.7").document == document


def test_declared_version_not_admitted_fails(store: SchemaStore) -> None:
    assert code_of(store, SAMPLES[0].read_bytes(), "1.6") is SbomErrorCode.VERSION


def test_spec_version_must_match_the_manifest(store: SchemaStore) -> None:
    document: dict[str, Any] = json.loads(SAMPLES[0].read_bytes())
    document["specVersion"] = "1.6"

    assert code_of(store, json.dumps(document).encode()) is SbomErrorCode.VERSION_MISMATCH
    with pytest.raises(SbomError) as info:
        serialize_cyclonedx(document, store)
    assert info.value.code is SbomErrorCode.VERSION_MISMATCH


def test_non_conforming_document_fails_without_values(store: SchemaStore) -> None:
    document: dict[str, Any] = json.loads(SAMPLES[0].read_bytes())
    document["components"] = "SENTINELLA"

    with pytest.raises(SbomError) as info:
        parse_cyclonedx(json.dumps(document).encode(), store, "1.7")

    assert info.value.code is SbomErrorCode.SCHEMA
    assert "SENTINELLA" not in str(info.value) + "".join(info.value.details)
    with pytest.raises(SbomError):
        serialize_cyclonedx(document, store)


@pytest.mark.parametrize(
    ("data", "code"),
    [
        (b"", SbomErrorCode.NOT_JSON),
        (b'{"specVersion": NaN}', SbomErrorCode.NOT_JSON),
        (b"[" * 100_000 + b"]" * 100_000, SbomErrorCode.TOO_DEEP),
        (b"[]", SbomErrorCode.VERSION_MISMATCH),
        (b'{"specVersion":"1.7"}', SbomErrorCode.SCHEMA),
    ],
)
def test_invalid_input_is_a_typed_error(
    store: SchemaStore, data: bytes, code: SbomErrorCode
) -> None:
    assert code_of(store, data) is code


def test_size_limit(store: SchemaStore) -> None:
    with pytest.raises(SbomError) as info:
        parse_cyclonedx(SAMPLES[0].read_bytes(), store, "1.7", max_bytes=10)
    assert info.value.code is SbomErrorCode.TOO_LARGE
