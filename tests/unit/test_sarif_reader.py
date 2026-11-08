import copy
import json
import os
import socket
from pathlib import Path
from typing import Any

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from ca_core.sarif import (
    ParsedSarif,
    SarifError,
    SarifErrorCode,
    SarifLimits,
    parse_sarif,
    read_sarif_file,
)
from ca_core.schema_validation import SchemaStore

ROOT = Path(__file__).resolve().parents[2]
SAMPLES = ROOT / "tests" / "fixtures" / "plugin-output"
SECRET = "SENTINELLA-NON-DEVE-USCIRE"

VALID: dict[str, Any] = {
    "version": "2.1.0",
    "runs": [
        {
            "tool": {"driver": {"name": "t"}},
            "results": [
                {
                    "ruleId": "r",
                    "message": {"text": "m"},
                    "properties": {"aliases": ["CVE-2024-1"], "tool_severity": "HIGH", "x": 1},
                }
            ],
        }
    ],
}


@pytest.fixture(autouse=True)
def no_network(monkeypatch: pytest.MonkeyPatch) -> None:
    def refuse(*args: Any, **kwargs: Any) -> None:
        raise AssertionError("accesso alla rete in un test")

    monkeypatch.setattr(socket, "socket", refuse)


@pytest.fixture(scope="module")
def store() -> SchemaStore:
    return SchemaStore(ROOT / "schemas" / "vendor")


def parse(store: SchemaStore, document: Any, **limits: int) -> ParsedSarif:
    return parse_sarif(json.dumps(document).encode(), store, SarifLimits(**limits))


def code_of(store: SchemaStore, data: bytes, limits: SarifLimits | None = None) -> SarifErrorCode:
    with pytest.raises(SarifError) as info:
        parse_sarif(data, store, limits)
    return info.value.code


def test_null_runs_is_valid_sarif(store: SchemaStore) -> None:
    assert parse(store, {"version": "2.1.0", "runs": None}).results == ()


@pytest.mark.parametrize("sample", sorted(SAMPLES.glob("*.sarif")), ids=lambda p: p.name)
def test_real_samples_are_read(store: SchemaStore, sample: Path) -> None:
    parsed = read_sarif_file(sample, store)

    expected = sum(len(run.get("results", [])) for run in parsed.document["runs"])
    assert len(parsed.results) == expected > 0


def test_valid_document_exposes_typed_properties(store: SchemaStore) -> None:
    parsed = parse(store, VALID)

    properties = parsed.results[0].properties
    assert properties is not None and properties.aliases == ["CVE-2024-1"]
    assert properties.tool_severity == "HIGH"


def test_result_without_properties(store: SchemaStore) -> None:
    document = copy.deepcopy(VALID)
    del document["runs"][0]["results"][0]["properties"]

    assert parse(store, document).results[0].properties is None


@pytest.mark.parametrize(
    ("data", "code"),
    [
        (b"", SarifErrorCode.NOT_JSON),
        (b"\xff\xfe", SarifErrorCode.NOT_JSON),
        (b'{"version": NaN}', SarifErrorCode.NOT_JSON),
        (b"9" * 10_000, SarifErrorCode.NOT_JSON),
        (b"[" * 100_000, SarifErrorCode.TOO_DEEP),
        (b'{"version":"2.0.0","runs":[]}', SarifErrorCode.SCHEMA),
        (b"[]", SarifErrorCode.SCHEMA),
    ],
)
def test_invalid_input_is_a_typed_error(
    store: SchemaStore, data: bytes, code: SarifErrorCode
) -> None:
    assert code_of(store, data) is code


def test_limits(store: SchemaStore) -> None:
    data = json.dumps(VALID).encode()
    assert code_of(store, data, SarifLimits(max_bytes=10)) is SarifErrorCode.TOO_LARGE
    assert code_of(store, data, SarifLimits(max_depth=3)) is SarifErrorCode.TOO_DEEP
    many = copy.deepcopy(VALID)
    many["runs"][0]["results"] *= 3
    assert code_of(store, json.dumps(many).encode(), SarifLimits(max_results=2)) is (
        SarifErrorCode.TOO_MANY_RESULTS
    )
    many["runs"] *= 3
    assert code_of(store, json.dumps(many).encode(), SarifLimits(max_runs=2)) is (
        SarifErrorCode.TOO_MANY_RUNS
    )
    with pytest.raises(ValueError):
        SarifLimits(max_depth=0)


def test_real_samples_fit_default_depth_with_margin(store: SchemaStore) -> None:
    for sample in SAMPLES.glob("*.sarif"):
        assert parse_sarif(sample.read_bytes(), store, SarifLimits(max_depth=32))


def test_invalid_properties_fail_without_leaking_values(store: SchemaStore) -> None:
    document = copy.deepcopy(VALID)
    document["runs"][0]["results"][0]["properties"] = {
        "cvss": {"version": "9.9", "vector": SECRET, "score": 99},
        "purl": SECRET,
    }

    with pytest.raises(SarifError) as info:
        parse(store, document)

    error = info.value
    assert error.code is SarifErrorCode.PROPERTIES
    assert SECRET not in str(error) and SECRET not in repr(error.details)
    assert "/runs/0/results/0/properties/cvss/version" in error.details


def test_schema_error_does_not_leak_values(store: SchemaStore) -> None:
    document = copy.deepcopy(VALID)
    document["runs"][0]["results"][0]["level"] = SECRET

    with pytest.raises(SarifError) as info:
        parse(store, document)

    assert info.value.code is SarifErrorCode.SCHEMA
    assert SECRET not in str(info.value) + repr(info.value.details)
    assert info.value.details == ("/runs/0/results/0/level",)


def test_extra_check_can_reject(store: SchemaStore) -> None:
    def no_results(document: Any) -> None:
        raise SarifError(SarifErrorCode.CHECK, "rifiutato")

    with pytest.raises(SarifError) as info:
        parse_sarif(json.dumps(VALID).encode(), store, checks=[no_results])

    assert info.value.code is SarifErrorCode.CHECK


def test_file_reading_refuses_non_regular_and_oversized(store: SchemaStore, tmp_path: Path) -> None:
    good = tmp_path / "ok.sarif"
    good.write_text(json.dumps(VALID))
    link = tmp_path / "link.sarif"
    link.symlink_to(good)
    fifo = tmp_path / "fifo.sarif"
    os.mkfifo(fifo)

    assert read_sarif_file(good, store).results
    for path in (link, fifo, tmp_path / "missing.sarif", tmp_path, Path("a\0b")):
        with pytest.raises(SarifError) as info:
            read_sarif_file(path, store)
        assert info.value.code is SarifErrorCode.UNREADABLE
    with pytest.raises(SarifError) as info:
        read_sarif_file(good, store, SarifLimits(max_bytes=10))
    assert info.value.code is SarifErrorCode.TOO_LARGE


_JSON = st.recursive(
    st.none() | st.booleans() | st.integers() | st.floats() | st.text(max_size=20),
    lambda children: (
        st.lists(children, max_size=4) | st.dictionaries(st.text(max_size=8), children)
    ),
    max_leaves=30,
)
_FUZZ = settings(max_examples=300, suppress_health_check=[HealthCheck.function_scoped_fixture])


def _only_typed(store: SchemaStore, data: bytes) -> None:
    try:
        parse_sarif(data, store, SarifLimits(max_depth=8, max_results=5))
    except SarifError:
        pass


@_FUZZ
@given(st.binary(max_size=2000))
def test_fuzz_arbitrary_bytes(store: SchemaStore, data: bytes) -> None:
    _only_typed(store, data)


@_FUZZ
@given(_JSON)
def test_fuzz_arbitrary_json(store: SchemaStore, document: Any) -> None:
    _only_typed(store, json.dumps(document, allow_nan=True).encode())


@_FUZZ
@given(_JSON, st.sampled_from(["tool", "results", "properties", "level", "message", "runs"]))
def test_fuzz_mutations_of_a_valid_document(store: SchemaStore, junk: Any, key: str) -> None:
    document = copy.deepcopy(VALID)
    run = document["runs"][0]
    result = run["results"][0]
    target = {
        "tool": run,
        "results": run,
        "properties": result,
        "level": result,
        "message": result,
        "runs": document,
    }[key]
    target[key] = junk
    _only_typed(store, json.dumps(document, allow_nan=True).encode())
