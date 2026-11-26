import json
import shutil
import socket
from pathlib import Path
from typing import Any

import pytest

from ca_core.schema_export import check
from ca_core.schema_validation import SchemaRefusedError, SchemaStore

ROOT = Path(__file__).resolve().parents[2]
VENDOR = ROOT / "schemas" / "vendor"
SARIF_OK = {
    "version": "2.1.0",
    "runs": [{"tool": {"driver": {"name": "t"}}, "results": []}],
}
CDX_OK = {"bomFormat": "CycloneDX", "specVersion": "1.7", "version": 1}


@pytest.fixture(autouse=True)
def no_network(monkeypatch: pytest.MonkeyPatch) -> None:
    def refuse(*args: Any, **kwargs: Any) -> None:
        raise AssertionError("accesso alla rete in un test")

    monkeypatch.setattr(socket, "socket", refuse)
    monkeypatch.setattr(socket, "getaddrinfo", refuse)


@pytest.fixture(scope="module")
def store() -> SchemaStore:
    return SchemaStore(VENDOR)


def test_sarif_valid_and_invalid(store: SchemaStore) -> None:
    assert store.validate_sarif(SARIF_OK) == []
    errors = store.validate_sarif({**SARIF_OK, "version": "2.0.0"})
    assert errors and errors[0].startswith("/version")
    assert store.validate_sarif({"runs": "x"})


def test_cyclonedx_validates_across_files_without_network(store: SchemaStore) -> None:
    # `components[].licenses` passa da `$ref` verso spdx.schema.json, altro file fissato.
    good = {
        **CDX_OK,
        "components": [{"type": "library", "name": "a", "licenses": [{"license": {"id": "MIT"}}]}],
    }
    bad = {
        **CDX_OK,
        "components": [
            {"type": "library", "name": "a", "licenses": [{"license": {"id": "NOT-AN-SPDX-ID"}}]}
        ],
    }
    assert store.validate_cyclonedx(good, "1.7") == []
    assert store.validate_cyclonedx(bad, "1.7")


def test_real_syft_sbom_is_valid(store: SchemaStore) -> None:
    sbom = json.loads((ROOT / "tests/fixtures/plugin-output/syft.cdx.json").read_text())
    assert store.validate_cyclonedx(sbom, "1.7") == []


def test_cyclonedx_version_not_admitted(store: SchemaStore) -> None:
    with pytest.raises(SchemaRefusedError, match="non ammessa"):
        store.validate_cyclonedx(CDX_OK, "1.6")


@pytest.mark.parametrize(
    "ref",
    [
        "https://example.com/other.schema.json",
        "http://cyclonedx.org/schema/unknown.schema.json",
        "file:///etc/passwd",
        "../secret.json",
        "/etc/passwd",
        "other.json#/definitions/x",
    ],
)
@pytest.mark.parametrize("key", ["$ref", "$dynamicRef"])
def test_external_or_unlisted_refs_are_refused(store: SchemaStore, ref: str, key: str) -> None:
    schema = {"$id": "urn:test:s", "properties": {"a": {key: ref}}}
    with pytest.raises(SchemaRefusedError, match="non ammesso"):
        store.validate_with(schema, {})


def test_local_and_pinned_refs_are_accepted(store: SchemaStore) -> None:
    schema = {
        "$id": "urn:test:s",
        "$defs": {"n": {"type": "integer"}},
        "properties": {
            "a": {"$ref": "#/$defs/n"},
            "b": {"$ref": "http://cyclonedx.org/schema/spdx.schema.json"},
        },
    }
    assert store.validate_with(schema, {"a": 1, "b": "MIT"}) == []
    assert store.validate_with(schema, {"a": "x"})


def test_deeply_nested_instance_is_reported_not_raised(store: SchemaStore) -> None:
    nested: Any = []
    for _ in range(20_000):
        nested = [nested]
    schema = {
        "$id": "urn:test:r",
        "$ref": "#/$defs/t",
        "$defs": {"t": {"items": {"$ref": "#/$defs/t"}}},
    }
    assert store.validate_with(schema, nested) == ["documento troppo annidato"]


def test_altered_vendor_file_is_refused(tmp_path: Path) -> None:
    shutil.copytree(VENDOR, tmp_path / "v")
    target = tmp_path / "v" / "spdx.schema.json"
    target.write_text(target.read_text() + " ")
    with pytest.raises(SchemaRefusedError, match="SHA-256"):
        SchemaStore(tmp_path / "v")


def test_unlisted_vendor_file_is_refused(tmp_path: Path) -> None:
    shutil.copytree(VENDOR, tmp_path / "v")
    (tmp_path / "v" / "extra.json").write_text("{}")
    with pytest.raises(SchemaRefusedError, match="non elencati"):
        SchemaStore(tmp_path / "v")


def test_vendor_sources_pin_known_origin() -> None:
    entries = json.loads((VENDOR / "SOURCES.json").read_text())["files"]
    assert {e["format"] for e in entries} == {
        "SARIF",
        "CycloneDX",
        "GitLab SAST",
        "GitLab Dependency Scanning",
    }
    assert all(len(e["sha256"]) == 64 and e["origin"].startswith("https://") for e in entries)


def test_schema_export_check_ignores_vendor_directory() -> None:
    # `vendor/` contiene file `*.schema.json` che non sono contratti nostri.
    assert [p for p in check([], ROOT / "schemas") if "vendor" in p or "bom-1.7" in p] == []


@pytest.mark.parametrize("path", sorted((ROOT / "tests/fixtures/plugin-output").glob("*.sarif")))
def test_recorded_sarif_outputs_are_valid(store: SchemaStore, path: Path) -> None:
    assert store.validate_sarif(json.loads(path.read_text())) == []


def test_recorded_trivy_sbom_is_valid(store: SchemaStore) -> None:
    sbom = json.loads((ROOT / "tests/fixtures/plugin-output/trivy.cdx.json").read_text())
    assert store.validate_cyclonedx(sbom, "1.7") == []
