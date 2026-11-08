"""R-01: i manifest vengono solo dai dati del pacchetto e rifiutati se incompleti."""

import json
from pathlib import Path
from typing import Any

import pytest

from ca_core.models.plugin_manifest import _EXAMPLE_FULL  # pyright: ignore
from ca_plugins import sdk

DIGEST = f"sha256:{'0' * 64}"


def _manifest(**changes: Any) -> dict[str, Any]:
    return {**json.loads(json.dumps(_EXAMPLE_FULL)), **changes}


def _bytes(doc: dict[str, Any]) -> bytes:
    return json.dumps(doc).encode()


def test_packaged_manifest_is_accepted() -> None:
    assert sdk.parse_manifest(_bytes(_manifest())).name == "osv-scanner"


def test_packaged_without_digest_is_rejected() -> None:
    doc = _manifest(image="registry.invalid/ca-plugins/osv-scanner:1.0.0")
    with pytest.raises(sdk.ManifestError):
        sdk.parse_manifest(_bytes(doc))
    assert sdk.parse_manifest(_bytes(doc), packaged=False).image == doc["image"]


def test_missing_max_bytes_is_rejected() -> None:
    doc = _manifest()
    del doc["outputs"]["max_bytes"]
    with pytest.raises(sdk.ManifestError, match="max_bytes"):
        sdk.parse_manifest(_bytes(doc), packaged=False)


@pytest.mark.parametrize("data", [b"{", b"[]", b"x" * (sdk.MAX_MANIFEST_BYTES + 1)])
def test_malformed_or_oversized_is_rejected(data: bytes) -> None:
    with pytest.raises(sdk.ManifestError):
        sdk.parse_manifest(data)


def test_error_does_not_echo_untrusted_input() -> None:
    with pytest.raises(sdk.ManifestError) as info:
        sdk.parse_manifest(_bytes(_manifest(name="SECRET-VALUE")))
    assert "SECRET-VALUE" not in str(info.value)


@pytest.mark.parametrize("name", ["../x", "a/b", "A", "", "x.json"])
def test_invalid_plugin_name_is_rejected(name: str) -> None:
    with pytest.raises(sdk.ManifestError):
        sdk.load_packaged_manifest(name)


def test_unknown_plugin_is_rejected() -> None:
    with pytest.raises(sdk.ManifestError, match="assente"):
        sdk.load_packaged_manifest("nope")


def test_loads_from_package_data(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    pkg = tmp_path / "ca_plugins"
    (pkg / "manifests").mkdir(parents=True)
    (pkg / "manifests" / "osv-scanner.json").write_bytes(_bytes(_manifest()))
    (pkg / "manifests" / "other.json").write_bytes(_bytes(_manifest()))
    monkeypatch.setattr(sdk, "files", lambda _: pkg)
    assert sdk.load_packaged_manifest("osv-scanner").image.endswith(DIGEST)
    assert sdk.list_packaged_plugins() == ["osv-scanner", "other"]
    with pytest.raises(sdk.ManifestError, match="non corrisponde"):
        sdk.load_packaged_manifest("other")
