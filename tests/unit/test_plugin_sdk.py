"""R-01: i manifest vengono solo dai dati del pacchetto e rifiutati se incompleti."""

import json
from pathlib import Path
from typing import Any

import pytest
import yaml

from ca_plugins import sdk

DIGEST = f"sha256:{'0' * 64}"
_BASE: dict[str, Any] = {
    "apiVersion": "code-analyzer/v1",
    "name": "osv-scanner",
    "version": "1.0.0",
    "image": f"registry.invalid/ca-plugins/osv-scanner:1.0.0@{DIGEST}",
    "capabilities": ["detect"],
    "languages": [],
    "categories": ["dependency"],
    "inputs": {"workspace": "readonly"},
    "outputs": {"sarif": "/out/results.sarif", "max_bytes": 52428800},
    "resources": {"cpu": "2", "memory": "2Gi", "timeout": "600s", "pids": 256},
    "network": "none",
}


def _manifest(**changes: Any) -> dict[str, Any]:
    return {**json.loads(json.dumps(_BASE)), **changes}


def _bytes(doc: dict[str, Any]) -> bytes:
    return yaml.safe_dump(doc).encode()


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


@pytest.mark.parametrize(
    "data",
    [
        b"{",
        b"[]",
        b"- a\n- b\n",
        b"just a string",
        b"",
        b"a: 1\n---\nb: 2\n",
        b"!!python/object/apply:os.getcwd []",
        b"\xff\xfe",
        b"x" * (sdk.MAX_MANIFEST_BYTES + 1),
    ],
)
def test_malformed_or_oversized_is_rejected(data: bytes) -> None:
    with pytest.raises(sdk.ManifestError):
        sdk.parse_manifest(data)


def test_yaml_aliases_are_rejected() -> None:
    text = _bytes(_manifest()).decode().replace("name: osv-scanner", "name: &n osv-scanner")
    with pytest.raises(sdk.ManifestError):
        sdk.parse_manifest((text + "x: *n\n").encode())


def test_error_does_not_echo_untrusted_input() -> None:
    with pytest.raises(sdk.ManifestError) as info:
        sdk.parse_manifest(_bytes(_manifest(name="SECRET-VALUE")))
    assert "SECRET-VALUE" not in str(info.value)


@pytest.mark.parametrize("name", ["../x", "a/b", "A", "", "x.yaml"])
def test_invalid_plugin_name_is_rejected(name: str) -> None:
    with pytest.raises(sdk.ManifestError):
        sdk.load_packaged_manifest(name)


def test_unknown_plugin_is_rejected() -> None:
    with pytest.raises(sdk.ManifestError, match="assente"):
        sdk.load_packaged_manifest("nope")


def test_loads_from_package_data(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    pkg = tmp_path / "ca_plugins"
    for folder in ("osv_scanner", "other"):
        (pkg / "builtin" / folder).mkdir(parents=True)
        (pkg / "builtin" / folder / "plugin.yaml").write_bytes(_bytes(_manifest()))
    (pkg / "builtin" / "empty").mkdir()
    monkeypatch.setattr(sdk, "files", lambda _: pkg)
    assert sdk.load_packaged_manifest("osv-scanner").image.endswith(DIGEST)
    assert sdk.list_packaged_plugins() == ["osv-scanner", "other"]
    with pytest.raises(sdk.ManifestError, match="non corrisponde"):
        sdk.load_packaged_manifest("other")
