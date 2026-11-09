"""Plugin syft (P-01) senza Docker: manifest, adattatore, fixture registrate, Dockerfile.

Le prove sull'immagine reale sono in `tests/integration/test_syft_image.py`. L'output registrato
in `fixtures/output/` è letto anche dal test di contratto T-04 (`tests/contract/plugins`).
"""

import importlib.util
import json
import re
import stat
import sys
from pathlib import Path
from typing import Any

import pytest
import yaml
from jsonschema import Draft202012Validator

from ca_core.models import PluginManifest

ROOT = Path(__file__).resolve().parents[2]
SYFT = ROOT / "packages/ca-plugins/src/ca_plugins/builtin/syft"
OUTPUTS = sorted((SYFT / "fixtures/output").glob("syft.*.cdx.json"))
SHA256 = "9c077a7d43029b3b13e98a8db720661e700c4d58db6352153a06395ae4a2a704"  # V-01

_spec = importlib.util.spec_from_file_location("syft_adapter", SYFT / "syft_adapter.py")
assert _spec and _spec.loader
adapter = importlib.util.module_from_spec(_spec)
sys.modules["syft_adapter"] = adapter
_spec.loader.exec_module(adapter)

MANIFEST: dict[str, Any] = yaml.safe_load((SYFT / "plugin.yaml").read_text())


def bom(**changes: Any) -> dict[str, Any]:
    document: dict[str, Any] = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.7",
        "metadata": {"component": {"type": "file", "name": "/workspace"}},
        "components": [
            {
                "type": "library",
                "name": "lodash",
                "properties": [
                    {"name": "syft:location:0:path", "value": "/package-lock.json"},
                    {"name": "syft:location:1:path", "value": "/workspace/a/package.json"},
                    {"name": "syft:package:type", "value": "npm"},
                ],
            },
            {"type": "file", "name": "/package-lock.json"},
            {"type": "file", "name": "/workspace/sub/f.txt"},
        ],
    }
    return {**document, **changes}


# --- manifest ---------------------------------------------------------------------------


def test_manifest_valid_for_schema_and_model() -> None:
    schema = json.loads((ROOT / "schemas" / "plugin-manifest.schema.json").read_text())
    Draft202012Validator(schema).validate(MANIFEST)
    model = PluginManifest.model_validate(MANIFEST)
    assert model.name == "syft"
    assert model.outputs.cyclonedx == "/out/sbom.cdx.json"
    assert model.outputs.sarif is None
    assert model.outputs.cyclonedx_version == "1.7"
    assert (model.inputs.sbom, model.inputs.config, model.network) == ("none", "none", "none")


def test_manifest_has_no_real_registry_and_no_digest() -> None:
    image = MANIFEST["image"]
    assert image.startswith("registry.invalid/") and "@" not in image  # D-0005 aperta
    assert not image.endswith(":latest")


def test_manifest_limits_cover_the_measured_outputs() -> None:
    largest = max(p.stat().st_size for p in OUTPUTS)
    assert MANIFEST["outputs"]["max_bytes"] > 100 * largest
    assert "X-02" in (SYFT / "plugin.yaml").read_text()


# --- fixture registrate ---------------------------------------------------------------------


def test_recorded_outputs_exist_for_both_fixture_repositories() -> None:
    assert [p.name for p in OUTPUTS] == ["syft.js-ts-app.cdx.json", "syft.python-app.cdx.json"]


@pytest.mark.parametrize("path", OUTPUTS, ids=lambda p: p.name)
def test_recorded_outputs_have_relative_paths_only(path: Path) -> None:
    text = path.read_text()
    assert "/workspace" not in text and "/home/" not in text and "/tmp/" not in text
    document = json.loads(text)
    assert document["specVersion"] == "1.7"
    assert document["metadata"]["component"]["name"] == "."
    for component in document["components"]:
        assert not component["name"].startswith("/") or component["type"] != "file"
        for prop in component.get("properties", []):
            if prop["name"].startswith("syft:location:"):
                assert not prop["value"].startswith("/")


def test_recorded_outputs_list_the_lockfile_packages() -> None:
    def purls(name: str) -> set[str]:
        document = json.loads((SYFT / "fixtures/output" / name).read_text())
        return {c["purl"] for c in document["components"] if "purl" in c}

    assert {"pkg:npm/lodash@4.17.15", "pkg:npm/axios@0.21.0"} <= purls("syft.js-ts-app.cdx.json")
    assert {"pkg:pypi/pyyaml@5.3.1", "pkg:pypi/requests@2.19.1"} <= purls(
        "syft.python-app.cdx.json"
    )


# --- adattatore ---------------------------------------------------------------------------


def test_adapt_makes_every_path_relative() -> None:
    out = json.loads(adapter.adapt(json.dumps(bom()).encode()))
    assert out["metadata"]["component"]["name"] == "."
    paths = [p["value"] for p in out["components"][0]["properties"] if "location" in p["name"]]
    assert paths == ["package-lock.json", "a/package.json"]
    assert [c["name"] for c in out["components"][1:]] == ["package-lock.json", "sub/f.txt"]
    assert out["components"][0]["properties"][2] == {"name": "syft:package:type", "value": "npm"}
    assert "/workspace" not in json.dumps(out)


def test_adapt_keeps_non_path_values() -> None:
    document = bom()
    document["components"][0]["name"] = "/library-with-a-leading-slash"  # non è un file
    out = json.loads(adapter.adapt(json.dumps(document).encode()))
    assert out["components"][0]["name"] == "/library-with-a-leading-slash"


@pytest.mark.parametrize(
    "raw",
    [
        b"not json",
        b"[]",
        json.dumps(bom(bomFormat="SPDX")).encode(),
        json.dumps(bom(specVersion="1.6")).encode(),
        json.dumps(bom(components=[{"name": "x", "description": "see /workspacefoo"}])).encode(),
    ],
    ids=["not-json", "not-object", "not-cyclonedx", "other-version", "path-left-over"],
)
def test_adapt_rejects_what_it_cannot_make_conforming(raw: bytes) -> None:
    with pytest.raises(adapter.InvalidOutput):
        adapter.adapt(raw)


def fake_syft(tmp_path: Path, body: str) -> str:
    script = tmp_path / "syft"
    script.write_text(f"#!/bin/sh\n{body}\n")
    script.chmod(script.stat().st_mode | stat.S_IXUSR)
    return str(script)


def run_adapter(tmp_path: Path, body: str) -> tuple[int, Path]:
    out = tmp_path / "sbom.cdx.json"
    code = adapter.run(
        syft=fake_syft(tmp_path, body),
        workspace="/workspace",
        out_file=str(out),
        tmp_file=str(tmp_path / "raw.json"),
    )
    return code, out


def test_run_passes_the_fixed_arguments_and_writes_the_adapted_file(tmp_path: Path) -> None:
    raw = json.dumps(bom())
    args = tmp_path / "args"
    body = f'echo "$@" > {args}\ncat > "${{5#cyclonedx-json@1.7=}}" <<\'EOF\'\n{raw}\nEOF'
    code, out = run_adapter(tmp_path, body)
    assert code == 0
    assert args.read_text().split() == [
        "scan",
        "dir:/workspace",
        "-q",
        "-o",
        f"cyclonedx-json@1.7={tmp_path}/raw.json",
    ]
    assert json.loads(out.read_text())["metadata"]["component"]["name"] == "."


def test_run_syft_failure_is_exit_3_and_writes_nothing(tmp_path: Path) -> None:
    code, out = run_adapter(tmp_path, "echo secret-from-repo >&2; exit 1")
    assert (code, out.exists()) == (adapter.EXIT_SYFT, False)


def test_run_syft_without_output_is_exit_3(tmp_path: Path) -> None:
    assert run_adapter(tmp_path, "exit 0")[0] == adapter.EXIT_SYFT


def test_run_missing_binary_is_exit_3(tmp_path: Path) -> None:
    code = adapter.run(syft=str(tmp_path / "nope"), out_file=str(tmp_path / "o"))
    assert code == adapter.EXIT_SYFT


def test_run_nonconforming_output_is_exit_5_and_writes_nothing(tmp_path: Path) -> None:
    body = 'echo "{}" > "${5#cyclonedx-json@1.7=}"'
    code, out = run_adapter(tmp_path, body)
    assert (code, out.exists()) == (adapter.EXIT_INVALID, False)


def test_run_never_leaks_stderr_or_stdout(
    tmp_path: Path, capfd: pytest.CaptureFixture[str]
) -> None:
    run_adapter(tmp_path, "echo token=abc; echo token=abc >&2; exit 1")
    assert capfd.readouterr() == ("", "")


def test_adapter_does_not_import_ca_core() -> None:
    assert not re.search(r"^\s*(?:from|import)\s+ca_", (SYFT / "syft_adapter.py").read_text(), re.M)


# --- immagine (statico) -------------------------------------------------------------------


def test_dockerfile_pins_base_binary_and_labels() -> None:
    text = (SYFT / "Dockerfile").read_text()
    froms = re.findall(r"^FROM\s+(?:--platform=\S+\s+)?(\S+)", text, re.M)
    assert froms and all(re.search(r"@sha256:[0-9a-f]{64}$", f) for f in froms)
    code = "\n".join(line for line in text.splitlines() if not line.lstrip().startswith("#"))
    assert "latest" not in code.lower()
    assert (
        f"--checksum=sha256:{SHA256}" in text
    )  # ADD con checksum: la build fallisce se differisce
    assert "syft_1.57.0_linux_amd64.tar.gz" in text
    assert 'ca.engines="syft"' in text
    assert "org.opencontainers.image.licenses" not in text  # D-0015
    assert "USER 65534:65534" in text
    assert re.search(r'^ENTRYPOINT \["python", "/opt/ca-plugin/syft_adapter.py"\]$', text, re.M)


def test_build_context_contains_only_what_the_image_needs() -> None:
    assert (SYFT / ".dockerignore").read_text().split() == [
        "*",
        "!syft_adapter.py",
        "!licenses",
    ]


def test_license_files_are_the_release_texts_without_a_product_license() -> None:
    notices = (SYFT / "licenses/THIRD-PARTY-NOTICES.md").read_text()
    assert "Apache-2.0" in notices
    assert "non dichiara la licenza del prodotto" in " ".join(notices.split()).lower()
    licence = (SYFT / "licenses/syft/LICENSE").read_text()
    assert "Apache License" in licence and "Version 2.0, January 2004" in licence
