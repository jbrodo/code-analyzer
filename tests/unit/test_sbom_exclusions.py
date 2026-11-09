"""ADR-0014: `paths.exclude` vale anche per le licenze dell'SBOM, che non hanno un percorso."""

import json
from pathlib import Path
from typing import Any

import pytest
from test_cli_scan_gate import REPORT, Env, manifest

from ca_core.fakes import FakePluginExecutor
from ca_core.normalize import declared_licenses
from ca_core.pipeline.exclusions import component_excluded

GPL = {"license": {"id": "GPL-3.0-only"}}


def component(*paths: str) -> dict[str, Any]:
    return {
        "type": "library",
        "name": "lib",
        "version": "1",
        "purl": "pkg:pypi/lib@1",
        "licenses": [GPL],
        "properties": [
            {"name": f"syft:location:{i}:path", "value": path} for i, path in enumerate(paths)
        ],
    }


def test_locations_come_from_the_syft_properties() -> None:
    [item] = declared_licenses({"components": [component("a/poetry.lock", "b/poetry.lock")]})
    assert item.locations == ("a/poetry.lock", "b/poetry.lock")


@pytest.mark.parametrize(
    ("locations", "excluded"),
    [
        (("vendor/poetry.lock",), True),
        (("vendor/poetry.lock", "other/poetry.lock"), False),  # basta un file ancora analizzato
        (("poetry.lock",), False),
        ((), False),  # provenienza ignota: si valuta
        (("a/node_modules/x/package-lock.json",), True),  # esclusione predefinita
    ],
)
def test_component_is_excluded_only_if_all_its_files_are(
    locations: tuple[str, ...], excluded: bool
) -> None:
    assert component_excluded(locations, ["vendor/**"]) is excluded


@pytest.mark.parametrize(("exclude", "findings"), [("vendor/**", 0), ("altro/**", 1)])
def test_scan_applies_exclusions_to_license_findings(
    tmp_path: Path, exclude: str, findings: int
) -> None:
    env = Env(tmp_path)
    (env.repo / ".code-analyzer.yml").write_text(
        f'version: 1\npaths:\n  exclude: ["{exclude}"]\n'
        "licenses:\n  forbidden: []\n  require_approval: [GPL-3.0-only]\n"
    )
    bom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.7",
        "version": 1,
        "components": [component("vendor/poetry.lock")],
    }
    (env.plugin_out / "sbom.cdx.json").write_text(json.dumps(bom))
    syft = manifest(
        "syft",
        outputs={
            "cyclonedx": "/out/sbom.cdx.json",
            "cyclonedx_version": "1.7",
            "max_bytes": 1048576,
        },
    )
    assert env.scan(env.context(FakePluginExecutor({"syft": env.ok()}), [syft])) == 0
    report = json.loads((env.out / REPORT).read_text())
    assert len([f for f in report["findings"] if f["category"] == "license"]) == findings
