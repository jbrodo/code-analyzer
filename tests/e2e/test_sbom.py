"""L-03: `code-analyzer sbom` con immagine firmata di syft e CLI vera."""

import json
from pathlib import Path

from .e2e_lab import Fleet, copy_fixture, e2e_marks

pytestmark = e2e_marks


def test_sbom_of_a_fixture_is_cyclonedx_17_with_its_components(fleet: Fleet, work: Path) -> None:
    fleet.add_builtin("syft")
    root = copy_fixture("python-app", work / "sbom")
    target = work / "sbom-out" / "bom.cdx.json"
    result = fleet.run(
        root.parent, "sbom", str(root), "--output", str(target), plugins=["syft"]
    )  # fmt: skip
    assert result.returncode == 0, result.stderr[-2000:]
    document = json.loads(target.read_text())
    assert (document["bomFormat"], document["specVersion"]) == ("CycloneDX", "1.7")
    assert any(c.get("purl", "").startswith("pkg:pypi/") for c in document["components"])
