"""K-06: licenze dichiarate da SBOM."""

import json
from pathlib import Path

import pytest

from ca_core.normalize import DeclaredLicense, declared_licenses

SAMPLES = Path(__file__).resolve().parents[1] / "fixtures" / "plugin-output"


def doc(*components: dict[str, object]) -> dict[str, object]:
    return {"components": list(components)}


def lic(**kv: str) -> list[dict[str, object]]:
    return [{"license": kv}]


@pytest.mark.parametrize(
    ("licenses", "expected"),
    [
        (lic(id="MIT"), "MIT"),
        ([{"expression": "MIT OR Apache-2.0"}], "MIT OR Apache-2.0"),
        (lic(id="NOASSERTION"), "NOASSERTION"),
        (lic(id="LicenseRef-acme"), "LicenseRef-acme"),
        (lic(name="NOASSERTION"), "NOASSERTION"),
        (lic(name="Acme EULA 1.0"), "LicenseRef-Acme-EULA-1.0"),
        (lic(name="!!!"), "LicenseRef-unnamed"),
        ([*lic(id="MIT"), *lic(id="Apache-2.0")], "MIT AND Apache-2.0"),
        ([*lic(id="MIT"), {"expression": "A OR B"}], "MIT AND (A OR B)"),
        ([], None),
        ([{"license": {}}], None),
    ],
)
def test_expression_of_declared_license(licenses: list[object], expected: str | None) -> None:
    [item] = declared_licenses(doc({"name": "x", "purl": "pkg:npm/x@1", "licenses": licenses}))

    assert item == DeclaredLicense("x", "pkg:npm/x@1", expected)


def test_missing_licenses_key_and_missing_purl() -> None:
    items = declared_licenses(doc({"name": "a"}, {"name": "b", "purl": "pkg:npm/b@1"}))

    assert [(i.name, i.purl, i.expression) for i in items] == [
        ("a", None, None),
        ("b", "pkg:npm/b@1", None),
    ]


def test_nested_components_are_visited_in_document_order() -> None:
    items = declared_licenses(
        doc(
            {"name": "a", "components": [{"name": "a1", "components": [{"name": "a11"}]}]},
            {"name": "b"},
        )
    )

    assert [i.name for i in items] == ["a", "a1", "a11", "b"]


def test_document_without_components_is_empty() -> None:
    assert declared_licenses({}) == []


@pytest.mark.parametrize("sample", sorted(SAMPLES.glob("*.cdx.json")), ids=lambda p: p.name)
def test_real_samples_yield_purl_and_license(sample: Path) -> None:
    items = declared_licenses(json.loads(sample.read_bytes()))

    assert ("lodash", "pkg:npm/lodash@4.17.15", "MIT") in [
        (i.name, i.purl, i.expression) for i in items
    ]
