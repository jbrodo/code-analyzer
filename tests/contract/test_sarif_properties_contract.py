"""`plugin-sarif-properties`: proprietà SARIF scritte dagli adattatori (ADR-0007)."""

import pytest
from conftest import errors_of, make_validator

VALIDATOR = make_validator("plugin-sarif-properties")

VALID = {
    "empty": {},
    "aliases": {"aliases": ["CVE-2024-1", "GHSA-xxxx"]},
    "aliases-empty": {"aliases": []},
    "cvss": {"cvss": {"version": "3.1", "vector": "CVSS:3.1/AV:N", "score": 9.8}},
    "cvss-null": {"cvss": None},
    "cvss-score-bounds-0": {"cvss": {"version": "2.0", "vector": "v", "score": 0}},
    "cvss-score-bounds-10": {"cvss": {"version": "4.0", "vector": "v", "score": 10}},
    "tool-severity": {"tool_severity": "HIGH"},
    "license": {"license_spdx": "MIT OR Apache-2.0"},
    "purl": {"purl": "pkg:pypi/requests@2.0"},
    "purl-null": {"purl": None},
    "category": {"category": "dependency"},
    "category-null": {"category": None},
    "secret-sha256": {"secret_sha256": "a" * 64},
    "all": {
        "aliases": ["a"],
        "cvss": {"version": "3.0", "vector": "v", "score": 1.5},
        "tool_severity": "s",
        "license_spdx": "MIT",
        "purl": "pkg:npm/%40a/b@1",
    },
}
INVALID = {
    "scanner-key-security-severity": {"security-severity": "7.5"},
    "scanner-key-tags": {"tags": ["x"]},
    "unknown-key": {"anything": {"a": 1}},
    "category-unknown": {"category": "other"},
    "category-not-string": {"category": 1},
    "secret-sha256-uppercase": {"secret_sha256": "A" * 64},
    "secret-sha256-short": {"secret_sha256": "a" * 63},
    "secret-sha256-long": {"secret_sha256": "a" * 65},
    "secret-sha256-not-hex": {"secret_sha256": "g" * 64},
    "aliases-duplicates": {"aliases": ["a", "a"]},
    "aliases-empty-string": {"aliases": [""]},
    "aliases-too-long": {"aliases": ["a" * 257]},
    "aliases-not-array": {"aliases": "CVE-1"},
    "cvss-missing-score": {"cvss": {"version": "3.1", "vector": "v"}},
    "cvss-missing-vector": {"cvss": {"version": "3.1", "score": 1}},
    "cvss-missing-version": {"cvss": {"vector": "v", "score": 1}},
    "cvss-version-unknown": {"cvss": {"version": "3.2", "vector": "v", "score": 1}},
    "cvss-version-prefix-match": {"cvss": {"version": "3.1x", "vector": "v", "score": 1}},
    "cvss-score-above-10": {"cvss": {"version": "3.1", "vector": "v", "score": 10.1}},
    "cvss-score-negative": {"cvss": {"version": "3.1", "vector": "v", "score": -0.1}},
    "cvss-score-string": {"cvss": {"version": "3.1", "vector": "v", "score": "9"}},
    "cvss-empty-vector": {"cvss": {"version": "3.1", "vector": "", "score": 1}},
    "cvss-vector-too-long": {"cvss": {"version": "3.1", "vector": "v" * 257, "score": 1}},
    "cvss-unknown-key": {"cvss": {"version": "3.1", "vector": "v", "score": 1, "x": 1}},
    "tool-severity-empty": {"tool_severity": ""},
    "tool-severity-too-long": {"tool_severity": "s" * 257},
    "license-empty": {"license_spdx": ""},
    "purl-no-scheme": {"purl": "requests@2.0"},
    "purl-uppercase-type": {"purl": "pkg:PyPI/requests"},
    "purl-empty-name": {"purl": "pkg:pypi/"},
    "purl-whitespace": {"purl": "pkg:pypi/a b"},
    "purl-too-long": {"purl": "pkg:pypi/" + "a" * 2048},
    "purl-not-string": {"purl": 1},
}


@pytest.mark.parametrize("instance", VALID.values(), ids=VALID.keys())
def test_valid_properties_are_accepted(instance: dict) -> None:
    assert errors_of(VALIDATOR, instance) == []


@pytest.mark.parametrize("instance", INVALID.values(), ids=INVALID.keys())
def test_invalid_properties_are_rejected(instance: dict) -> None:
    assert errors_of(VALIDATOR, instance) != []


def test_non_object_is_rejected() -> None:
    assert errors_of(VALIDATOR, ["aliases"]) != []
