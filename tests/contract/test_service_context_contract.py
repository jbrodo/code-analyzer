"""`service-context`: file di contesto del servizio (ADR-0028, K-05)."""

import pytest
from conftest import Json, case_params, errors_of, make_validator, mutated

VALIDATOR = make_validator("service-context")
MINIMAL: Json = {"version": 1}
FULL: Json = {
    "version": 1,
    "tier": 2,
    "internet_facing": True,
    "catalog_id": "payments/api",
    "origin": "catalogo interno",
}

VALID = {
    "minimal": MINIMAL,
    "full": FULL,
    "tier-1": mutated(FULL, lambda i: i.update(tier=1)),
    "tier-3-internal": mutated(FULL, lambda i: i.update(tier=3, internet_facing=False)),
    "only-exposure": {"version": 1, "internet_facing": False},
    "nulls": {"version": 1, "tier": None, "internet_facing": None, "catalog_id": None},
}

INVALID = {
    "empty": {},
    "no-version": {"tier": 1},
    "version-2": mutated(MINIMAL, lambda i: i.update(version=2)),
    "version-true": mutated(MINIMAL, lambda i: i.update(version=True)),
    "unknown-key": mutated(FULL, lambda i: i.update(owner="x")),
    "tier-0": mutated(FULL, lambda i: i.update(tier=0)),
    "tier-4": mutated(FULL, lambda i: i.update(tier=4)),
    "tier-string": mutated(FULL, lambda i: i.update(tier="1")),
    "tier-true": mutated(FULL, lambda i: i.update(tier=True)),
    "exposure-string": mutated(FULL, lambda i: i.update(internet_facing="yes")),
    "exposure-int": mutated(FULL, lambda i: i.update(internet_facing=1)),
    "catalog-too-long": mutated(FULL, lambda i: i.update(catalog_id="x" * 201)),
    "catalog-newline": mutated(FULL, lambda i: i.update(catalog_id="a\n::error::b")),
    "origin-escape": mutated(FULL, lambda i: i.update(origin="a\x1b[31m")),
}


@pytest.mark.parametrize("instance", case_params(VALID, "valid:"))
def test_valid_instances_pass(instance: Json) -> None:
    assert errors_of(VALIDATOR, instance) == []


@pytest.mark.parametrize("instance", case_params(INVALID, "invalid:"))
def test_invalid_instances_are_rejected(instance: Json) -> None:
    assert errors_of(VALIDATOR, instance) != []
