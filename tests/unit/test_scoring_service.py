"""K-05: contesto del servizio, precedenza per valore e fattore C (ADR-0028, ADR-0021)."""

import json

import pytest

from ca_core.models.config import Service
from ca_core.models.scan_report import ServiceContext, ServiceValue
from ca_core.models.scoring_config import ScoringConfig
from ca_core.models.service_context_file import ServiceContextFile
from ca_core.scoring.base import ScoringContext
from ca_core.scoring.config import default_bytes, load_default
from ca_core.scoring.service import DEFAULT_SERVICE, factor_c, resolve_service_context

CONFIG = load_default()


def file(**kv: object) -> ServiceContextFile:
    return ServiceContextFile(version=1, **kv)  # type: ignore[arg-type]


def codes(warnings: list) -> list[str]:
    return [w.code for w in warnings]


def test_nothing_declared_is_all_default_without_warnings() -> None:
    context, warnings = resolve_service_context(None, None)
    assert context == DEFAULT_SERVICE and warnings == []


def test_the_file_wins_and_is_marked_catalog() -> None:
    context, warnings = resolve_service_context(
        file(tier=1, internet_facing=True, catalog_id="a/b"), None
    )
    assert (context.tier.value, context.tier.source) == (1, "catalog")
    assert (context.internet_facing.value, context.internet_facing.source) == (True, "catalog")
    assert context.catalog_id == "a/b" and warnings == []


def test_the_service_block_is_a_declaration_and_says_so() -> None:
    context, warnings = resolve_service_context(None, Service(tier=2, internet_facing=False))
    assert (context.tier.source, context.internet_facing.source) == ("repository", "repository")
    assert codes(warnings) == ["service-from-repository"]


def test_precedence_is_per_value_not_per_source() -> None:
    context, warnings = resolve_service_context(file(tier=1), Service(tier=3, internet_facing=True))
    assert (context.tier.value, context.tier.source) == (1, "catalog")
    assert (context.internet_facing.value, context.internet_facing.source) == (True, "repository")
    assert codes(warnings) == ["service-config-ignored", "service-from-repository"]


def test_a_matching_service_block_is_not_reported_as_ignored() -> None:
    _, warnings = resolve_service_context(file(tier=2), Service(tier=2))
    assert warnings == []


def test_a_file_value_missing_leaves_the_default_when_nothing_else_says() -> None:
    context, _ = resolve_service_context(file(internet_facing=True), None)
    assert (context.tier.value, context.tier.source) == (None, "default")


def test_catalog_id_comes_from_the_file_then_the_block() -> None:
    assert (
        resolve_service_context(file(catalog_id="f"), Service(catalog_id="s"))[0].catalog_id == "f"
    )
    assert resolve_service_context(file(), Service(catalog_id="s"))[0].catalog_id == "s"


@pytest.mark.parametrize(("tier", "expected"), [(1, 1.0), (2, 0.7), (3, 0.4), (None, 0.7)])
def test_c_follows_the_tier_with_the_declared_default(tier: int | None, expected: float) -> None:
    service = ServiceContext(
        tier=ServiceValue(value=tier, source="catalog" if tier else "default"),
        internet_facing=ServiceValue(value=None, source="default"),
    )
    factor = factor_c(service, CONFIG)
    assert factor.value == expected
    assert factor.evidence == {
        "rule": "tier",
        "tier": tier,
        "source": "catalog" if tier else "default",
    }


def test_c_reads_every_value_from_the_configuration() -> None:
    data = json.loads(default_bytes())
    data["c"] = {"tier_1": 0.9, "tier_2": 0.6, "tier_3": 0.3, "missing": 0.5}
    other = ScoringConfig.model_validate(data)
    assert factor_c(DEFAULT_SERVICE, other).value == 0.5
    service = ServiceContext(
        tier=ServiceValue(value=3, source="catalog"),
        internet_facing=ServiceValue(value=None, source="default"),
    )
    assert factor_c(service, other).value == 0.3
    assert factor_c(service, CONFIG).value == 0.4


def test_the_scoring_context_defaults_to_the_default_service() -> None:
    assert ScoringContext(config=CONFIG).service == DEFAULT_SERVICE
