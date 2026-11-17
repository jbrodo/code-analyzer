"""K-01, K-02, K-12: interfaccia, G della Variante A e livelli da punteggio (casi di F-05)."""

import json
from datetime import date
from pathlib import Path
from typing import Any

import pytest
from builders import finding
from test_scoring_exposure import Fake

from ca_core.fakes import FakeEnrichmentFeeds
from ca_core.models.finding import Category, Level, Location
from ca_core.models.scan_report import ServiceContext, ServiceValue
from ca_core.models.scoring_config import ScoringConfig
from ca_core.ports import FeedStatus, KevAnswer
from ca_core.scoring.base import Factor, ScoringContext, impact, round_score
from ca_core.scoring.config import (
    ScoringConfigError,
    default_bytes,
    load_default,
    resolve_config,
)
from ca_core.scoring.exposure import factor_e
from ca_core.scoring.levels import best_cvss_entry, level_from_score
from ca_core.scoring.overrides import applicable_overrides, floor_of
from ca_core.scoring.reach import ReachResult, ReachState
from ca_core.scoring.service import factor_c
from ca_core.scoring.variant_a import factor_g, factor_p

CASES: dict[str, Any] = json.loads(
    (Path(__file__).resolve().parents[1] / "fixtures/scoring/cases.json").read_text()
)
CONFIG = load_default()


def build(case: dict[str, Any]):
    category = Category(case["category"])
    f = finding("x", category=category, tool=case["tool"], evidence=case["evidence"])
    second = case.get("second")
    if second:
        f = f.model_copy(
            update={
                "tools": sorted([f.tool, second["tool"]]),
                "evidence": {**f.evidence, second["tool"]: second["evidence"]},
            }
        )
        f = f.model_copy(update={"tool": f.tools[0]})
    return f


@pytest.mark.parametrize("case", CASES["g"], ids=[c["name"] for c in CASES["g"]])
def test_g_matches_the_hand_derived_table(case: dict[str, Any]) -> None:
    factor = factor_g(build(case), CONFIG)
    assert factor.value == pytest.approx(case["expected"], abs=1e-9)
    if "fallback" in case:
        assert factor.evidence["fallback"] == case["fallback"]
    else:
        assert "fallback" not in factor.evidence


def test_g_cvss_evidence_records_the_version_used() -> None:
    case = next(c for c in CASES["g"] if c["name"] == "cvss-v4-wins-over-v3")
    assert factor_g(build(case), CONFIG).evidence["cvss"] == {"score": 8.0, "version": "4.0"}


def test_g_reads_every_value_from_the_configuration() -> None:
    data = json.loads(default_bytes())
    data["g"]["secret"] = 0.4
    data["g"]["severity"]["missing"] = 0.45
    other = ScoringConfig.model_validate(data)
    secret = finding("s", category=Category.SECRET, tool="gitleaks")
    code = finding("c", category=Category.SAST)
    assert factor_g(secret, other).value == 0.4
    assert factor_g(code, other).value == 0.45
    assert factor_g(secret, CONFIG).value == 0.75  # il predefinito non è cambiato


def test_every_category_has_a_g() -> None:
    for category in Category:
        f = finding("x", category=category, tool="t")
        assert 0.0 <= factor_g(f, CONFIG).value <= 1.0


# --- punteggio e livelli ---------------------------------------------------------------------


@pytest.mark.parametrize("case", CASES["impact"], ids=[c["name"] for c in CASES["impact"]])
def test_impact_and_level_match_the_adr_table(case: dict[str, Any]) -> None:
    score = impact(case["g"], case["p"], case["e"], case["c"])
    assert score == pytest.approx(case["score"], abs=1e-9)
    assert level_from_score(score, CONFIG.levels.thresholds).value == case["level"]


@pytest.mark.parametrize("case", CASES["edges"], ids=[str(c["score"]) for c in CASES["edges"]])
def test_level_edges_are_half_open_and_rounded_before_comparing(case: dict[str, Any]) -> None:
    assert level_from_score(case["score"], CONFIG.levels.thresholds).value == case["level"]


def test_thresholds_come_from_the_configuration() -> None:
    data = json.loads(default_bytes())
    data["levels"]["thresholds"] = {"critico": 90.0, "alto": 60.0, "medio": 30.0}
    other = ScoringConfig.model_validate(data)
    assert level_from_score(69.0, other.levels.thresholds) is Level.HIGH
    assert level_from_score(69.0, CONFIG.levels.thresholds) is Level.HIGH
    assert level_from_score(75.0, other.levels.thresholds) is Level.HIGH
    assert level_from_score(75.0, CONFIG.levels.thresholds) is Level.CRITICAL
    assert level_from_score(35.0, other.levels.thresholds) is Level.MEDIUM


def test_round_score_is_half_up_on_the_decimal_representation() -> None:
    assert round_score(69.995) == 70.0 and round_score(14.994) == 14.99
    assert round_score(0.125) == 0.13


@pytest.mark.parametrize("bad", [-0.1, 1.1, True])
def test_factors_outside_the_unit_interval_are_errors_not_clamped(bad: float) -> None:
    with pytest.raises(ValueError, match=r"\[0,1\]"):
        impact(bad, 1.0, 1.0, 1.0)
    with pytest.raises(ValueError, match=r"\[0,1\]"):
        Factor(bad)


def test_best_cvss_entry_prefers_the_newest_version_then_the_highest_score() -> None:
    f = finding(
        "x",
        category=Category.DEPENDENCY,
        tool="osv-scanner",
        evidence={"cvss": {"score": 7.0, "version": "3.1"}},
    )
    assert best_cvss_entry(f) == (7.0, "3.1")


# --- configurazione effettiva ----------------------------------------------------------------


def test_the_flag_wins_over_the_tenant_which_wins_over_the_package() -> None:
    def blob(variant: str) -> bytes:
        data = json.loads(default_bytes())
        data["variant"] = variant
        return json.dumps(data).encode()

    assert resolve_config().variant == "A"
    assert resolve_config(tenant=blob("B")).variant == "B"
    assert resolve_config(flag=blob("B"), tenant=blob("A")).variant == "B"
    assert resolve_config(flag=blob("A"), tenant=blob("B")).variant == "A"


def test_an_invalid_override_is_an_error_never_a_silent_fallback_to_the_default() -> None:
    with pytest.raises(ScoringConfigError):
        resolve_config(flag=b"{}")
    with pytest.raises(ScoringConfigError):
        resolve_config(tenant=b"{")


# --- F-05: P, E, C e override, dalla tabella di ADR-0021 e ADR-0022 ----------------------------


def _dep_with(cve: str = "CVE-2024-0001"):
    return finding("d", category=Category.DEPENDENCY, tool="osv-scanner").model_copy(
        update={
            "cve": [cve],
            "location": Location(
                repository="repo", path="requirements.txt", purl="pkg:pypi/django@3.2"
            ),
        }
    )


def _feeds(case: dict[str, Any]) -> FakeEnrichmentFeeds | None:
    if not case["feeds"]:
        return None
    kev = {"CVE-2024-0001": KevAnswer(status=FeedStatus.FOUND, date_added=date(2024, 1, 1))}
    epss = {} if case["epss"] is None else {"CVE-2024-0001": (case["epss"], 0.5)}
    return FakeEnrichmentFeeds(epss=epss, kev=kev if case["kev"] else {})


@pytest.mark.parametrize("case", CASES["p"], ids=[c["name"] for c in CASES["p"]])
def test_p_matches_the_hand_derived_table(case: dict[str, Any]) -> None:
    factor = factor_p(_dep_with(), ScoringContext(config=CONFIG, feeds=_feeds(case)))
    assert factor.value == pytest.approx(case["expected"], abs=1e-9)
    assert factor.evidence.get("fallback") == case.get("fallback")


@pytest.mark.parametrize("case", CASES["e"], ids=[c["name"] for c in CASES["e"]])
def test_e_matches_the_hand_derived_table(case: dict[str, Any]) -> None:
    reach = Fake(modules={"app/x.py": ReachResult(ReachState(case["state"]))})
    exposure = ServiceValue(
        value=case["exposed"], source="catalog" if case["exposed"] is not None else "default"
    )
    context = ScoringContext(
        config=CONFIG,
        reachability=reach,
        service=ServiceContext(
            tier=ServiceValue(value=None, source="default"), internet_facing=exposure
        ),
    )
    f = finding("x", category=Category.SAST, path="app/x.py")
    assert factor_e(f, context).value == case["expected"]


@pytest.mark.parametrize("case", CASES["c"], ids=[c["name"] for c in CASES["c"]])
def test_c_matches_the_hand_derived_table(case: dict[str, Any]) -> None:
    service = ServiceContext(
        tier=ServiceValue(value=case["tier"], source="catalog" if case["tier"] else "default"),
        internet_facing=ServiceValue(value=None, source="default"),
    )
    assert factor_c(service, CONFIG).value == case["expected"]


@pytest.mark.parametrize("case", CASES["override"], ids=[c["name"] for c in CASES["override"]])
def test_overrides_match_the_hand_derived_table(case: dict[str, Any]) -> None:
    kev = {"CVE-2024-0001": KevAnswer(status=FeedStatus.FOUND, date_added=date(2024, 1, 1))}
    epss = {} if case["kind"] == "kev" else {"CVE-2024-0001": (case["value"], 0.5)}
    feeds = FakeEnrichmentFeeds(epss=epss, kev=kev if case["kind"] in ("kev", "both") else {})
    reach = Fake(dependencies={("pypi", "django"): ReachResult(ReachState(case["reach"]))})
    context = ScoringContext(config=CONFIG, feeds=feeds, reachability=reach)
    found = applicable_overrides(_dep_with(), context)
    assert [o.name for o in found] == case["expected"]
    floor = floor_of(_dep_with(), context)
    assert (floor.level.value if floor else None) == case["floor"]
