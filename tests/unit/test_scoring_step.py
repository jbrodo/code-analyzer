"""K-11, K-13, K-14: override, le due varianti in ombra e il passo `score` (ADR-0021, D2-10)."""

import json
from datetime import date

import pytest
from builders import finding
from test_scoring_churn import graph
from test_scoring_exposure import Fake, service

from ca_core.fakes import FakeEnrichmentFeeds
from ca_core.models.finding import Category, Finding, Level, LevelSource, Location
from ca_core.models.scoring_config import ScoringConfig
from ca_core.ports import FeedStatus, KevAnswer
from ca_core.scoring import overrides as ov
from ca_core.scoring.base import ScoringContext
from ca_core.scoring.churn import ChurnIndex
from ca_core.scoring.config import config_version, default_bytes, load_default
from ca_core.scoring.models import B_UNDEFINED
from ca_core.scoring.reach import ReachResult, ReachState
from ca_core.scoring.score import score_finding, score_findings

R, T, N, U = (
    ReachState.REACHABLE,
    ReachState.TEST_ONLY,
    ReachState.NOT_REACHABLE,
    ReachState.UNKNOWN,
)
CONFIG = load_default()
KEV = KevAnswer(status=FeedStatus.FOUND, date_added=date(2024, 1, 1), ransomware_use="Unknown")


def with_source(source: str) -> ScoringConfig:
    data = json.loads(default_bytes())
    data["levels"]["source"] = source
    return ScoringConfig.model_validate(data)


def ctx(config: ScoringConfig = CONFIG, **kv: object) -> ScoringContext:
    return ScoringContext(config=config, **kv)  # type: ignore[arg-type]


def dependency(*cves: str, cvss: float = 9.8):
    return finding(
        "d",
        category=Category.DEPENDENCY,
        tool="osv-scanner",
        evidence={"cvss": {"score": cvss, "version": "3.1"}},
    ).model_copy(
        update={
            "cve": list(cves),
            "location": Location(
                repository="repo", path="requirements.txt", purl="pkg:pypi/django@3.2"
            ),
        }
    )


def reach_django(state: ReachState) -> Fake:
    return Fake(dependencies={("pypi", "django"): ReachResult(state, entrypoint="m.py")})


# --- override ---------------------------------------------------------------------------------


def names(found: list[ov.Override]) -> list[str]:
    return [o.name for o in found]


def test_kev_and_reachable_forces_critical() -> None:
    feeds = FakeEnrichmentFeeds(kev={"CVE-2024-0001": KEV})
    found = ov.applicable_overrides(
        dependency("CVE-2024-0001"), ctx(feeds=feeds, reachability=reach_django(R))
    )
    assert names(found) == [ov.KEV_REACHABLE] and found[0].level is Level.CRITICAL


@pytest.mark.parametrize("state", [U, T, N])
def test_kev_without_proven_reachability_does_not_force_anything(state: ReachState) -> None:
    feeds = FakeEnrichmentFeeds(kev={"CVE-2024-0001": KEV})
    context = ctx(feeds=feeds, reachability=reach_django(state))
    assert ov.applicable_overrides(dependency("CVE-2024-0001"), context) == []


def test_epss_at_least_the_threshold_and_reachable_forces_high() -> None:
    reach = reach_django(R)
    at = FakeEnrichmentFeeds(epss={"CVE-2024-0001": (0.1, 0.5)})
    below = FakeEnrichmentFeeds(epss={"CVE-2024-0001": (0.099, 0.5)})
    assert names(
        ov.applicable_overrides(dependency("CVE-2024-0001"), ctx(feeds=at, reachability=reach))
    ) == [ov.EPSS_REACHABLE]
    assert (
        ov.applicable_overrides(dependency("CVE-2024-0001"), ctx(feeds=below, reachability=reach))
        == []
    )


def test_no_feeds_or_no_cve_means_no_dependency_override() -> None:
    reach = reach_django(R)
    assert ov.applicable_overrides(dependency("CVE-2024-0001"), ctx(reachability=reach)) == []
    feeds = FakeEnrichmentFeeds(kev={"CVE-2024-0001": KEV})
    assert ov.applicable_overrides(dependency(), ctx(feeds=feeds, reachability=reach)) == []
    assert (
        ov.applicable_overrides(dependency("GHSA-x-y-z"), ctx(feeds=feeds, reachability=reach))
        == []
    )


def test_kev_and_epss_together_floor_to_the_most_severe() -> None:
    feeds = FakeEnrichmentFeeds(epss={"CVE-2024-0001": (0.9, 0.9)}, kev={"CVE-2024-0001": KEV})
    context = ctx(feeds=feeds, reachability=reach_django(R))
    assert names(ov.applicable_overrides(dependency("CVE-2024-0001"), context)) == [
        ov.KEV_REACHABLE,
        ov.EPSS_REACHABLE,
    ]
    assert ov.floor_of(dependency("CVE-2024-0001"), context).level is Level.CRITICAL  # type: ignore[union-attr]


def license_finding(verdict: str, distributed: object):
    return finding(
        "l",
        category=Category.LICENSE,
        tool="ca-core",
        evidence={"verdict": verdict, "distributed": distributed},
    )


def test_forbidden_license_in_a_distributed_product_is_critical() -> None:
    assert names(ov.applicable_overrides(license_finding("forbidden", True), ctx())) == [
        ov.LICENSE_FORBIDDEN_DISTRIBUTED
    ]
    for case in (("forbidden", False), ("approval", True), ("unknown", True)):
        assert ov.applicable_overrides(license_finding(*case), ctx()) == []


def sast(confirmed: object = True):
    return finding(
        "s", category=Category.SAST, tool="semgrep", evidence={"path_confirmed": confirmed}
    )


@pytest.mark.parametrize(
    ("confirmed", "exposed", "source", "applies"),
    [
        (True, True, "catalog", True),
        (True, True, "repository", True),
        (True, True, "default", False),
        (True, False, "catalog", False),
        (True, None, "default", False),
        (False, True, "catalog", False),
    ],
)
def test_confirmed_sast_in_a_declared_exposed_service(
    confirmed: bool, exposed: bool | None, source: str, applies: bool
) -> None:
    found = ov.applicable_overrides(sast(confirmed), ctx(service=service(exposed, source)))
    assert (names(found) == [ov.SAST_CONFIRMED_EXPOSED]) is applies
    if applies:
        assert found[0].level is Level.HIGH


def index() -> ChurnIndex:
    return ChurnIndex(graph({f"f{i}.py": i for i in range(10)}))  # percentili 0,0 .. 0,9


def smell(path: str):
    return finding("s", category=Category.ARCHITECTURE, tool="ca-graph", path=path)


def test_architecture_smell_in_a_hotspot_is_at_least_medium() -> None:
    assert names(ov.applicable_overrides(smell("f9.py"), ctx(churn=index()))) == [
        ov.ARCHITECTURE_HOTSPOT
    ]
    assert ov.applicable_overrides(smell("f8.py"), ctx(churn=index())) == []  # 80° percentile
    assert ov.applicable_overrides(smell("f9.py"), ctx()) == []  # churn ignoto
    shallow = ChurnIndex(graph({"f9.py": None}, status="superficiale"))
    assert ov.applicable_overrides(smell("f9.py"), ctx(churn=shallow)) == []


def coverage(value: int, path: str = "f9.py"):
    return finding(
        "c", category=Category.TEST, tool="coverage", path=path,
        evidence={"metric": {"value": value, "threshold": 50}},
    )  # fmt: skip


def covered_context(state: ReachState = R) -> ScoringContext:
    return ctx(churn=index(), reachability=Fake(modules={"f9.py": ReachResult(state)}))


def test_low_coverage_on_reachable_code_changed_often_is_at_least_medium() -> None:
    assert names(ov.applicable_overrides(coverage(49), covered_context())) == [
        ov.LOW_COVERAGE_CRITICAL_CODE
    ]
    assert ov.applicable_overrides(coverage(50), covered_context()) == []  # non sotto il 50%
    assert ov.applicable_overrides(coverage(10), covered_context(U)) == []
    assert (
        ov.applicable_overrides(coverage(10, "f1.py"), covered_context()) == []
    )  # poco modificato


def test_there_is_no_valid_secret_override_to_apply() -> None:
    secret = finding("k", category=Category.SECRET, tool="gitleaks", evidence={"validity": "valid"})
    assert ov.applicable_overrides(secret, ctx(service=service(True))) == []
    fields = type(CONFIG.overrides).model_fields
    assert not any("secret" in name or "valid" in name for name in fields)


# --- le due varianti e il passo ---------------------------------------------------------------


def full_context(config: ScoringConfig = CONFIG) -> ScoringContext:
    feeds = FakeEnrichmentFeeds(epss={"CVE-2024-0001": (0.5, 0.9)})
    tier1 = service(True)
    tier1 = tier1.model_copy(
        update={"tier": tier1.tier.model_copy(update={"value": 1, "source": "catalog"})}
    )
    return ScoringContext(config=config, service=tier1, reachability=reach_django(R), feeds=feeds)


def test_both_variants_are_always_computed_with_the_adr_example() -> None:
    scored = score_finding(dependency("CVE-2024-0001"), full_context(), "A")
    a, b = scored.variant_scores
    assert (a.variant, b.variant) == ("A", "B")
    assert a.score == b.score == 49.0 and a.level is b.level is Level.HIGH  # ADR-0021, riga 1
    assert (a.impact.g, a.impact.p, a.impact.e, a.impact.c) == (0.98, 0.5, 1.0, 1.0)
    assert scored.score == 49.0 and scored.impact == a.impact


def test_the_provisional_level_stays_until_the_config_says_score() -> None:
    base = dependency("CVE-2024-0001").model_copy(
        update={"level": Level.CRITICAL, "level_source": LevelSource.TOOL_SEVERITY}
    )
    kept = score_finding(base, full_context(), "A")
    assert (kept.level, kept.level_source) == (Level.CRITICAL, LevelSource.TOOL_SEVERITY)
    assert kept.variant_scores[0].level is Level.HIGH  # il livello da punteggio è solo in ombra
    active = score_finding(base, full_context(with_source("score")), "A")
    assert (active.level, active.level_source) == (Level.HIGH, LevelSource.SCORE)


def test_an_override_raises_the_level_and_is_recorded_as_such() -> None:
    feeds = FakeEnrichmentFeeds(epss={"CVE-2024-0001": (0.5, 0.9)}, kev={"CVE-2024-0001": KEV})
    base = ScoringContext(config=with_source("score"), reachability=reach_django(R), feeds=feeds)
    scored = score_finding(dependency("CVE-2024-0001"), base, "A")
    assert scored.level is Level.CRITICAL and scored.level_source is LevelSource.OVERRIDE
    assert scored.variant_scores[0].impact.evidence["override"]["name"] == ov.KEV_REACHABLE
    assert scored.score < 70  # il punteggio non cambia: l'override è un'etichetta


def test_an_override_never_lowers_a_level() -> None:
    feeds = FakeEnrichmentFeeds(
        epss={"CVE-2024-0001": (0.9, 0.9)}
    )  # EPSS alto e raggiungibile: alto

    def level_with(thresholds: dict[str, float]) -> Finding:
        data = json.loads(default_bytes())
        data["levels"]["source"] = "score"
        data["levels"]["thresholds"] = thresholds
        context = ScoringContext(
            config=ScoringConfig.model_validate(data), reachability=reach_django(R), feeds=feeds
        )
        return score_finding(dependency("CVE-2024-0001"), context, "A")  # punteggio 37,04

    raised = level_with({"critico": 70.0, "alto": 40.0, "medio": 15.0})  # medio: alzato ad alto
    assert (raised.level, raised.level_source) == (Level.HIGH, LevelSource.OVERRIDE)
    above = level_with({"critico": 30.0, "alto": 20.0, "medio": 10.0})  # già critico: resta
    assert (above.level, above.level_source) == (Level.CRITICAL, LevelSource.SCORE)


def test_variant_b_equals_a_on_quality_and_architecture_and_says_so() -> None:
    quality = finding("q", category=Category.QUALITY, tool="ruff")
    a, b = score_finding(quality, ctx(), "A").variant_scores
    assert a.score == b.score
    assert B_UNDEFINED in b.impact.evidence["fallbacks"]
    assert B_UNDEFINED not in a.impact.evidence.get("fallbacks", [])
    secret = finding("k", category=Category.SECRET, tool="gitleaks")
    assert B_UNDEFINED not in score_finding(secret, ctx(), "A").variant_scores[
        1
    ].impact.evidence.get("fallbacks", [])


def test_the_active_variant_decides_score_and_impact_not_the_other_one() -> None:
    quality = finding("q", category=Category.QUALITY, tool="ruff")
    chosen = score_finding(quality, ctx(), "B")
    assert chosen.impact is not None and chosen.impact.variant == "B"


def test_scoring_is_idempotent_and_deterministic() -> None:
    items = [dependency("CVE-2024-0001"), finding("a", category=Category.SECRET, tool="gitleaks")]
    first = score_findings(items, full_context(), active_variant="A", config_version="1+x")
    second = score_findings(
        first.findings, full_context(), active_variant="A", config_version="1+x"
    )
    assert first.findings == second.findings
    reversed_ = score_findings(
        items[::-1], full_context(), active_variant="A", config_version="1+x"
    )
    assert [f.fingerprint for f in reversed_.findings] == [f.fingerprint for f in first.findings]


def test_the_order_is_level_then_score_then_category_then_fingerprint() -> None:
    low = finding("1", category=Category.SECRET, tool="gitleaks", level=Level.HIGH)
    high = finding("2", category=Category.SECRET, tool="gitleaks", level=Level.HIGH)
    low = low.model_copy(update={"score": 10.0})
    high = high.model_copy(update={"score": 60.0})
    critical = finding("3", category=Category.SECRET, tool="gitleaks", level=Level.CRITICAL)
    from ca_core.scoring.score import sort_scored

    assert [f.fingerprint for f in sort_scored([low, high, critical])] == [
        critical.fingerprint,
        high.fingerprint,
        low.fingerprint,
    ]


def test_the_result_carries_scoring_info_and_counts_fallbacks() -> None:
    items = [dependency("CVE-2024-0001"), finding("a", category=Category.SECRET, tool="gitleaks")]
    result = score_findings(items, ctx(), active_variant="B", config_version=config_version(CONFIG))
    assert result.info.active_variant == "B" and result.info.shadow is True
    assert result.info.config_version == config_version(CONFIG)
    assert result.with_fallback == 1  # la dipendenza senza feed né grafo
