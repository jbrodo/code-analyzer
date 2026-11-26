"""K-03: fattore P della Variante A (ADR-0021, ADR-0024), valori attesi ricavati dall'ADR."""

import json
from datetime import date

import pytest
from builders import finding
from test_scoring_churn import graph

from ca_core.fakes import FakeEnrichmentFeeds
from ca_core.models.finding import Category
from ca_core.models.scoring_config import ScoringConfig
from ca_core.ports import FeedStatus, KevAnswer
from ca_core.scoring.base import ScoringContext
from ca_core.scoring.churn import ChurnIndex
from ca_core.scoring.config import default_bytes, load_default
from ca_core.scoring.variant_a import factor_p

CONFIG = load_default()
FOUND = KevAnswer(status=FeedStatus.FOUND, date_added=date(2024, 1, 1), ransomware_use="Known")


def dep(*cves: str):
    return finding("d", category=Category.DEPENDENCY, tool="osv-scanner").model_copy(
        update={"cve": list(cves)}
    )


def ctx(
    feeds: FakeEnrichmentFeeds | None, config: ScoringConfig = CONFIG, **kv: object
) -> ScoringContext:
    return ScoringContext(config=config, feeds=feeds, **kv)  # type: ignore[arg-type]


# --- dipendenze ---------------------------------------------------------------------------------


def test_kev_is_1_even_with_a_tiny_epss() -> None:
    feeds = FakeEnrichmentFeeds(epss={"CVE-2024-0001": (0.0001, 0.1)}, kev={"CVE-2024-0001": FOUND})
    factor = factor_p(dep("CVE-2024-0001"), ctx(feeds))
    assert factor.value == 1.0
    assert factor.evidence["cves"][0]["kev"] == {"status": "found", "date_added": "2024-01-01"}


@pytest.mark.parametrize(
    ("epss", "expected"),
    [(0.5, 0.5), (0.1, 0.1), (0.0001, 0.01), (0.0, 0.01), (1.0, 1.0)],
)
def test_epss_with_the_floor(epss: float, expected: float) -> None:
    feeds = FakeEnrichmentFeeds(epss={"CVE-2024-0001": (epss, 0.5)})
    assert factor_p(dep("CVE-2024-0001"), ctx(feeds)).value == expected


def test_a_cve_the_feed_does_not_list_gets_the_floor_not_the_missing_value() -> None:
    feeds = FakeEnrichmentFeeds(epss={"CVE-2024-0009": (0.5, 0.5)})
    factor = factor_p(dep("CVE-2024-0001"), ctx(feeds))
    assert factor.value == 0.01 and "fallback" not in factor.evidence
    assert factor.evidence["cves"][0]["epss"] == {"status": "not-listed"}


def test_without_any_snapshot_p_is_the_declared_constant_and_says_so() -> None:
    for feeds in (None, FakeEnrichmentFeeds(available=False)):
        factor = factor_p(dep("CVE-2024-0001"), ctx(feeds))
        assert factor.value == 0.1 and factor.evidence["fallback"] == "feed-assente"
        assert factor.evidence["cves"][0]["epss"]["status"] == "snapshot-absent"


def test_a_missing_feed_never_lowers_p_below_the_constant() -> None:
    class KevAbsent(FakeEnrichmentFeeds):
        def kev(self, cve: str) -> KevAnswer:
            return KevAnswer(status=FeedStatus.SNAPSHOT_ABSENT)

    feeds = KevAbsent(epss={"CVE-2024-0001": (0.02, 0.5)})
    factor = factor_p(dep("CVE-2024-0001"), ctx(feeds))
    assert factor.value == 0.1 and factor.evidence["fallback"] == "feed-assente"
    high = KevAbsent(epss={"CVE-2024-0001": (0.6, 0.5)})
    assert factor_p(dep("CVE-2024-0001"), ctx(high)).value == 0.6  # un EPSS alto resta alto


def test_several_cves_take_the_maximum_with_each_one_in_the_evidence() -> None:
    feeds = FakeEnrichmentFeeds(
        epss={"CVE-2024-0001": (0.2, 0.5), "CVE-2024-0002": (0.7, 0.9)},
        kev={"CVE-2024-0003": FOUND},
    )
    factor = factor_p(dep("CVE-2024-0002", "CVE-2024-0001"), ctx(feeds))
    assert factor.value == 0.7 and [c["cve"] for c in factor.evidence["cves"]] == [
        "CVE-2024-0001",
        "CVE-2024-0002",
    ]
    assert factor_p(dep("CVE-2024-0001", "CVE-2024-0003"), ctx(feeds)).value == 1.0


def test_a_dependency_without_a_cve_is_the_missing_constant_not_a_favourable_value() -> None:
    feeds = FakeEnrichmentFeeds(epss={"CVE-2024-0001": (0.9, 0.9)})
    factor = factor_p(dep("GHSA-xxxx-yyyy-zzzz"), ctx(feeds))
    assert factor.value == 0.1 and factor.evidence["fallback"] == "nessuna-cve"
    assert feeds.queries == []  # nessuna richiesta senza CVE valida


def test_only_valid_cves_are_looked_up() -> None:
    feeds = FakeEnrichmentFeeds()
    factor_p(dep("CVE-2024-0001", "not-a-cve", "cve-2024-2"), ctx(feeds))
    assert {q[1] for q in feeds.queries} == {"CVE-2024-0001"}


# --- SAST e categorie fisse -----------------------------------------------------------------------


def sast(**evidence: object):
    return finding("s", category=Category.SAST, tool="semgrep", evidence=dict(evidence))


def test_sast_path_is_confirmed_only_by_a_product_taint_result() -> None:
    assert factor_p(sast(path_confirmed=True), ctx(None)).value == 0.8
    assert factor_p(sast(), ctx(None)).value == 0.4
    assert factor_p(sast(path_confirmed=False), ctx(None)).value == 0.4
    assert factor_p(sast(path_confirmed="yes"), ctx(None)).value == 0.4  # non è un booleano vero


@pytest.mark.parametrize(
    ("category", "expected"),
    [
        (Category.IAC, 0.5),
        (Category.SECRET, 0.8),
        (Category.LICENSE, 1.0),
        (Category.HEALTH, 1.0),
    ],
)
def test_fixed_categories(category: Category, expected: float) -> None:
    assert factor_p(finding("x", category=category, tool="t"), ctx(None)).value == expected


# --- churn -------------------------------------------------------------------------------------


def quality(path: str = "a.py"):
    return finding("q", category=Category.QUALITY, tool="ruff", path=path)


def test_churn_percentile_is_p_with_the_floor() -> None:
    index = ChurnIndex(graph({"a.py": 0, "b.py": 1, "c.py": 2, "d.py": 3}))
    context = ctx(None, churn=index)
    assert factor_p(quality("d.py"), context).value == 0.75
    assert factor_p(quality("b.py"), context).value == 0.25
    assert factor_p(quality("a.py"), context).value == 0.1  # percentile 0 -> minimo
    assert factor_p(quality("d.py"), context).evidence["commits"] == 3


def test_unknown_churn_is_the_declared_constant_never_a_percentile() -> None:
    shallow = ChurnIndex(graph({"a.py": None}, status="superficiale"))
    for context in (ctx(None), ctx(None, churn=shallow)):
        factor = factor_p(quality(), context)
        assert factor.value == 0.3 and factor.evidence["fallback"] == "churn-ignoto"


def test_a_file_outside_the_graph_is_the_constant_with_its_own_reason() -> None:
    context = ctx(None, churn=ChurnIndex(graph({"a.py": 1})))
    factor = factor_p(quality("other.py"), context)
    assert factor.value == 0.3 and factor.evidence["fallback"] == "percorso-senza-churn"


def test_architecture_and_test_findings_use_churn_too() -> None:
    index = ChurnIndex(graph({"a.py": 0, "b.py": 5, "c.py": 9}))
    smell = finding("s", category=Category.ARCHITECTURE, tool="ca-graph").model_copy(
        update={"evidence": {"ca-graph": {"members": ["a.py", "c.py"], "size": 2}}}
    )
    assert factor_p(smell, ctx(None, churn=index)).value == pytest.approx(2 / 3)
    covered = finding("t", category=Category.TEST, tool="coverage", path="b.py")
    assert factor_p(covered, ctx(None, churn=index)).value == pytest.approx(1 / 3)


# --- configurazione ----------------------------------------------------------------------------


def test_every_value_comes_from_the_configuration() -> None:
    data = json.loads(default_bytes())
    data["p"].update(kev=0.9, epss_floor=0.05, feed_missing=0.2, iac=0.55, secret=0.7)
    data["p"]["sast"] = {"confirmed": 0.9, "unconfirmed": 0.3}
    data["p"]["churn"] = {"window_days": 90, "floor": 0.2, "unknown": 0.35}
    other = ScoringConfig.model_validate(data)
    feeds = FakeEnrichmentFeeds(epss={"CVE-2024-0001": (0.001, 0.1)}, kev={"CVE-2024-0002": FOUND})
    assert factor_p(dep("CVE-2024-0002"), ctx(feeds, other)).value == 0.9
    assert factor_p(dep("CVE-2024-0001"), ctx(feeds, other)).value == 0.05
    assert factor_p(dep("CVE-2024-0001"), ctx(None, other)).value == 0.2
    assert factor_p(sast(path_confirmed=True), ctx(None, other)).value == 0.9
    assert factor_p(quality(), ctx(None, other)).value == 0.35
    assert factor_p(finding("i", category=Category.IAC, tool="c"), ctx(None, other)).value == 0.55


def test_every_category_has_a_p() -> None:
    for category in Category:
        value = factor_p(finding("x", category=category, tool="t"), ctx(None)).value
        assert 0.0 <= value <= 1.0
