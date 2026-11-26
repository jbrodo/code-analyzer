"""F-04: lo snapshot ridotto di EPSS e KEV copre le fixture e si legge senza rete (ADR-0024)."""

import sys
from datetime import UTC, datetime
from pathlib import Path

import pytest
import yaml
from builders import finding

from ca_core.fakes import FixedClock
from ca_core.models.finding import Category
from ca_core.ports import FeedStatus
from ca_core.scoring.base import ScoringContext
from ca_core.scoring.config import load_default
from ca_core.scoring.variant_a import factor_p
from ca_plugins import enrichment as en

FEEDS_DIR = Path(__file__).parents[1] / "fixtures" / "feeds"
sys.path.insert(0, str(FEEDS_DIR))
import enrichment_snapshot as snap  # noqa: E402

REPOS = Path(__file__).parents[1] / "fixtures" / "repos"


def fixture_cves() -> set[str]:
    found: set[str] = set()
    for path in REPOS.glob("*/expected-findings.yaml"):
        for item in yaml.safe_load(path.read_text())["expected"]:
            if "cve" in item:
                found.add(item["cve"])
    return found


class NoNetwork:
    def fetch(self, url: str, *, max_bytes: int, gzip: bool, max_decompressed: int) -> bytes:
        raise AssertionError("lo snapshot di prova non deve usare la rete")


def test_every_fixture_cve_has_an_epss_score() -> None:
    feeds = snap.snapshot_feeds()
    cves = fixture_cves()
    assert len(cves) >= 10
    for cve in sorted(cves):
        assert feeds.epss(cve).status is FeedStatus.FOUND, cve


def test_the_fixture_cves_cover_both_sides_of_the_epss_threshold_and_kev() -> None:
    feeds = snap.snapshot_feeds()
    cves = fixture_cves()
    scores = {cve: feeds.epss(cve).score for cve in cves}
    assert any(s is not None and s >= snap.EPSS_THRESHOLD for s in scores.values())
    assert any(s is not None and s < snap.EPSS_THRESHOLD for s in scores.values())
    in_kev = {cve for cve in cves if feeds.kev(cve).status is FeedStatus.FOUND}
    assert in_kev == snap.SYNTHETIC_KEV  # le sole voci inventate, e dichiarate
    assert cves - in_kev  # e altre fuori dal catalogo


def test_real_control_entries_are_kept() -> None:
    feeds = snap.snapshot_feeds()
    assert feeds.kev("CVE-2021-44228").status is FeedStatus.FOUND
    assert feeds.kev("CVE-2020-8203").status is FeedStatus.NOT_LISTED
    assert feeds.epss("CVE-2099-0001").status is FeedStatus.NOT_LISTED


def test_the_production_limits_reject_the_reduced_snapshot() -> None:
    from ca_core.scoring.feeds.limits import load_limits
    from ca_core.scoring.feeds.parse import FeedRejected, parse_epss

    with pytest.raises(FeedRejected, match="epss-too-few"):
        parse_epss(snap.raw("epss"), load_limits().epss)


def test_the_seeded_cache_loads_offline_without_warnings(tmp_path: Path) -> None:
    now = datetime(2026, 11, 18, 0, 0, tzinfo=UTC)
    cache = tmp_path / "enrichment"
    snap.seed_cache(cache, downloaded_at=datetime(2026, 11, 17, 23, 37, tzinfo=UTC))
    result = en.load_enrichment(cache, NoNetwork(), FixedClock(now), limits=snap.LIMITS)
    assert result.warnings == []
    assert result.feeds.kev("CVE-2021-44906").status is FeedStatus.FOUND
    assert result.feeds.epss("CVE-2021-23337").score == 0.20158
    assert {s.feed for s in result.feeds.snapshots()} == {"epss", "kev"}


def test_an_old_seeded_cache_offline_is_stale_but_used(tmp_path: Path) -> None:
    cache = tmp_path / "enrichment"
    snap.seed_cache(cache, downloaded_at=datetime(2026, 11, 17, 23, 37, tzinfo=UTC))
    later = FixedClock(datetime(2026, 12, 1, tzinfo=UTC))
    result = en.load_enrichment(cache, NoNetwork(), later, offline=True, limits=snap.LIMITS)
    assert sorted((w.code, w.subject) for w in result.warnings) == [
        ("feeds-stale", "epss"),
        ("feeds-stale", "kev"),
    ]
    assert result.feeds.epss("CVE-2020-8203").status is FeedStatus.FOUND


@pytest.mark.parametrize(
    ("cve", "expected"),
    [
        ("CVE-2021-44906", 1.0),  # in KEV (voce di prova)
        ("CVE-2021-23337", 0.20158),  # EPSS sopra 0,1
        ("CVE-2024-29041", 0.01),  # EPSS sotto il minimo di P: 0,00786 -> 0,01
    ],
)
def test_factor_p_on_the_snapshot(cve: str, expected: float) -> None:
    dep = finding("d", category=Category.DEPENDENCY, tool="osv-scanner").model_copy(
        update={"cve": [cve]}
    )
    context = ScoringContext(config=load_default(), feeds=snap.snapshot_feeds())
    assert factor_p(dep, context).value == expected
