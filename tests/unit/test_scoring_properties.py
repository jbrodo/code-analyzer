"""T-01 (ADR-0021): proprietà del punteggio e dei livelli, per qualunque valore dei fattori.

La tabella dei casi di F-05 sta in `tests/unit/test_scoring_variant_a.py`; qui si provano le
proprietà che nessuna tabella può esaurire: limiti, monotonia, intervalli semiaperti, arrotondamento
prima del confronto e determinismo dell'ordinamento.
"""

import random
from decimal import Decimal

from builders import finding
from hypothesis import given, settings
from hypothesis import strategies as st

from ca_core.models.finding import Level
from ca_core.models.scoring_config import Thresholds
from ca_core.scoring.base import impact, round_score
from ca_core.scoring.levels import level_from_score
from ca_core.scoring.score import sort_scored

UNIT = st.floats(min_value=0.0, max_value=1.0, allow_nan=False, allow_infinity=False)
ORDER = [Level.LOW, Level.MEDIUM, Level.HIGH, Level.CRITICAL]
DEFAULT = Thresholds(critico=70.0, alto=40.0, medio=15.0)


@st.composite
def thresholds(draw: st.DrawFn) -> Thresholds:
    """Soglie qualunque purché crescenti, come le vuole la configurazione."""
    medio, alto, critico = sorted(
        draw(st.lists(st.integers(1, 100), min_size=3, max_size=3, unique=True))
    )
    return Thresholds(critico=float(critico), alto=float(alto), medio=float(medio))


@given(UNIT, UNIT, UNIT, UNIT)
def test_the_score_is_in_zero_to_one_hundred_with_two_decimals(
    g: float, p: float, e: float, c: float
) -> None:
    value = impact(g, p, e, c)
    assert 0.0 <= value <= 100.0
    assert Decimal(repr(value)).as_tuple().exponent >= -2  # al più due decimali


@given(UNIT, UNIT, UNIT, UNIT, UNIT, st.sampled_from("gpec"))
def test_the_score_never_decreases_when_one_factor_grows(
    g: float, p: float, e: float, c: float, other: float, which: str
) -> None:
    base = {"g": g, "p": p, "e": e, "c": c}
    low, high = sorted((base[which], other))
    assert impact(**{**base, which: low}) <= impact(**{**base, which: high})


@given(UNIT, UNIT, UNIT, UNIT)
def test_a_zero_factor_zeroes_the_score_and_all_ones_give_one_hundred(
    g: float, p: float, e: float, c: float
) -> None:
    assert impact(0.0, p, e, c) == impact(g, 0.0, e, c) == impact(g, p, 0.0, c) == 0.0
    assert impact(1.0, 1.0, 1.0, 1.0) == 100.0


@given(UNIT, UNIT, UNIT, UNIT)
def test_the_score_is_the_same_whatever_the_order_of_the_calls(
    g: float, p: float, e: float, c: float
) -> None:
    assert impact(g, p, e, c) == impact(g, p, e, c)
    # e, per la formula, non dipende da come si raggruppano i fattori
    assert abs(impact(g, p, e, c) - impact(c, e, p, g)) <= 0.01


@given(st.floats(min_value=0.0, max_value=100.0, allow_nan=False), thresholds())
def test_a_higher_score_never_gives_a_lower_level(score: float, t: Thresholds) -> None:
    for lower, higher in ((score, min(100.0, score + 0.01)), (score, 100.0), (0.0, score)):
        assert ORDER.index(level_from_score(lower, t)) <= ORDER.index(level_from_score(higher, t))


@given(thresholds())
def test_the_intervals_are_half_open_at_every_threshold(t: Thresholds) -> None:
    for limit, above in (
        (t.critico, Level.CRITICAL),
        (t.alto, Level.HIGH),
        (t.medio, Level.MEDIUM),
    ):
        assert level_from_score(limit, t) is above  # il limite inferiore è incluso
        assert ORDER.index(level_from_score(round(limit - 0.01, 2), t)) < ORDER.index(
            above
        )  # sotto: il livello inferiore


@given(st.floats(min_value=0.0, max_value=100.0, allow_nan=False))
def test_the_level_follows_the_rounded_score_never_the_raw_one(score: float) -> None:
    assert level_from_score(score, DEFAULT) is level_from_score(round_score(score), DEFAULT)


@given(st.floats(min_value=0.0, max_value=100.0, allow_nan=False))
def test_rounding_twice_changes_nothing(score: float) -> None:
    once = round_score(score)
    assert round_score(once) == once and abs(once - score) <= 0.005 + 1e-9


@settings(max_examples=60)
@given(
    st.lists(
        st.tuples(
            st.sampled_from(list(Level)), st.floats(0.0, 100.0, allow_nan=False), st.integers(0, 50)
        ),
        min_size=1,
        max_size=12,
        unique_by=lambda t: t[2],
    ),
    st.randoms(use_true_random=False),
)
def test_the_ordering_does_not_depend_on_the_input_order(
    rows: list[tuple[Level, float, int]], rng: random.Random
) -> None:
    findings = [
        finding(f"s{n}", level=level).model_copy(update={"score": round_score(score)})
        for level, score, n in rows
    ]
    shuffled = findings[:]
    rng.shuffle(shuffled)
    assert [f.fingerprint for f in sort_scored(findings)] == [
        f.fingerprint for f in sort_scored(shuffled)
    ]
    ranked = sort_scored(findings)
    for first, second in zip(ranked, ranked[1:], strict=False):
        assert ORDER.index(first.level) >= ORDER.index(second.level)  # prima i più gravi
