"""`ca-decision` (DE-01, ADR-0036) e le basi di confronto di G3.c, senza modelli."""

import importlib.util
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from ca_core.models.decision import Decision, DecisionThresholds, Threshold
from ca_core.ports import DecisionEngine, DecisionError, EvidenceTooLarge, UnsupportedQuestion
from ca_decision.fake import FakeEngine
from ca_decision.routing import packaged_thresholds, route

ROOT = Path(__file__).resolve().parents[2]
SECRET = "password_finta = 'non-deve-uscire'"
ASK = ("is_true_positive", "Il rischio c'è davvero?")


def decide(engine: DecisionEngine, evidence: str = "x = 1") -> Decision:
    return engine.decide(*ASK, evidence, None, "boolean")


def test_the_fake_is_deterministic_and_says_it_is_fake() -> None:
    first = decide(FakeEngine())
    assert first == decide(FakeEngine())
    assert first.model == "finto"
    assert first.confidence == max(first.probabilities.true, first.probabilities.false)
    other = decide(FakeEngine(seed="1"))
    assert other.model_version != first.model_version


def test_too_much_evidence_is_an_error_not_a_silent_cut() -> None:
    engine = FakeEngine(max_characters=10)
    decide(engine, "x" * 10)
    with pytest.raises(EvidenceTooLarge) as failure:
        decide(engine, SECRET)
    assert SECRET not in str(failure.value)


@pytest.mark.parametrize(
    "call",
    [
        ("smell_category", "?", "x", None, "boolean"),
        ("is_true_positive", "?", "x", None, "choice"),
        ("is_true_positive", "?", "x", ["a"], "boolean"),
    ],
)
def test_other_questions_are_refused(call: tuple) -> None:
    with pytest.raises(UnsupportedQuestion):
        FakeEngine().decide(*call)


def test_no_fallback_decision_without_evidence() -> None:
    with pytest.raises(DecisionError):
        decide(FakeEngine(), "")


def test_probabilities_must_sum_to_one() -> None:
    data = decide(FakeEngine()).model_dump()
    Decision.model_validate({**data, "probabilities": {"true": 0.6, "false": 0.4005}})
    with pytest.raises(ValidationError, match="non sommano"):
        Decision.model_validate({**data, "probabilities": {"true": 0.6, "false": 0.5}})


def thresholds(decision: Decision, minimum: float, **over: Any) -> DecisionThresholds:
    entry = {
        "question_id": decision.question_id,
        "model": decision.model,
        "model_version": decision.model_version,
        "minimum_confidence": minimum,
        **over,
    }
    return DecisionThresholds(version=1, thresholds=[Threshold(**entry)])


def test_routing_suggests_only_at_or_above_a_threshold_for_these_weights() -> None:
    decision = decide(FakeEngine())
    assert route(decision, thresholds(decision, decision.confidence)) == "suggerimento"
    assert route(decision, thresholds(decision, min(1.0, decision.confidence + 1e-6))) == "umano"
    stale = thresholds(decision, 0, model_version="sha256:" + "0" * 64)
    assert route(decision, stale) == "umano"
    assert route(decision, thresholds(decision, 0, model="altro")) == "umano"


def test_the_product_ships_no_calibrated_threshold_yet() -> None:
    shipped = packaged_thresholds()
    assert shipped.thresholds == []
    sure = decide(FakeEngine()).model_copy(update={"confidence": 1.0})
    assert route(sure, shipped) == "umano"


def test_two_thresholds_for_the_same_weights_are_refused() -> None:
    one = thresholds(decide(FakeEngine()), 0.8).thresholds[0]
    with pytest.raises(ValidationError, match="due soglie"):
        DecisionThresholds(version=1, thresholds=[one, one])


# --- basi di confronto ---------------------------------------------------------------------------


def baselines() -> Any:
    spec = importlib.util.spec_from_file_location(
        "golden_baselines", ROOT / "golden-set/eval/baselines.py"
    )
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


TRAINING = [
    ("A", "falso-positivo"),
    ("A", "falso-positivo"),
    ("A", "vero"),
    ("B", "vero"),
    ("B", "vero"),
    ("B", "vero"),
    ("C", "non-so"),
]


def test_majority_class_ignores_the_rule() -> None:
    predict = baselines().majority_class(TRAINING)
    assert [predict(rule) for rule in "ABZ"] == ["vero"] * 3


def test_per_rule_falls_back_to_the_majority_for_unknown_and_unsure_rules() -> None:
    predict = baselines().per_rule(TRAINING)
    assert [predict(rule) for rule in "ABCZ"] == ["falso-positivo", "vero", "vero", "vero"]


def test_a_tie_answers_true() -> None:
    tie = [("A", "falso-positivo"), ("A", "vero")]
    assert baselines().majority_class(tie)("A") == "vero"
    assert baselines().per_rule(tie)("A") == "vero"


@pytest.mark.parametrize("training", [[], [("A", "non-so")]])
def test_no_baseline_without_answers(training: list) -> None:
    for build in (baselines().majority_class, baselines().per_rule):
        with pytest.raises(ValueError):
            build(training)
