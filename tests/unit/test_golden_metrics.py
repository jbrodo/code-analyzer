"""Le misure del Gate 3 (DE-05), su decisioni costruite a mano e sul motore finto."""

import importlib.util
import json
import sys
from pathlib import Path
from typing import Any

import pytest

from ca_core.models.decision import Decision, Probabilities
from ca_decision.fake import FakeEngine

EVAL = Path(__file__).resolve().parents[2] / "golden-set/eval"
GATE = json.loads((EVAL / "gate3.json").read_text(encoding="utf-8"))
SMALL = {**GATE, "minimum_test_answers": 10, "minimum_minority_answers": 4}


def load() -> Any:
    sys.path.insert(0, str(EVAL))
    try:
        spec = importlib.util.spec_from_file_location("golden_metrics", EVAL / "metrics.py")
        assert spec and spec.loader
        module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = module
        spec.loader.exec_module(module)
        return module
    finally:
        sys.path.remove(str(EVAL))


metrics = load()


def decision(true: float, **over: Any) -> Decision:
    fields = {
        "question_id": "is_true_positive",
        "kind": "boolean",
        "probabilities": Probabilities(true=true, false=1 - true),
        "confidence": max(true, 1 - true),
        "model": "finto",
        "model_version": "sha256:" + "a" * 64,
        **over,
    }
    return Decision(**fields)


def record(
    label: str, true: float, route: str = "suggerimento", rule: str = "A", n: int = 0
) -> Any:
    return metrics.Record(f"test-{n % 2}", rule, label, decision(true), route)


TRAINING = [metrics.Training("addestramento", "A", "vero")] * 3 + [
    metrics.Training("addestramento", "B", "falso-positivo")
]


def good_test() -> list[Any]:
    """Decisi: 6 veri e 4 falsi positivi, uno sbagliato per classe. Poi 2 rimandati e 1 «non so»."""
    decided = (
        [record("vero", 0.9, n=n) for n in range(5)]
        + [record("vero", 0.1)]
        + [record("falso-positivo", 0.05, n=n) for n in range(3)]
        + [record("falso-positivo", 0.95)]
    )
    deferred = [record("vero", 0.55, "umano"), record("falso-positivo", 0.45, "umano")]
    return decided + deferred + [record("non-so", 0.9)]


def test_numbers_on_a_hand_made_test() -> None:
    report = metrics.evaluate(good_test(), TRAINING, SMALL)
    assert report["counts"]["unsure"] == 1
    assert report["counts"]["by_class"] == {"vero": 7, "falso-positivo": 5}
    assert (report["coverage"]["successes"], report["coverage"]["total"]) == (10, 12)
    assert report["confusion_on_decided"] == {
        "vero": {"vero": 5, "falso-positivo": 1},
        "falso-positivo": {"vero": 1, "falso-positivo": 3},
    }
    assert report["precision_on_decided"]["vero"]["value"] == pytest.approx(5 / 6)
    assert report["precision_on_decided"]["falso-positivo"]["value"] == pytest.approx(3 / 4)
    assert report["engine_balanced_accuracy_on_decided"] == pytest.approx((5 / 6 + 3 / 4) / 2)
    assert report["baselines"]["majority"]["balanced_accuracy_on_decided"] == 0.5
    assert report["conditions"] == {"G3.a": False, "G3.b": True, "G3.c": True}
    assert report["outcome"] == "non superato"
    json.dumps(report)


def perfect() -> list[Any]:
    return [record("vero", 0.9, n=n) for n in range(6)] + [
        record("falso-positivo", 0.1, n=n) for n in range(4)
    ]


def test_passing_is_only_about_a_to_c_and_says_so() -> None:
    report = metrics.evaluate(perfect(), TRAINING, SMALL)
    assert report["outcome"] == "superate G3.a-G3.c"
    assert "G3.d" in report["offline"]


def test_the_real_gate_is_not_evaluable_on_a_small_test() -> None:
    report = metrics.evaluate(perfect(), TRAINING, GATE)
    assert report["outcome"] == "non valutabile"
    assert len(report["not_evaluable_because"]) == 2


def test_ties_with_a_baseline_do_not_pass() -> None:
    rules = [record("vero", 0.9, rule="A", n=n) for n in range(6)] + [
        record("falso-positivo", 0.1, rule="B", n=n) for n in range(4)
    ]
    report = metrics.evaluate(rules, TRAINING, SMALL)
    assert report["baselines"]["per_rule"]["balanced_accuracy_on_decided"] == 1.0
    assert report["conditions"]["G3.c"] is False


def test_deferring_one_whole_class_does_not_pass() -> None:
    test = [record("vero", 0.9, n=n) for n in range(6)] + [
        record("falso-positivo", 0.1, "umano", n=n) for n in range(4)
    ]
    report = metrics.evaluate(test, TRAINING, SMALL)
    assert report["engine_balanced_accuracy_on_decided"] is None
    assert report["conditions"] == {"G3.a": False, "G3.b": True, "G3.c": False}


def test_deciding_nothing_gives_no_numbers_instead_of_errors() -> None:
    test = [record(r.label, 0.9, "umano") for r in perfect()]
    report = metrics.evaluate(test, TRAINING, SMALL)
    assert report["coverage"]["value"] == 0
    assert report["precision_on_decided"]["vero"] == {
        "value": None,
        "successes": 0,
        "total": 0,
        "interval95": None,
    }
    assert report["conditions"] == {"G3.a": False, "G3.b": False, "G3.c": False}


def test_training_repositories_cannot_be_in_the_test() -> None:
    leaked = [*TRAINING, metrics.Training("test-1", "A", "vero")]
    with pytest.raises(ValueError, match="in comune"):
        metrics.evaluate(perfect(), leaked, SMALL)


def test_one_model_and_one_set_of_weights_per_report() -> None:
    other = metrics.Record(
        "test-0", "A", "vero", decision(0.9, model_version="sha256:" + "b" * 64), "umano"
    )
    for test in ([*perfect(), other], []):
        with pytest.raises(ValueError, match="un solo modello"):
            metrics.evaluate(test, TRAINING, SMALL)


def test_calibration_bins_cover_every_answered_item_once() -> None:
    test = [record("vero", p) for p in (0.5, 0.6, 0.99, 1.0)] + [record("non-so", 0.7)]
    bins = metrics.evaluate(test, TRAINING, SMALL)["calibration_on_answered"]
    assert [(b["from"], b["accuracy"]["total"]) for b in bins] == [(0.5, 1), (0.6, 1), (0.9, 2)]


def test_wilson_matches_known_values() -> None:
    low, high = metrics.wilson(172, 200)
    assert (round(low, 3), round(high, 3)) == (0.805, 0.901)
    assert metrics.wilson(0, 0) is None
    assert metrics.wilson(0, 10)[0] == 0


def test_same_inputs_give_the_same_report_whatever_the_order() -> None:
    engine = FakeEngine(seed="eval")
    test = [
        metrics.Record(
            f"test-{n % 3}",
            "A",
            "vero" if n % 2 else "falso-positivo",
            engine.decide("is_true_positive", "?", f"riga {n}", None, "boolean"),
            "suggerimento",
        )
        for n in range(30)
    ]
    first = metrics.evaluate(test, TRAINING, GATE)
    again = metrics.evaluate(test[::-1], TRAINING[::-1], GATE)
    assert json.dumps(first, sort_keys=True) == json.dumps(again, sort_keys=True)


def test_items_without_a_decision_lower_the_coverage_and_stay_out_of_calibration() -> None:
    silent = [metrics.Record("test-0", "A", "vero", None, "umano")] * 10
    report = metrics.evaluate([*perfect(), *silent], TRAINING, SMALL)
    assert (report["coverage"]["successes"], report["coverage"]["total"]) == (10, 20)
    assert report["counts"]["without_decision"] == 10
    assert sum(b["accuracy"]["total"] for b in report["calibration_on_answered"]) == 10
    with pytest.raises(ValueError, match="all'umano"):
        metrics.Record("test-0", "A", "vero", None, "suggerimento")
