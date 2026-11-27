"""`decision` e `decision-thresholds`: il motore decisionale (ADR-0036)."""

import pytest
from conftest import Json, errors_of, make_validator, mutated

VALIDATORS = {
    "decision": make_validator("decision"),
    "evidence": make_validator("decision", "Evidence"),
    "decision-thresholds": make_validator("decision-thresholds"),
}
DIGEST = "sha256:" + "a" * 64

DECISION: Json = {
    "question_id": "is_true_positive",
    "kind": "boolean",
    "probabilities": {"true": 0.9, "false": 0.1},
    "confidence": 0.9,
    "model": "finto",
    "model_version": DIGEST,
}
EVIDENCE: Json = {"text": "x = 1", "reduced": False}
THRESHOLDS: Json = {
    "version": 1,
    "thresholds": [
        {
            "question_id": "is_true_positive",
            "model": "finto",
            "model_version": DIGEST,
            "minimum_confidence": 0.8,
        }
    ],
}


def _set(**changes: object):
    return lambda i: i.update(changes)


def _threshold(**changes: object):
    return lambda i: i["thresholds"][0].update(changes)


VALID = {
    "decision": {
        "full": DECISION,
        "no-score": mutated(DECISION, _set(score=None)),
        "integer-probabilities": mutated(
            DECISION, _set(probabilities={"true": 1, "false": 0}, confidence=1)
        ),
    },
    "evidence": {"full": EVIDENCE, "reduced": mutated(EVIDENCE, _set(reduced=True))},
    "decision-thresholds": {
        "full": THRESHOLDS,
        "empty": mutated(THRESHOLDS, _set(thresholds=[])),
    },
}

INVALID = {
    "decision": {
        "other-question": mutated(DECISION, _set(question_id="smell_category")),
        "other-kind": mutated(DECISION, _set(kind="choice")),
        "extra-class": mutated(
            DECISION, _set(probabilities={"true": 0.5, "false": 0.4, "forse": 0.1})
        ),
        "missing-class": mutated(DECISION, _set(probabilities={"true": 1.0})),
        "over-one": mutated(DECISION, _set(confidence=1.5)),
        "string-number": mutated(DECISION, _set(confidence="0.9")),
        "score-given": mutated(DECISION, _set(score=0.4)),
        "version-not-a-digest": mutated(DECISION, _set(model_version="0.5.5")),
        "evidence-copied": mutated(DECISION, _set(evidence="x = 1")),
        "action": mutated(DECISION, _set(action="auto")),
    },
    "evidence": {
        "empty": mutated(EVIDENCE, _set(text="")),
        "not-said": mutated(EVIDENCE, lambda i: i.pop("reduced")),
    },
    "decision-thresholds": {
        "no-version-of-weights": mutated(
            THRESHOLDS, lambda i: i["thresholds"][0].pop("model_version")
        ),
        "over-one": mutated(THRESHOLDS, _threshold(minimum_confidence=2)),
        "auto-threshold": mutated(THRESHOLDS, _threshold(auto_confidence=0.99)),
    },
}


def cases(table: dict[str, dict[str, Json]]) -> list:
    return [
        pytest.param(name, instance, id=f"{name}:{case}")
        for name, group in table.items()
        for case, instance in group.items()
    ]


@pytest.mark.parametrize("name,instance", cases(VALID))
def test_valid_instances_pass(name: str, instance: Json) -> None:
    assert errors_of(VALIDATORS[name], instance) == []


@pytest.mark.parametrize("name,instance", cases(INVALID))
def test_invalid_instances_fail(name: str, instance: Json) -> None:
    assert errors_of(VALIDATORS[name], instance)
