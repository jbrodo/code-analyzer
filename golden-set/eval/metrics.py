"""Le misure del Gate 3 (DE-05; ADR-0034, ADR-0036). Solo calcoli: niente motori, file o rete.

- «Decise» sono le voci instradate a `suggerimento`. La copertura è la loro quota tra le voci con
  risposta «vero» o «falso positivo»; le «non so» si contano a parte.
- G3.c confronta motore e basi **sulle stesse voci decise**; le basi si riportano anche su tutto il
  test. Si costruiscono con le sole etichette di addestramento.
- G3.d (rete disattivata) non si ricava dai numeri: la verifica chi esegue il motore.

Soglie in `gate3.json`.
"""

import math
from collections import Counter
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from typing import Any

from baselines import majority_class, per_rule

from ca_core.models.decision import Decision, Route
from ca_core.models.golden_set import Label

CLASSES = ("vero", "falso-positivo")
Z95 = 1.959963984540054


@dataclass(frozen=True)
class Record:
    """Una voce del test con la risposta umana e la decisione del motore. `decision` manca quando
    il motore non è stato interrogato (niente evidenza, DE-02) o non ha risposto: la voce resta
    all'umano e conta nella copertura."""

    repository: str
    rule_id: str
    label: Label
    decision: Decision | None
    route: Route

    def __post_init__(self) -> None:
        if self.decision is None and self.route != "umano":
            raise ValueError("senza decisione la voce va all'umano")


@dataclass(frozen=True)
class Training:
    repository: str
    rule_id: str
    label: Label


def answer(decision: Decision) -> str:
    """La classe più probabile; a parità, «vero»."""
    return "vero" if decision.probabilities.true >= decision.probabilities.false else CLASSES[1]


def wilson(successes: int, total: int) -> list[float] | None:
    """Intervallo di Wilson al 95%; `None` senza osservazioni."""
    if total == 0:
        return None
    share, square = successes / total, Z95 * Z95
    scale = 1 + square / total
    centre = (share + square / (2 * total)) / scale
    half = Z95 * math.sqrt(share * (1 - share) / total + square / (4 * total * total)) / scale
    return [max(0.0, centre - half), min(1.0, centre + half)]


def _ratio(successes: int, total: int) -> dict[str, Any]:
    return {
        "value": successes / total if total else None,
        "successes": successes,
        "total": total,
        "interval95": wilson(successes, total),
    }


def balanced_accuracy(pairs: Sequence[tuple[str, str]]) -> float | None:
    """`pairs`: (vera, predetta). `None` se manca una delle due classi vere."""
    recalls = []
    for wanted in CLASSES:
        predicted = [guess for truth, guess in pairs if truth == wanted]
        if not predicted:
            return None
        recalls.append(sum(guess == wanted for guess in predicted) / len(predicted))
    return sum(recalls) / len(recalls)


def _calibration(records: Sequence[Record], edges: Sequence[float]) -> list[dict[str, Any]]:
    """Per fascia di confidenza dichiarata, quante volte la classe più probabile è giusta. L'ultima
    fascia comprende l'estremo alto; sotto il primo estremo c'è una fascia a sé."""
    bounds = [0.0, *edges]
    bins = []
    for index, (low, high) in enumerate(zip(bounds, bounds[1:], strict=False)):
        last = index == len(bounds) - 2
        inside = [
            r
            for r in records
            if low <= r.decision.confidence and (r.decision.confidence < high or last)
        ]
        if not inside:
            continue
        right = sum(answer(r.decision) == r.label for r in inside)
        confidences = math.fsum(r.decision.confidence for r in inside)
        bins.append(
            {
                "from": low,
                "to": high,
                "mean_confidence": confidences / len(inside),
                "accuracy": _ratio(right, len(inside)),
            }
        )
    return bins


def evaluate(
    test: Sequence[Record], training: Sequence[Training], gate: dict[str, Any]
) -> dict[str, Any]:
    """Il rapporto, serializzabile in JSON; a parità di ingressi è identico."""
    shared = {r.repository for r in test} & {t.repository for t in training}
    if shared:
        raise ValueError(f"test e addestramento hanno repository in comune: {sorted(shared)}")
    answered = [r for r in test if r.decision is not None]
    weights = {(r.decision.model, r.decision.model_version) for r in answered}
    if len(weights) != 1:
        raise ValueError("serve un test deciso da un solo modello con gli stessi pesi")
    labelled = [r for r in test if r.label in CLASSES]
    counts = Counter(r.label for r in labelled)
    decided = [r for r in labelled if r.route == "suggerimento"]

    pairs = [(r.label, answer(r.decision)) for r in decided]
    confusion = {
        truth: {guess: pairs.count((truth, guess)) for guess in CLASSES} for truth in CLASSES
    }
    precision = {
        guess: _ratio(confusion[guess][guess], sum(confusion[truth][guess] for truth in CLASSES))
        for guess in CLASSES
    }
    coverage = _ratio(len(decided), len(labelled))

    examples = [(t.rule_id, t.label) for t in training]
    builders: dict[str, Callable] = {"majority": majority_class, "per_rule": per_rule}
    baselines = {}
    for name, build in builders.items():
        predict = build(examples)
        baselines[name] = {
            "balanced_accuracy_on_decided": balanced_accuracy(
                [(r.label, predict(r.rule_id)) for r in decided]
            ),
            "balanced_accuracy_on_all": balanced_accuracy(
                [(r.label, predict(r.rule_id)) for r in labelled]
            ),
        }
    engine = balanced_accuracy(pairs)

    conditions = {
        "G3.a": all(
            p["value"] is not None and p["value"] >= gate["minimum_precision"]
            for p in precision.values()
        ),
        "G3.b": coverage["value"] is not None and coverage["value"] >= gate["minimum_coverage"],
        "G3.c": engine is not None
        and all(engine > b["balanced_accuracy_on_decided"] for b in baselines.values()),
    }
    reasons = []
    if len(labelled) < gate["minimum_test_answers"]:
        reasons.append(
            f"{len(labelled)} voci con risposta, ne servono {gate['minimum_test_answers']}"
        )
    minority = min(counts[c] for c in CLASSES)
    if minority < gate["minimum_minority_answers"]:
        reasons.append(
            f"{minority} voci nella classe meno frequente, ne servono "
            f"{gate['minimum_minority_answers']}"
        )
    if reasons:
        outcome = "non valutabile"
    else:
        outcome = "superate G3.a-G3.c" if all(conditions.values()) else "non superato"

    repositories = {
        name: dict(sorted(Counter(r.label for r in test if r.repository == name).items()))
        for name in sorted({r.repository for r in test})
    }
    model, version = next(iter(weights))
    return {
        "model": model,
        "model_version": version,
        "outcome": outcome,
        "not_evaluable_because": reasons,
        "conditions": conditions,
        "offline": "G3.d non si verifica dai numeri",
        "counts": {
            "items": len(test),
            "without_decision": len(test) - len(answered),
            "unsure": len(test) - len(labelled),
            "by_class": {c: counts[c] for c in CLASSES},
            "by_repository": repositories,
        },
        "coverage": coverage,
        "confusion_on_decided": confusion,
        "precision_on_decided": precision,
        "engine_balanced_accuracy_on_decided": engine,
        "baselines": baselines,
        "calibration_on_answered": _calibration(
            [r for r in labelled if r.decision is not None], gate["calibration_bin_edges"]
        ),
    }
