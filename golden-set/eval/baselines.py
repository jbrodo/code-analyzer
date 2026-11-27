"""Le due basi di confronto di G3.c (ADR-0034, ADR-0036): classe di maggioranza e regola per
`rule_id`.

Si costruiscono con le sole etichette di **addestramento**. Le voci «non so» non contano. A parità
di voti la risposta è «vero»: la regola è fissata qui, prima di avere un test. Per una `rule_id`
mai vista si risponde con la classe di maggioranza.
"""

from collections import Counter
from collections.abc import Callable, Iterable

from ca_core.models.golden_set import Label

Answer = Label  # le basi rispondono solo «vero» o «falso-positivo»
Predictor = Callable[[str], Answer]


def _majority(counts: Counter[str]) -> Answer:
    return "falso-positivo" if counts["falso-positivo"] > counts["vero"] else "vero"


def _decided(training: Iterable[tuple[str, Label]]) -> list[tuple[str, Label]]:
    decided = [(rule, label) for rule, label in training if label != "non-so"]
    if not decided:
        raise ValueError("nessuna etichetta «vero» o «falso-positivo» per costruire la base")
    return decided


def majority_class(training: Iterable[tuple[str, Label]]) -> Predictor:
    """`training`: coppie (rule_id, risposta)."""
    answer = _majority(Counter(label for _, label in _decided(training)))
    return lambda rule_id: answer


def per_rule(training: Iterable[tuple[str, Label]]) -> Predictor:
    decided = _decided(training)
    counts: dict[str, Counter[str]] = {}
    for rule, label in decided:
        counts.setdefault(rule, Counter())[label] += 1
    answers = {rule: _majority(votes) for rule, votes in counts.items()}
    fallback = _majority(Counter(label for _, label in decided))
    return lambda rule_id: answers.get(rule_id, fallback)
