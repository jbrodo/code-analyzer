"""Motore finto per test e per provare la valutazione (§14): deterministico, senza modelli.

Le sue risposte vengono da un digest dell'evidenza: **non dicono nulla sul finding**. Non va mai
usato per dare suggerimenti a una persona, meno che mai a chi annota il golden set.
"""

import hashlib

from ca_core.models.decision import Decision, DecisionKind, Probabilities, QuestionId
from ca_core.ports import DecisionError, EvidenceTooLarge, UnsupportedQuestion

MODEL = "finto"


def _digest(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", "surrogateescape")).hexdigest()


class FakeEngine:
    """`max_characters` imita il limite di contesto di un motore vero."""

    def __init__(self, *, seed: str = "0", max_characters: int = 4000) -> None:
        self.seed = seed
        self.max_characters = max_characters
        self.version = "sha256:" + _digest(f"{MODEL}\0{seed}")

    def decide(
        self,
        question_id: QuestionId,
        question: str,
        evidence: str,
        options: list[str] | None,
        kind: DecisionKind,
    ) -> Decision:
        if question_id != "is_true_positive" or kind != "boolean" or options is not None:
            raise UnsupportedQuestion("il motore gestisce solo is_true_positive, senza opzioni")
        if not evidence:
            raise DecisionError("evidenza vuota")
        if len(evidence) > self.max_characters:
            raise EvidenceTooLarge(
                f"evidenza di {len(evidence)} caratteri, limite {self.max_characters}"
            )
        true = int(_digest(f"{self.seed}\0{question}\0{evidence}")[:8], 16) / 0xFFFFFFFF
        return Decision(
            question_id=question_id,
            kind=kind,
            probabilities=Probabilities(true=true, false=1 - true),
            confidence=max(true, 1 - true),
            model=MODEL,
            model_version=self.version,
        )
