"""Oscura ciò che somiglia a una credenziale (DE-02, §11.4).

È la terza difesa, dopo le due di `ca_decision.evidence` sui finding di segreti: **non riconosce
ogni segreto**. Le espressioni e le soglie stanno in `evidence.json`. Il numero di righe non
cambia, così le posizioni dei finding restano giuste; ogni riga toccata porta il segno, anche
quando il blocco comincia prima della parte che si mostrerà.
"""

import math
import re
from collections import Counter

from ca_core.models.decision import EvidenceSettings

MASK = "[oscurato]"
# Una stringa tra apici su una sola riga, senza spazi: le frasi non sono candidate.
_LITERAL = re.compile(r"""(?P<quote>["'`])(?P<value>[^\s"'`]+)(?P=quote)""")


def _entropy(value: str) -> float:
    return -sum(n / len(value) * math.log2(n / len(value)) for n in Counter(value).values())


def redact(text: str, settings: EvidenceSettings) -> tuple[str, int]:
    """Il testo con le credenziali oscurate e quante sostituzioni sono state fatte."""
    spans: list[tuple[int, int]] = []
    for pattern in settings.redaction_patterns:
        for match in re.finditer(pattern, text, re.MULTILINE):
            group = "secret" if "secret" in match.re.groupindex else 0
            spans.append(match.span(group))
    for match in _LITERAL.finditer(text):
        value = match["value"]
        if (
            len(value) >= settings.entropy_min_length
            and _entropy(value) >= settings.entropy_min_bits
        ):
            spans.append(match.span("value"))
    merged: list[list[int]] = []
    for start, end in sorted(spans):
        if merged and start <= merged[-1][1]:
            merged[-1][1] = max(merged[-1][1], end)
        else:
            merged.append([start, end])
    pieces, position = [], 0
    for start, end in merged:
        pieces += [text[position:start], MASK, f"\n{MASK}" * text.count("\n", start, end)]
        position = end
    return "".join([*pieces, text[position:]]), len(merged)
