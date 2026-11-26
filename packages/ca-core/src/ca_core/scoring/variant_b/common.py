"""Pezzi comuni ai fattori della Variante B (ADR-0023)."""

from typing import Any

from ca_core.scoring.base import Factor


def from_a(a: Factor, reason: str) -> Factor:
    """Il fattore di A, dichiarato come ripiego di B con il motivo."""
    evidence: dict[str, Any] = {**a.evidence, "fallback": reason, "from_variant": "A"}
    return Factor(a.value, evidence)


def clamp(value: float) -> float:
    return min(1.0, max(0.0, value))


def rounded(value: float) -> float:
    return round(value, 6)
