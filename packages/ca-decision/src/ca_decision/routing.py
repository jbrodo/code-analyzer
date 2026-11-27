"""Instradamento per confidenza (§10.3, ADR-0036): `suggerimento` o `umano`.

L'azione automatica non esiste: nessun esito di qui cambia stato, livello, punteggio o gate. Le
soglie sono un dato del prodotto (`thresholds.json`), per domanda e pesi esatti: senza una soglia
calibrata decide l'umano.
"""

from importlib.resources import files

from ca_core.models.decision import Decision, DecisionThresholds, Route


def packaged_thresholds() -> DecisionThresholds:
    return DecisionThresholds.model_validate_json(
        files("ca_decision").joinpath("thresholds.json").read_bytes()
    )


def route(decision: Decision, thresholds: DecisionThresholds) -> Route:
    wanted = decision.question_id, decision.model, decision.model_version
    for threshold in thresholds.thresholds:
        if (threshold.question_id, threshold.model, threshold.model_version) == wanted:
            if decision.confidence >= threshold.minimum_confidence:
                return "suggerimento"
            return "umano"
    return "umano"
