"""`scoring-config`: contratto della configurazione di scoring (C-03, ADR-0021)."""

import json
from pathlib import Path

import pytest
from conftest import Json, case_params, errors_of, make_validator, mutated

VALIDATOR = make_validator("scoring-config")
DEFAULT_FILE = (
    Path(__file__).resolve().parents[2] / "packages/ca-core/src/ca_core/scoring/default.json"
)
DEFAULT: Json = json.loads(DEFAULT_FILE.read_text())


def _set(path: str, value: object):
    """Imposta `a.b.c` nell'istanza; `None` come valore toglie la chiave."""

    def apply(instance: Json) -> None:
        *parents, last = path.split(".")
        node = instance
        for key in parents:
            node = node[key]
        if value is None:
            del node[last]
        else:
            node[last] = value

    return apply


VALID = {
    "default": DEFAULT,
    "variant-b": mutated(DEFAULT, _set("variant", "B")),
    "source-score": mutated(DEFAULT, _set("levels.source", "score")),
    "integer-numbers": mutated(DEFAULT, _set("g.secret", 1), _set("levels.thresholds.alto", 40)),
    "version-2": mutated(DEFAULT, _set("version", 2)),
    # ADR-0023: senza il blocco B coincide con A, ed è un file valido
    "without-variant-b": mutated(DEFAULT, _set("variant_b", None)),
}

INVALID = {
    "empty": {},
    "unknown-top-level": mutated(DEFAULT, _set("weights", {})),
    "unknown-nested-key": mutated(DEFAULT, _set("g.secret_extra", 0.5)),
    "missing-levels": mutated(DEFAULT, _set("levels", None)),
    "missing-overrides": mutated(DEFAULT, _set("overrides", None)),
    "missing-g-severity-key": mutated(DEFAULT, _set("g.severity.high", None)),
    "version-zero": mutated(DEFAULT, _set("version", 0)),
    "version-true": mutated(DEFAULT, _set("version", True)),
    "version-string": mutated(DEFAULT, _set("version", "1")),
    "variant-c": mutated(DEFAULT, _set("variant", "C")),
    "source-unknown": mutated(DEFAULT, _set("levels.source", "shadow")),
    "factor-above-one": mutated(DEFAULT, _set("p.kev", 1.1)),
    "factor-negative": mutated(DEFAULT, _set("e.unknown", -0.1)),
    "factor-bool": mutated(DEFAULT, _set("c.missing", True)),
    "factor-string": mutated(DEFAULT, _set("g.health", "0.5")),
    "threshold-zero": mutated(DEFAULT, _set("levels.thresholds.medio", 0)),
    "threshold-above-100": mutated(DEFAULT, _set("levels.thresholds.critico", 101)),
    "override-level-unknown": mutated(DEFAULT, _set("overrides.kev_reachable.level", "bassissimo")),
    "override-percentile-zero": mutated(
        DEFAULT, _set("overrides.architecture_smell_hotspot.churn_percentile_min", 0)
    ),
    "override-percentile-fraction": mutated(
        DEFAULT, _set("overrides.low_coverage_critical_code.churn_percentile_min", 90.5)
    ),
    "window-zero": mutated(DEFAULT, _set("p.churn.window_days", 0)),
    "variant-b-missing-c": mutated(DEFAULT, _set("variant_b.c", None)),
    "variant-b-unknown-smell": mutated(
        DEFAULT, _set("variant_b.g.architecture.god_component", 1.0)
    ),
    "variant-b-weight-above-one": mutated(DEFAULT, _set("variant_b.p.w_churn", 1.5)),
    "variant-b-null": mutated(DEFAULT, _set("variant_b", "none")),
    # «segreto valido esposto» non si applica (ADR-0012): non c'è un posto dove configurarlo
    "valid-secret-override": mutated(DEFAULT, _set("overrides.valid_secret", {"level": "critico"})),
}


@pytest.mark.parametrize("instance", case_params(VALID, "valid:"))
def test_valid_instances_pass(instance: Json) -> None:
    assert errors_of(VALIDATOR, instance) == []


@pytest.mark.parametrize("instance", case_params(INVALID, "invalid:"))
def test_invalid_instances_are_rejected(instance: Json) -> None:
    assert errors_of(VALIDATOR, instance) != []


def test_the_packaged_default_has_no_value_the_schema_cannot_express() -> None:
    """Il file predefinito supera lo schema ed elenca ogni sezione del contratto."""
    assert errors_of(VALIDATOR, DEFAULT) == []
    assert set(DEFAULT) == {
        "version",
        "variant",
        "levels",
        "g",
        "p",
        "e",
        "c",
        "overrides",
        "variant_b",
    }


def test_default_levels_source_is_provisional_until_gate_2() -> None:
    """D2-10: il livello da punteggio non è attivo finché non lo decide chi controlla il file."""
    assert DEFAULT["levels"]["source"] == "provisional"
