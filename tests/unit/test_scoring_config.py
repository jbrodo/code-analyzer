"""Lettura della configurazione di scoring e versione registrata (C-03, ADR-0021)."""

import json
import re

import pytest

from ca_core.scoring.config import (
    MAX_BYTES,
    ScoringConfigError,
    config_version,
    default_bytes,
    load_default,
    parse_config,
)


def test_the_packaged_default_loads() -> None:
    config = load_default()
    assert config.variant == "A" and config.levels.source.value == "provisional"
    assert config.levels.thresholds.critico == 70.0


def test_version_is_the_version_plus_a_short_fingerprint() -> None:
    assert re.fullmatch(r"2\+[0-9a-f]{12}", config_version(load_default()))


def test_version_ignores_whitespace_and_key_order() -> None:
    data = json.loads(default_bytes())
    reordered = json.dumps(dict(reversed(list(data.items()))), indent=None).encode()
    assert config_version(parse_config(reordered)) == config_version(load_default())


def test_any_change_of_a_value_changes_the_version() -> None:
    data = json.loads(default_bytes())
    data["p"]["feed_missing"] = 0.2
    other = parse_config(json.dumps(data).encode())
    assert config_version(other) != config_version(load_default())


def test_a_partial_file_is_refused_not_merged_with_the_default() -> None:
    with pytest.raises(ScoringConfigError, match="non valida"):
        parse_config(b'{"version": 1, "variant": "A"}')


@pytest.mark.parametrize("raw", [b"", b"{", b"[]", b"null", b'{"version": "x"}'])
def test_malformed_files_are_refused_without_echoing_the_content(raw: bytes) -> None:
    with pytest.raises(ScoringConfigError) as caught:
        parse_config(raw)
    assert raw.decode() not in str(caught.value) or raw == b""


def test_a_file_over_the_limit_is_refused() -> None:
    with pytest.raises(ScoringConfigError, match="troppo grande"):
        parse_config(b" " * (MAX_BYTES + 1))


def test_no_scoring_value_is_hard_coded_in_the_model() -> None:
    """Regola 3: i campi non hanno un predefinito nel modello; i valori stanno nel file."""
    from ca_core.models.scoring_config import ScoringConfig

    defaults = [n for n, f in ScoringConfig.model_fields.items() if not f.is_required()]
    # `variant_b` è un blocco facoltativo, non un valore: assente, B coincide con A (ADR-0023)
    assert defaults == ["variant_b"]
    assert ScoringConfig.model_fields["variant_b"].default is None
