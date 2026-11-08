"""Regole dei modelli che lo schema non esprime, e rifiuto della coercizione lax."""

from copy import deepcopy
from typing import Any

import pytest
from pydantic import ValidationError

from ca_core.models import PluginManifest
from ca_core.models.finding import ImpactFactors, Location
from ca_core.models.plugin_manifest import _EXAMPLE as MINIMAL
from ca_core.models.scan_report import FeedSnapshot


def manifest(**changes: Any) -> PluginManifest:
    return PluginManifest.model_validate({**deepcopy(MINIMAL), **changes})


def test_outputs_sarif_and_cyclonedx_must_differ() -> None:
    outputs = {"sarif": "/out/a", "cyclonedx": "/out/a", "cyclonedx_version": "1.7", "max_bytes": 1}
    with pytest.raises(ValidationError, match="diversi"):
        manifest(outputs=outputs)


@pytest.mark.parametrize("image", ["r/x:latest", f"r/x:latest@sha256:{'0' * 64}"])
def test_latest_tag_is_forbidden(image: str) -> None:
    with pytest.raises(ValidationError, match="latest"):
        manifest(image=image)
    assert manifest(image="r/latest:1").image == "r/latest:1"


def test_cyclonedx_producer_cannot_take_sbom_input() -> None:
    outputs = {"cyclonedx": "/out/s", "cyclonedx_version": "1.7", "max_bytes": 1}
    manifest(outputs=outputs)
    with pytest.raises(ValidationError, match="sbom"):
        manifest(outputs=outputs, inputs={"workspace": "readonly", "sbom": "optional"})


def test_max_bytes_has_a_ceiling() -> None:
    outputs = {"sarif": "/out/a", "max_bytes": 268_435_457}
    with pytest.raises(ValidationError):
        manifest(outputs=outputs)


@pytest.mark.parametrize(
    ("model", "data"),
    [
        (Location, {"repository": "r", "start_line": "4"}),
        (ImpactFactors, {"g": "0.5", "p": 0, "e": 0, "c": 0, "variant": "A"}),
        (FeedSnapshot, {"origin": "o", "synced_at": "2026-11-08T10:00:00Z", "sync_failed": "true"}),
    ],
)
def test_numbers_and_booleans_are_not_coerced_from_strings(
    model: Any, data: dict[str, Any]
) -> None:
    with pytest.raises(ValidationError):
        model.model_validate(data)
