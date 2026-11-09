"""K-18: `publish` scrive report e SARIF tramite `ArtifactSink`, in modo deterministico."""

import json
from pathlib import Path

import pytest
from builders import finding, report

from ca_core.fakes import InMemoryArtifactSink
from ca_core.models.finding import Level
from ca_core.pipeline.publish import REPORT_NAME, SARIF_NAME, PublishError, publish
from ca_core.schema_validation import SchemaStore

ROOT = Path(__file__).resolve().parents[2]
SCHEMA = json.loads((ROOT / "schemas" / "scan-report.schema.json").read_text())


@pytest.fixture(scope="module")
def store() -> SchemaStore:
    return SchemaStore(ROOT / "schemas" / "vendor")


def test_writes_valid_report_and_sarif(store: SchemaStore) -> None:
    sink = InMemoryArtifactSink()
    result = publish(report([finding("a", level=Level.HIGH)]), sink, store)
    assert set(sink.artifacts) == {REPORT_NAME, SARIF_NAME}
    assert result.report.size == len(sink.artifacts[REPORT_NAME])
    document = json.loads(sink.artifacts[REPORT_NAME])
    assert store.validate_with(SCHEMA, document) == []  # contro il file in `schemas/`
    assert store.validate_sarif(json.loads(sink.artifacts[SARIF_NAME])) == []


def test_output_is_deterministic(store: SchemaStore) -> None:
    runs = []
    for _ in range(2):
        sink = InMemoryArtifactSink()
        publish(report([finding("a"), finding("b")]), sink, store)
        runs.append(sink.artifacts)
    assert runs[0] == runs[1]


def test_invalid_report_writes_nothing(store: SchemaStore) -> None:
    sink = InMemoryArtifactSink()
    bad = report().model_copy(update={"duration_seconds": -1.0})  # `model_copy` non rivalida
    with pytest.raises(PublishError):
        publish(bad, sink, store)
    assert sink.artifacts == {}
