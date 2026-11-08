from datetime import UTC, datetime
from typing import Any

import pytest
from pydantic import ValidationError

from ca_core.fakes import (
    FakePluginExecutor,
    FixedClock,
    InMemoryArtifactSink,
    InMemorySourceReader,
)
from ca_core.models import PackagedPluginManifest
from ca_core.ports import (
    ArtifactSink,
    Clock,
    FeedsSyncRequest,
    Isolation,
    PluginExecutor,
    PluginRunRequest,
    PluginRunResult,
    RunOutcome,
    SourceError,
    SourceReader,
    SourceTooLarge,
)

MANIFEST = PackagedPluginManifest.model_validate(
    {
        "apiVersion": "code-analyzer/v1",
        "name": "semgrep",
        "version": "1.0.0",
        "image": f"registry.invalid/ca/semgrep:1.0.0@sha256:{'a' * 64}",
        "capabilities": ["detect"],
        "languages": [],
        "categories": ["sast"],
        "inputs": {"workspace": "readonly"},
        "outputs": {"sarif": "/out/results.sarif", "max_bytes": 1000},
        "resources": {"cpu": "1", "memory": "1Gi", "timeout": "60s", "pids": 64},
        "network": "none",
    }
)


FEEDS = {"sync_command": ["sync"], "ecosystems": ["npm"], "sync_timeout": "60s"}


def manifest(**changes: Any) -> PackagedPluginManifest:
    return PackagedPluginManifest.model_validate({**MANIFEST.model_dump(mode="json"), **changes})


def test_fakes_satisfy_the_protocols() -> None:
    assert isinstance(FakePluginExecutor(), PluginExecutor)
    assert isinstance(InMemorySourceReader(), SourceReader)
    assert isinstance(InMemoryArtifactSink(), ArtifactSink)
    assert isinstance(FixedClock(), Clock)


def test_executor_answers_by_plugin_name_and_records_requests() -> None:
    executor = FakePluginExecutor({"semgrep": FakePluginExecutor.ok("/out/1", 2.5)})
    request = PluginRunRequest(manifest=MANIFEST, workspace="/ws")

    result = executor.run(request)

    assert result.outcome is RunOutcome.OK and result.output_dir == "/out/1"
    assert executor.runs == [request]
    assert PluginRunResult.model_validate_json(result.model_dump_json()) == result


def test_executor_without_configured_answer_fails_like_a_broken_plugin() -> None:
    result = FakePluginExecutor().run(PluginRunRequest(manifest=MANIFEST, workspace="/ws"))

    assert result.outcome is RunOutcome.FAILED and result.exit_code is None


def test_requests_are_serializable() -> None:
    request = FeedsSyncRequest(manifest=manifest(feeds=FEEDS), snapshot_dir="/cache/s")

    assert FeedsSyncRequest.model_validate_json(request.model_dump_json()) == request
    assert FakePluginExecutor().sync_feeds(request).output_dir == "/cache/s"


def test_source_reader_confines_and_limits_reads() -> None:
    reader = InMemorySourceReader({"/out": {"a.sarif": b"{}", "big": b"x" * 10}})

    assert reader.list_files("/out") == ["a.sarif", "big"]
    assert reader.read_file("/out", "a.sarif", 10) == b"{}"
    for bad in ("../etc/passwd", "/etc/passwd", "missing", ""):
        with pytest.raises(SourceError):
            reader.read_file("/out", bad, 10)
    with pytest.raises(SourceTooLarge, match="supera") as info:
        reader.read_file("/out", "big", 9)
    assert isinstance(info.value, SourceError)
    for bad in ("a/./b", "a//b", "a/b/", "./a"):
        with pytest.raises(SourceError):
            reader.read_file("/out", bad, 10)


def test_artifact_sink_stores_and_rejects_escaping_names() -> None:
    sink = InMemoryArtifactSink()

    ref = sink.write("reports/r.json", b"abc")

    assert ref.size == 3 and ref.location.endswith("reports/r.json")
    assert sink.artifacts["reports/r.json"] == b"abc"
    for bad in ("../x", "/abs", "", "a/./b", "a//b"):
        with pytest.raises(ValueError):
            sink.write(bad, b"")


def test_clock_is_fixed_until_advanced_and_aware() -> None:
    clock = FixedClock(datetime(2026, 5, 1, tzinfo=UTC))
    first = clock.now()
    assert clock.now() == first
    clock.advance(90)
    assert (clock.now() - first).total_seconds() == 90
    with pytest.raises(ValueError):
        FixedClock(datetime(2026, 5, 1))


def test_executor_reports_its_isolation_before_running() -> None:
    assert FakePluginExecutor().isolation() is Isolation.HARDENED_CONTAINER
    assert FakePluginExecutor(isolation=Isolation.GVISOR).isolation() is Isolation.GVISOR


def test_failed_run_has_no_output_dir_and_roundtrips() -> None:
    result = FakePluginExecutor().run(PluginRunRequest(manifest=MANIFEST, workspace="/ws"))

    assert result.output_dir is None
    assert PluginRunResult.model_validate_json(result.model_dump_json()) == result


def test_request_inputs_must_match_the_manifest() -> None:
    with_inputs = manifest(
        inputs={"workspace": "readonly", "sbom": "optional", "config": "optional"}, feeds=FEEDS
    )
    PluginRunRequest(
        manifest=with_inputs, workspace="/w", sbom="/s", config="/c", feeds_snapshot="/f"
    )
    for field in ("sbom", "config", "feeds_snapshot"):
        with pytest.raises(ValidationError):
            PluginRunRequest(manifest=MANIFEST, workspace="/w", **{field: "/x"})


def test_feeds_sync_requires_feeds_in_the_manifest() -> None:
    with pytest.raises(ValidationError, match="feeds"):
        FeedsSyncRequest(manifest=MANIFEST, snapshot_dir="/s")
