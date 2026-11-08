"""`plugin-manifest`: forma sorgente (radice) e forma impacchettata (PackagedPluginManifest)."""

import pytest
from conftest import Json, errors_of, make_validator, mutated

SOURCE = make_validator("plugin-manifest")
PACKAGED = make_validator("plugin-manifest", "PackagedPluginManifest")
DIGEST = "@sha256:" + "0" * 64

MINIMAL: Json = {
    "apiVersion": "code-analyzer/v1",
    "name": "semgrep",
    "version": "1.0.0",
    "image": "registry.invalid/ca-plugins/semgrep:1.0.0",
    "capabilities": ["detect"],
    "languages": ["python", "c++", "c#"],
    "categories": ["sast"],
    "inputs": {"workspace": "readonly"},
    "outputs": {"max_bytes": 1000, "sarif": "/out/results.sarif"},
    "resources": {"cpu": "2", "memory": "2Gi", "pids": 256, "timeout": "600s"},
    "network": "none",
}
FEEDS: Json = {"ecosystems": ["npm", "PyPI"], "sync_command": ["osv-sync"], "sync_timeout": "900s"}
CDX_ONLY: Json = {"max_bytes": 1, "cyclonedx": "/out/sbom.cdx.json", "cyclonedx_version": "1.7"}


def _with(**kv: object):
    return lambda i: i.update(kv)


def _in(section: str, **kv: object):
    return lambda i: i[section].update(kv)


def _drop(key: str):
    return lambda i: i.pop(key)


SOURCE_VALID = {
    "minimal": MINIMAL,
    "with-digest": mutated(MINIMAL, _with(image=MINIMAL["image"] + DIGEST)),
    "image-registry-port": mutated(MINIMAL, _with(image="localhost:5000/ca/x:1")),
    "languages-empty": mutated(MINIMAL, _with(languages=[])),
    "all-capabilities": mutated(MINIMAL, _with(capabilities=["detect", "fix", "enrich"])),
    "inputs-optional": mutated(MINIMAL, _in("inputs", config="optional", sbom="optional")),
    "with-feeds": mutated(MINIMAL, _with(feeds=FEEDS)),
    "feeds-null": mutated(MINIMAL, _with(feeds=None)),
    "cyclonedx-only": mutated(MINIMAL, _with(outputs=CDX_ONLY)),
    "sarif-and-cyclonedx": mutated(MINIMAL, _with(outputs={**MINIMAL["outputs"], **CDX_ONLY})),
    "version-prerelease-build": mutated(MINIMAL, _with(version="1.2.3-rc.1+build.5")),
    "cpu-fractional": mutated(MINIMAL, _in("resources", cpu="0.5")),
    "image-latest-as-repository-part": mutated(MINIMAL, _with(image="r/latest:1.0")),
    "image-latest-prefix-tag": mutated(MINIMAL, _with(image="r/x:latest-1")),
    "max-bytes-at-cap": mutated(MINIMAL, _in("outputs", max_bytes=268435456)),
    "memory-mi": mutated(MINIMAL, _in("resources", memory="512Mi")),
}
SOURCE_INVALID = {
    "image-latest": mutated(MINIMAL, _with(image="r/x:latest")),
    "image-latest-with-digest": mutated(MINIMAL, _with(image="r/x:latest" + DIGEST)),
    "outputs-max-bytes-over-cap": mutated(MINIMAL, _in("outputs", max_bytes=268435457)),
    "cyclonedx-with-optional-sbom-input": mutated(
        MINIMAL, _with(outputs=CDX_ONLY, inputs={"workspace": "readonly", "sbom": "optional"})
    ),
    "sarif-and-cyclonedx-with-optional-sbom-input": mutated(
        MINIMAL,
        _with(
            outputs={**MINIMAL["outputs"], **CDX_ONLY},
            inputs={"workspace": "readonly", "sbom": "optional"},
        ),
    ),
    **{
        f"missing-{k}": mutated(MINIMAL, _drop(k))
        for k in (
            "apiVersion",
            "name",
            "version",
            "image",
            "capabilities",
            "languages",
            "categories",
            "inputs",
            "outputs",
            "resources",
            "network",
        )
    },
    "unknown-top-level": mutated(MINIMAL, _with(command=["sh"])),
    "unknown-key-privileged": mutated(MINIMAL, _with(privileged=True)),
    "apiVersion-v2": mutated(MINIMAL, _with(apiVersion="code-analyzer/v2")),
    "network-feeds-only": mutated(MINIMAL, _with(network="feeds-only")),
    "network-host": mutated(MINIMAL, _with(network="host")),
    "name-uppercase": mutated(MINIMAL, _with(name="Semgrep")),
    "name-leading-digit": mutated(MINIMAL, _with(name="1semgrep")),
    "name-too-long": mutated(MINIMAL, _with(name="a" * 64)),
    "version-two-parts": mutated(MINIMAL, _with(version="1.0")),
    "version-leading-zero": mutated(MINIMAL, _with(version="01.0.0")),
    "image-no-tag": mutated(MINIMAL, _with(image="registry.invalid/ca/semgrep")),
    "image-uppercase": mutated(MINIMAL, _with(image="Registry/ca:1")),
    "image-digest-only": mutated(MINIMAL, _with(image="registry.invalid/ca/x" + DIGEST)),
    "image-short-digest": mutated(MINIMAL, _with(image="r/x:1@sha256:abc")),
    "capabilities-empty": mutated(MINIMAL, _with(capabilities=[])),
    "capabilities-unknown": mutated(MINIMAL, _with(capabilities=["exploit"])),
    "capabilities-duplicate": mutated(MINIMAL, _with(capabilities=["detect", "detect"])),
    "categories-empty": mutated(MINIMAL, _with(categories=[])),
    "categories-unknown": mutated(MINIMAL, _with(categories=["x"])),
    "languages-duplicate": mutated(MINIMAL, _with(languages=["python", "python"])),
    "language-uppercase": mutated(MINIMAL, _with(languages=["Python"])),
    "workspace-readwrite": mutated(MINIMAL, _in("inputs", workspace="readwrite")),
    "inputs-unknown-mount": mutated(MINIMAL, _in("inputs", secrets="optional")),
    "inputs-config-required": mutated(MINIMAL, _in("inputs", config="required")),
    "outputs-without-max-bytes": mutated(MINIMAL, _with(outputs={"sarif": "/out/r.sarif"})),
    "outputs-max-bytes-zero": mutated(MINIMAL, _in("outputs", max_bytes=0)),
    "outputs-no-format": mutated(MINIMAL, _with(outputs={"max_bytes": 1})),
    "outputs-sarif-outside-out": mutated(MINIMAL, _in("outputs", sarif="/etc/passwd")),
    "outputs-sarif-traversal": mutated(MINIMAL, _in("outputs", sarif="/out/../etc/x")),
    "outputs-sarif-subdir": mutated(MINIMAL, _in("outputs", sarif="/out/a/b.sarif")),
    "outputs-cyclonedx-without-version": mutated(
        MINIMAL, _with(outputs={"max_bytes": 1, "cyclonedx": "/out/s.json"})
    ),
    "outputs-cyclonedx-version-1.6": mutated(
        MINIMAL, _with(outputs={**CDX_ONLY, "cyclonedx_version": "1.6"})
    ),
    "outputs-sarif-with-cyclonedx-version": mutated(
        MINIMAL, _in("outputs", cyclonedx_version="1.7")
    ),
    "outputs-unknown-key": mutated(MINIMAL, _in("outputs", spdx="/out/x")),
    "resources-missing-pids": mutated(
        MINIMAL, _with(resources={"cpu": "1", "memory": "1Gi", "timeout": "1s"})
    ),
    "resources-pids-zero": mutated(MINIMAL, _in("resources", pids=0)),
    "resources-cpu-zero": mutated(MINIMAL, _in("resources", cpu="0")),
    "resources-memory-no-unit": mutated(MINIMAL, _in("resources", memory="2048")),
    "resources-timeout-minutes": mutated(MINIMAL, _in("resources", timeout="10m")),
    "resources-timeout-zero": mutated(MINIMAL, _in("resources", timeout="0s")),
    "resources-unknown-key": mutated(MINIMAL, _in("resources", gpus=1)),
    "feeds-missing-sync-command": mutated(
        MINIMAL, _with(feeds={"ecosystems": [], "sync_timeout": "1s"})
    ),
    "feeds-sync-command-empty-element": mutated(
        MINIMAL, _with(feeds={**FEEDS, "sync_command": ["osv-sync", ""]})
    ),
    "feeds-sync-command-only-empty": mutated(MINIMAL, _with(feeds={**FEEDS, "sync_command": [""]})),
    "feeds-empty-sync-command": mutated(MINIMAL, _with(feeds={**FEEDS, "sync_command": []})),
    "feeds-bad-ecosystem": mutated(MINIMAL, _with(feeds={**FEEDS, "ecosystems": ["Maven"]})),
    "feeds-mount-elsewhere": mutated(MINIMAL, _with(feeds={**FEEDS, "mount": "/data"})),
    "feeds-bad-timeout": mutated(MINIMAL, _with(feeds={**FEEDS, "sync_timeout": "15m"})),
    "feeds-unknown-key": mutated(MINIMAL, _with(feeds={**FEEDS, "url": "https://x"})),
}

# Forma impacchettata: stesso schema, ma il digest è obbligatorio (ADR-0005).
PACKAGED_VALID = {
    "digest-pinned": mutated(MINIMAL, _with(image=MINIMAL["image"] + DIGEST)),
    "digest-pinned-with-feeds": mutated(
        MINIMAL, _with(image=MINIMAL["image"] + DIGEST, feeds=FEEDS)
    ),
    "digest-pinned-registry-port": mutated(MINIMAL, _with(image="localhost:5000/ca/x:1" + DIGEST)),
}
PACKAGED_INVALID = {
    "no-digest": MINIMAL,
    "short-digest": mutated(MINIMAL, _with(image="r/x:1@sha256:" + "0" * 63)),
    "uppercase-digest": mutated(MINIMAL, _with(image="r/x:1@sha256:" + "A" * 64)),
    "md5-digest": mutated(MINIMAL, _with(image="r/x:1@md5:" + "0" * 64)),
    "digest-but-no-tag": mutated(MINIMAL, _with(image="r/x" + DIGEST)),
    "digest-but-unknown-key": mutated(MINIMAL, _with(image=MINIMAL["image"] + DIGEST, extra=1)),
    "digest-but-missing-field": mutated(
        MINIMAL, _with(image=MINIMAL["image"] + DIGEST), _drop("resources")
    ),
    "digest-but-network-host": mutated(
        MINIMAL, _with(image=MINIMAL["image"] + DIGEST, network="host")
    ),
    "digest-but-bad-output": mutated(
        MINIMAL, _with(image=MINIMAL["image"] + DIGEST), _in("outputs", sarif="/tmp/x")
    ),
}


@pytest.mark.parametrize("instance", SOURCE_VALID.values(), ids=SOURCE_VALID.keys())
def test_valid_source_manifest_is_accepted(instance: Json) -> None:
    assert errors_of(SOURCE, instance) == []


@pytest.mark.parametrize("instance", SOURCE_INVALID.values(), ids=SOURCE_INVALID.keys())
def test_invalid_source_manifest_is_rejected(instance: Json) -> None:
    assert errors_of(SOURCE, instance) != []


@pytest.mark.parametrize("instance", PACKAGED_VALID.values(), ids=PACKAGED_VALID.keys())
def test_valid_packaged_manifest_is_accepted(instance: Json) -> None:
    assert errors_of(PACKAGED, instance) == []


@pytest.mark.parametrize("instance", PACKAGED_INVALID.values(), ids=PACKAGED_INVALID.keys())
def test_invalid_packaged_manifest_is_rejected(instance: Json) -> None:
    assert errors_of(PACKAGED, instance) != []


@pytest.mark.parametrize("instance", SOURCE_INVALID.values(), ids=SOURCE_INVALID.keys())
def test_packaged_never_accepts_what_source_rejects(instance: Json) -> None:
    """La forma impacchettata restringe quella sorgente, non la allarga."""
    assert errors_of(PACKAGED, instance) != []


def test_digest_is_the_only_difference_for_the_packaged_form() -> None:
    assert errors_of(SOURCE, MINIMAL) == []
    assert errors_of(PACKAGED, MINIMAL) != []
    pinned = mutated(MINIMAL, _with(image=MINIMAL["image"] + DIGEST))
    assert errors_of(SOURCE, pinned) == []
    assert errors_of(PACKAGED, pinned) == []


def test_packaged_def_exists_and_references_root() -> None:
    from conftest import load_schema

    packaged = load_schema("plugin-manifest")["$defs"]["PackagedPluginManifest"]
    assert packaged["allOf"] == [{"$ref": "#"}]
    assert packaged["required"] == ["image"]
