"""K-16 (`run_plugins` a due stadi) e K-17 (`normalize`) con le porte finte."""

import copy
import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from ca_core.fakes import FakePluginExecutor, FixedClock, InMemorySourceReader
from ca_core.models import CodeAnalyzerConfig, PackagedPluginManifest
from ca_core.models.finding import Category, Level, Status
from ca_core.models.plugin_manifest import _EXAMPLE as BASE
from ca_core.models.scan_report import Outcome, ReportStatus, ScanReport
from ca_core.pipeline.normalize import NormalizeRequest, NormalizeResult, normalize
from ca_core.pipeline.run_plugins import RunPluginsRequest, RunPluginsResult, run_plugins
from ca_core.pipeline.workspace import Workspace
from ca_core.ports import (
    PluginRunRequest,
    PluginRunResult,
    RunOutcome,
    ScanAborted,
    Signature,
)
from ca_core.schema_validation import SchemaStore

ROOT = Path(__file__).resolve().parents[2]
SYFT = (ROOT / "tests" / "fixtures" / "plugin-output" / "syft.cdx.json").read_bytes()
DIGEST = "sha256:" + "a" * 64
WS = "/ws"
SOURCE = b"import os\nsubprocess.run(x, shell=True)\nend\n"


@pytest.fixture(scope="module")
def store() -> SchemaStore:
    return SchemaStore(ROOT / "schemas" / "vendor")


def manifest(name: str, **kv: Any) -> PackagedPluginManifest:
    data = {
        **copy.deepcopy(BASE),
        "name": name,
        "image": f"registry.invalid/ca/{name}:1.0.0@{DIGEST}",
        **kv,
    }
    return PackagedPluginManifest.model_validate(data)


def sbom_producer(name: str = "syft") -> PackagedPluginManifest:
    return manifest(
        name,
        languages=[],
        categories=["dependency"],
        outputs={"cyclonedx": "/out/sbom.cdx.json", "cyclonedx_version": "1.7", "max_bytes": 10**7},
    )


def scanner(name: str, *, sbom: str = "none", **kv: Any) -> PackagedPluginManifest:
    return manifest(
        name,
        inputs={"workspace": "readonly", "sbom": sbom},
        outputs={"sarif": "/out/results.sarif", "max_bytes": 10**6},
        **kv,
    )


def sarif(results: list[dict[str, Any]]) -> bytes:
    run = {"tool": {"driver": {"name": "x"}}, "results": results}
    return json.dumps({"version": "2.1.0", "runs": [run]}).encode()


def code_result(rule: str = "B602", uri: str = "app.py", **props: Any) -> dict[str, Any]:
    region = {"startLine": 2, "startColumn": 1, "endLine": 2, "endColumn": 6}
    return {
        "ruleId": rule,
        "message": {"text": "m"},
        "level": "warning",
        "locations": [{"physicalLocation": {"artifactLocation": {"uri": uri}, "region": region}}],
        "properties": props or {"tool_severity": "HIGH"},
    }


def license_result(spdx: str, purl: str = "pkg:npm/lodash@4.17.15") -> dict[str, Any]:
    return {
        "ruleId": "license",
        "message": {"text": "m"},
        "properties": {"category": "license", "purl": purl, "license_spdx": spdx},
    }


def workspace(*languages: str) -> Workspace:
    return Workspace(
        path=WS, detected_languages=list(languages), languages=list(languages), file_count=1
    )


def ok(dirname: str) -> PluginRunResult:
    return FakePluginExecutor.ok(dirname)


def call(
    manifests: list[PackagedPluginManifest],
    executor: FakePluginExecutor,
    store: SchemaStore,
    files: dict[str, dict[str, bytes]] | None = None,
    *,
    languages: tuple[str, ...] = ("python",),
    disabled: list[str] | None = None,
) -> RunPluginsResult:
    request = RunPluginsRequest(
        repository="repo",
        workspace=workspace(*languages),
        manifests=manifests,
        disabled=disabled or [],
    )
    return run_plugins(request, executor, InMemorySourceReader(files or {}), store, FixedClock())


# --- K-16 -------------------------------------------------------------------------------------


def test_sbom_stage_runs_first_and_feeds_optional_consumers(store: SchemaStore) -> None:
    executor = FakePluginExecutor(
        {"syft": ok("/o/syft"), "osv": ok("/o/osv"), "bandit": ok("/o/bandit")}
    )
    manifests = [
        scanner("osv", sbom="optional"),
        scanner("bandit"),
        sbom_producer(),
    ]

    result = call(manifests, executor, store, {"/o/syft": {"sbom.cdx.json": SYFT}})

    assert [r.manifest.name for r in executor.runs] == ["syft", "bandit", "osv"]
    by_name = {r.manifest.name: r for r in executor.runs}
    assert by_name["osv"].sbom == "/o/syft/sbom.cdx.json"
    assert by_name["bandit"].sbom is None and by_name["syft"].sbom is None
    assert result.sbom_from == "syft" and result.status is ReportStatus.COMPLETE
    assert all(e.run.signature is Signature.VERIFIED for e in result.executions)
    assert result.executions[0].run.digest == DIGEST


def test_no_sbom_available_runs_second_stage_without_it(store: SchemaStore) -> None:
    executor = FakePluginExecutor({"osv": ok("/o/osv")})

    result = call([scanner("osv", sbom="optional")], executor, store)

    assert executor.runs[0].sbom is None and result.sbom_from is None


@pytest.mark.parametrize(
    "content",
    [None, b"not json", SYFT.replace(b'"1.7"', b'"1.6"', 1)],
    ids=["missing", "invalid", "wrong-version"],
)
def test_unusable_sbom_fails_producer_only(store: SchemaStore, content: bytes | None) -> None:
    executor = FakePluginExecutor({"syft": ok("/o/syft"), "osv": ok("/o/osv")})
    files = {"/o/syft": {} if content is None else {"sbom.cdx.json": content}}

    result = call([sbom_producer(), scanner("osv", sbom="optional")], executor, store, files)

    outcomes = {e.run.name: e.run.outcome for e in result.executions}
    assert outcomes == {"syft": Outcome.FAILED, "osv": Outcome.OK}
    assert executor.runs[-1].sbom is None
    assert result.status is ReportStatus.PARTIAL
    [health] = result.health
    assert (health.rule_id, health.category, health.location.path) == (
        "ca.scanner-not-run",
        Category.HEALTH,
        None,
    )


@pytest.mark.parametrize("outcome", [RunOutcome.FAILED, RunOutcome.TIMEOUT])
def test_failed_plugin_does_not_stop_others(store: SchemaStore, outcome: RunOutcome) -> None:
    bad = PluginRunResult(
        outcome=outcome,
        exit_code=1,
        isolation=FakePluginExecutor().isolation(),
        duration_seconds=1,
        output_dir=None,
        detail="causa generica",
    )
    executor = FakePluginExecutor({"a-bad": bad, "b-good": ok("/o/b")})

    result = call([scanner("b-good"), scanner("a-bad")], executor, store)

    runs = {e.run.name: e.run for e in result.executions}
    assert runs["a-bad"].outcome is Outcome.FAILED and "causa generica" in (
        runs["a-bad"].failure or ""
    )
    assert runs["b-good"].outcome is Outcome.OK
    assert result.status is ReportStatus.PARTIAL and [h.tool for h in result.health] == ["a-bad"]


def test_language_filter_and_disabled(store: SchemaStore) -> None:
    executor = FakePluginExecutor({"bandit": ok("/o/b"), "any": ok("/o/a")})
    manifests = [
        scanner("bandit", languages=["python"]),
        scanner("eslint", languages=["javascript"]),
        scanner("any", languages=[]),
        scanner("off"),
    ]

    result = call(manifests, executor, store, disabled=["off", "ghost"])

    assert [e.run.name for e in result.executions] == ["any", "bandit"]
    assert result.skipped_by_language == ["eslint"] and result.disabled == ["off"]


def test_scan_abort_from_executor_propagates(store: SchemaStore) -> None:
    def boom(request: PluginRunRequest) -> PluginRunResult:
        raise ScanAborted("firma non valida")

    with pytest.raises(ScanAborted) as info:
        call([scanner("bandit")], FakePluginExecutor({"bandit": boom}), store)
    assert info.value.exit_code == 2


def test_signature_skipped_is_recorded(store: SchemaStore) -> None:
    skipped = ok("/o/b").model_copy(update={"signature": Signature.SKIPPED})

    result = call([scanner("bandit")], FakePluginExecutor({"bandit": skipped}), store)

    assert result.executions[0].run.signature is Signature.SKIPPED


# --- K-17 -------------------------------------------------------------------------------------


def config(**kv: Any) -> CodeAnalyzerConfig:
    return CodeAnalyzerConfig.model_validate({"version": 1, **kv})


def pipeline(
    store: SchemaStore,
    files: dict[str, dict[str, bytes]],
    *,
    manifests: list[PackagedPluginManifest],
    cfg: CodeAnalyzerConfig | None = None,
    wrap: Callable[[InMemorySourceReader], Any] = lambda r: r,
) -> tuple[NormalizeResult, NormalizeRequest, Any]:
    cfg = cfg or config()
    reader = wrap(InMemorySourceReader({WS: {"app.py": SOURCE, "dist/x.py": SOURCE}, **files}))
    executor = FakePluginExecutor({m.name: ok(f"/o/{m.name}") for m in manifests})
    clock = FixedClock()
    plan = run_plugins(
        RunPluginsRequest(
            repository="repo",
            workspace=workspace("python"),
            manifests=manifests,
            disabled=cfg.plugins.disable,
        ),
        executor,
        reader,
        store,
        clock,
    )
    request = NormalizeRequest(
        repository="repo", workspace=WS, executions=plan.executions, config=cfg
    )
    return normalize(request, reader, store, clock), request, reader


def test_normalize_is_idempotent_and_ordered(store: SchemaStore) -> None:
    files = {
        "/o/bandit": {
            "results.sarif": sarif([code_result(), code_result("B101", tool_severity="LOW")])
        },
        "/o/syft": {"sbom.cdx.json": SYFT},
    }
    result, request, reader = pipeline(
        store, files, manifests=[scanner("bandit", languages=["python"]), sbom_producer()]
    )

    again = normalize(request, reader, store, FixedClock())

    assert again == result
    assert [f.level for f in result.findings] == [Level.HIGH, Level.LOW]
    assert result.status is ReportStatus.COMPLETE and result.warnings[0].code == (
        "license-policy-absent"
    )
    # il risultato è serializzabile e compone un report valido
    NormalizeResult.model_validate_json(result.model_dump_json())
    ScanReport.model_validate(
        {
            "version": 1,
            "status": result.status,
            "started_at": FixedClock().now(),
            "duration_seconds": 1.0,
            "repository": {"name": "repo", "history": "absent"},
            "gate": {"mode": "all", "effective_mode": "all"},
            "plugins": result.plugins,
            "findings": result.findings,
            "warnings": result.warnings,
            "exclusions": result.exclusions,
        }
    )


def test_exclusions_exceptions_and_dedup(store: SchemaStore) -> None:
    files = {
        "/o/bandit": {
            "results.sarif": sarif([code_result(), code_result(uri="dist/x.py", rule="B1")])
        }
    }
    base, _, _ = pipeline(store, files, manifests=[scanner("bandit")])
    assert [f.location.path for f in base.findings] == ["app.py"]  # `dist` escluso di default

    fingerprint = base.findings[0].fingerprint
    exc = {
        "fingerprint": fingerprint,
        "reason": "ok",
        "expires": "2099-01-01",
        "approved_by": "@sec",
    }
    result, _, _ = pipeline(
        store, files, manifests=[scanner("bandit")], cfg=config(exceptions=[exc])
    )
    assert result.findings[0].status is Status.ACCEPTED
    assert [e.fingerprint for e in result.exceptions] == [fingerprint]


def test_license_policy_consumes_declared_and_detected(store: SchemaStore) -> None:
    files = {
        "/o/scancode": {"results.sarif": sarif([license_result("GPL-3.0-only")])},
        "/o/syft": {"sbom.cdx.json": SYFT},
    }
    manifests = [scanner("scancode", categories=["license"]), sbom_producer()]

    absent, _, _ = pipeline(store, files, manifests=manifests)
    assert absent.findings == [] and absent.warnings[0].code == "license-policy-absent"

    cfg = config(licenses={"forbidden": ["GPL-3.0-only"], "require_approval": ["MIT"]})
    result, _, _ = pipeline(store, files, manifests=manifests, cfg=cfg)
    assert {f.tool for f in result.findings} == {"ca-core"}
    assert all(f.category is Category.LICENSE and f.level is not None for f in result.findings)
    # componenti senza licenza dichiarata: ignota (NOASSERTION), come da ADR-0013
    assert {f.license_spdx for f in result.findings} == {"GPL-3.0-only", "MIT", "NOASSERTION"}


@pytest.mark.parametrize(
    "document",
    [
        sarif([code_result(tool_severity="HIGH", snippet="x")]),  # K-10: chiave snippet
        b"not json",
        sarif([code_result(uri="/etc/passwd")]),  # percorso assoluto
        None,  # file mancante
    ],
    ids=["snippet", "not-json", "absolute-uri", "missing"],
)
def test_unusable_sarif_fails_only_that_plugin(store: SchemaStore, document: bytes | None) -> None:
    files = {
        "/o/bad": {} if document is None else {"results.sarif": document},
        "/o/bandit": {"results.sarif": sarif([code_result()])},
    }

    result, _, _ = pipeline(store, files, manifests=[scanner("bad"), scanner("bandit")])

    runs = {p.name: p for p in result.plugins}
    assert runs["bad"].outcome is Outcome.FAILED and runs["bandit"].outcome is Outcome.OK
    assert result.status is ReportStatus.PARTIAL
    assert {(f.tool, f.category) for f in result.findings} == {
        ("bad", Category.HEALTH),
        ("bandit", Category.SAST),
    }
    assert "snippet" not in (runs["bad"].failure or "")


def test_structural_check_applies_to_gitleaks(store: SchemaStore) -> None:
    leaky = {
        "ruleId": "r",
        "message": {"text": "found SECRETVALUE"},
        "locations": [{"physicalLocation": {"artifactLocation": {"uri": "app.py"}}}],
        "properties": {"secret_sha256": "ab" * 32},
    }
    files = {"/o/gitleaks": {"results.sarif": sarif([leaky])}}

    result, _, _ = pipeline(store, files, manifests=[scanner("gitleaks", categories=["secret"])])

    assert result.plugins[0].outcome is Outcome.FAILED
    dumped = result.model_dump_json()
    assert "SECRETVALUE" not in dumped and "ab" * 32 not in dumped


def test_secret_hash_never_enters_report(store: SchemaStore) -> None:
    uri = "app.py"
    clean = {
        "ruleId": "r",
        "message": {"text": f"r has detected secret for file {uri}."},
        "locations": [{"physicalLocation": {"artifactLocation": {"uri": uri}}}],
        "properties": {"secret_sha256": "ab" * 32},
    }
    files = {"/o/gitleaks": {"results.sarif": sarif([clean])}}

    result, _, _ = pipeline(store, files, manifests=[scanner("gitleaks", categories=["secret"])])

    assert result.plugins[0].outcome is Outcome.OK and len(result.findings) == 1
    assert "ab" * 32 not in result.model_dump_json()
