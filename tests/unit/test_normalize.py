import copy
import json
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from ca_core import fingerprint as fp
from ca_core.dedup import deduplicate
from ca_core.fakes import FixedClock, InMemorySourceReader
from ca_core.models import PluginManifest
from ca_core.models.finding import Category, Finding
from ca_core.models.plugin_manifest import _EXAMPLE as MINIMAL
from ca_core.normalize import health_finding, normalize_sarif
from ca_core.ports import SourceError, SourceTooLarge
from ca_core.sarif import ParsedSarif, SarifError, SarifErrorCode, parse_sarif
from ca_core.schema_validation import SchemaStore

ROOT = Path(__file__).resolve().parents[2]
SAMPLES = ROOT / "tests" / "fixtures" / "plugin-output"
NOW = datetime(2026, 5, 6, 7, 8, tzinfo=UTC)
SECRET_HASH = "ab" * 32
SOURCE = "import os\nsubprocess.run(x, shell=True)\nsubprocess.run(x, shell=True)\nend\n"
WS = "/ws"


@pytest.fixture(scope="module")
def store() -> SchemaStore:
    return SchemaStore(ROOT / "schemas" / "vendor")


def manifest(name: str = "bandit", *categories: str) -> PluginManifest:
    return PluginManifest.model_validate(
        {**copy.deepcopy(MINIMAL), "name": name, "categories": list(categories or ["sast"])}
    )


def result(
    rule: str = "B602",
    uri: str | None = "app.py",
    line: int | None = 2,
    column: int = 1,
    **properties: Any,
) -> dict[str, Any]:
    physical: dict[str, Any] = {}
    if uri is not None:
        physical["artifactLocation"] = {"uri": uri}
    if line is not None:
        physical["region"] = {
            "startLine": line,
            "startColumn": column,
            "endLine": line,
            "endColumn": column + 5,
        }
    out: dict[str, Any] = {"ruleId": rule, "message": {"text": "m"}, "level": "warning"}
    if physical:
        out["locations"] = [{"physicalLocation": physical}]
    if properties:
        out["properties"] = properties
    return out


def sarif(store: SchemaStore, results: list[dict[str, Any]]) -> ParsedSarif:
    document = {
        "version": "2.1.0",
        "runs": [{"tool": {"driver": {"name": "x"}}, "results": results}],
    }
    return parse_sarif(json.dumps(document).encode(), store)


def run(
    store: SchemaStore,
    results: list[dict[str, Any]],
    *,
    plugin: PluginManifest | None = None,
    reader: Any = None,
    commit: str | None = "c0ffee",
    **kwargs: Any,
) -> list[Finding]:
    return normalize_sarif(
        sarif(store, results),
        manifest=plugin or manifest(),
        repository="repo",
        commit=commit,
        workspace=WS,
        reader=reader or InMemorySourceReader({WS: {"app.py": SOURCE.encode()}}),
        clock=FixedClock(NOW),
        **kwargs,
    )


def failure(store: SchemaStore, results: list[dict[str, Any]], **kwargs: Any) -> SarifError:
    with pytest.raises(SarifError) as info:
        run(store, results, **kwargs)
    return info.value


def code_fp(line: int, occurrence: int = 0, source: str = SOURCE, rule: str = "B602") -> str:
    return fp.fingerprint_code(
        rule_id=rule,
        tool="bandit",
        path="app.py",
        source=source,
        start_line=line,
        occurrence=occurrence,
    )


def test_code_finding_fields_and_clock(store: SchemaStore) -> None:
    (finding,) = run(store, [result(tool_severity="HIGH")])

    assert finding.fingerprint == finding.id == code_fp(2)
    assert (finding.category, finding.rule_id, finding.tool, finding.tools) == (
        Category.SAST,
        "B602",
        "bandit",
        ["bandit"],
    )
    assert finding.location.model_dump(exclude={"dependency_path"}) == {
        "repository": "repo",
        "commit": "c0ffee",
        "path": "app.py",
        "start_line": 2,
        "end_line": 2,
        "purl": None,
    }
    assert finding.first_seen == finding.last_seen == NOW
    assert finding.evidence == {"bandit": {"sarif_level": "warning", "tool_severity": "HIGH"}}
    assert finding.level is None and finding.score is None and finding.impact is None


def test_folder_without_git_has_no_commit(store: SchemaStore) -> None:
    (finding,) = run(store, [result()], commit=None)

    assert finding.location.commit is None


def test_results_at_different_places_have_distinct_fingerprints_in_any_order(
    store: SchemaStore,
) -> None:
    results = [result(line=3), result(line=2), result(line=3, column=9)]

    fingerprints = [f.fingerprint for f in run(store, results)]

    assert len(set(fingerprints)) == 3
    assert fingerprints == [f.fingerprint for f in run(store, results[::-1])][::-1]


def test_two_results_at_the_same_position_share_the_fingerprint(store: SchemaStore) -> None:
    first, second = run(store, [result(line=2), result(line=2)])

    assert first.fingerprint == second.fingerprint  # li fonde la deduplica
    assert len(deduplicate([first, second])) == 1


def test_same_context_gets_occurrence_indexes_by_position(store: SchemaStore) -> None:
    source = "x\nx\nx\n"
    reader = InMemorySourceReader({WS: {"app.py": source.encode()}})

    first, second = run(store, [result(line=2, column=7), result(line=2, column=1)], reader=reader)

    assert first.fingerprint == code_fp(2, 1, source)
    assert second.fingerprint == code_fp(2, 0, source)


def test_result_without_region_has_no_context(store: SchemaStore) -> None:
    (finding,) = run(store, [result(line=None)])

    assert finding.fingerprint == code_fp(1, 0, "")
    assert finding.location.start_line is None


def test_file_over_the_limit_has_no_context_but_real_positions(store: SchemaStore) -> None:
    class Big(InMemorySourceReader):
        def read_file(self, root: str, path: str, max_bytes: int) -> bytes:
            raise SourceTooLarge(path)

    first, second = run(store, [result(line=2), result(line=3)], reader=Big())

    assert first.fingerprint == code_fp(1, 0, "")
    assert second.fingerprint == code_fp(1, 1, "")
    assert first.location.start_line == 2  # la posizione resta nel finding


def test_other_source_errors_fail_the_plugin(store: SchemaStore) -> None:
    for results in ([result(uri="missing.py")], [result(line=None, uri="missing.py")]):
        error = failure(store, results)
        assert error.code is SarifErrorCode.SOURCE
        assert "missing.py" not in str(error) + "".join(error.details)


def test_symlink_escaping_the_workspace_fails_the_plugin(store: SchemaStore) -> None:
    class Escaping(InMemorySourceReader):
        def read_file(self, root: str, path: str, max_bytes: int) -> bytes:
            raise SourceError("symlink fuori dalla radice")

    assert failure(store, [result()], reader=Escaping()).code is SarifErrorCode.SOURCE


@pytest.mark.parametrize(
    "uri",
    [
        "file:///etc/passwd",
        "/etc/passwd",
        "\\windows",
        "C:/x.py",
        "../x.py",
        "a/../../x.py",
        "a/./b.py",
        "%2e%2e/x.py",
        "a%2F..%2Fb.py",
        "%2Fetc/passwd",
        "a//b.py",
        "a/",
        "a%00b.py",
        "a\ud800b.py",
        "a.py?x=1",
        "a.py#L1",
        "",
    ],
)
def test_unsafe_uris_fail_the_plugin(store: SchemaStore, uri: str) -> None:
    assert failure(store, [result(uri=uri, line=None)]).code is SarifErrorCode.URI


def test_uri_base_id_is_refused(store: SchemaStore) -> None:
    raw = result()
    raw["locations"][0]["physicalLocation"]["artifactLocation"]["uriBaseId"] = "ROOT"

    assert failure(store, [raw]).code is SarifErrorCode.URI


def test_percent_encoded_path_is_decoded(store: SchemaStore) -> None:
    reader = InMemorySourceReader({WS: {"a b/è.py": SOURCE.encode()}})

    (finding,) = run(store, [result(uri="a%20b/%C3%A8.py")], reader=reader)

    assert finding.location.path == "a b/è.py"


def test_dependency_ids_are_the_union_of_rule_and_aliases(store: SchemaStore) -> None:
    raw = result(
        "GHSA-aaaa",
        uri="package-lock.json",
        line=None,
        category="dependency",
        purl="pkg:npm/lodash@4.17.0",
        aliases=["CVE-2021-1", "GHSA-aaaa", "CVE-2020-9"],
        cvss={"version": "3.1", "vector": "CVSS:3.1/AV:N", "score": 7.5},
        secret_sha256=SECRET_HASH,
    )
    plugin = manifest("osv-scanner", "dependency")
    (finding,) = run(store, [raw], plugin=plugin)

    expected = fp.fingerprint_dependency(
        vuln_ids=["GHSA-aaaa", "CVE-2020-9"], purl="pkg:npm/lodash"
    )
    assert finding.fingerprint == expected
    assert finding.rule_id == finding.title == "CVE-2020-9"
    assert finding.cve == ["CVE-2020-9", "CVE-2021-1"]
    assert finding.location.purl == "pkg:npm/lodash@4.17.0"
    assert finding.evidence["osv-scanner"]["cvss"]["score"] == 7.5
    assert SECRET_HASH not in finding.model_dump_json()


def test_two_scanners_on_the_same_vulnerability_fuse(store: SchemaStore) -> None:
    def one(name: str, rule: str, aliases: list[str]) -> Finding:
        raw = result(
            rule,
            uri="package-lock.json",
            line=None,
            category="dependency",
            purl="pkg:npm/lodash@4.17.0",
            aliases=aliases,
        )
        return run(store, [raw], plugin=manifest(name, "dependency"))[0]

    osv = one("osv-scanner", "GHSA-aaaa", ["CVE-2021-1"])
    trivy = one("trivy", "CVE-2021-1", [])

    (merged,) = deduplicate([trivy, osv])
    assert merged.tools == ["osv-scanner", "trivy"]


def test_dependency_requires_purl(store: SchemaStore) -> None:
    raw = result("CVE-1", uri="x", line=None, category="dependency")

    error = failure(store, [raw], plugin=manifest("osv-scanner", "dependency"))

    assert error.code is SarifErrorCode.PROPERTIES
    # il vincolo `category` -> `purl` è nello schema delle proprietà: l'errore punta all'oggetto
    assert error.details[0].startswith("/runs/0/results/0/properties")


def test_secret_uses_hash_only_and_never_copies_it_or_the_scanner_text(
    store: SchemaStore,
) -> None:
    raw = result("github-pat", uri="conf.py", category="secret", secret_sha256=SECRET_HASH)
    raw["message"] = {"text": "ghp_SENTINELLA"}  # il testo dello scanner non entra nel report

    (finding,) = run(store, [raw], plugin=manifest("gitleaks", "secret"))

    assert finding.fingerprint == fp.fingerprint_secret(
        rule_id="github-pat", path="conf.py", value_sha256=SECRET_HASH
    )
    dumped = finding.model_dump_json()
    assert SECRET_HASH not in dumped and "SENTINELLA" not in dumped
    assert finding.category is Category.SECRET


def test_secret_needs_hash_and_path_only_syntactically(store: SchemaStore) -> None:
    plugin = manifest("gitleaks", "secret")
    # nessun accesso al file: nel workspace può non esistere, solo nella storia
    (finding,) = run(
        store,
        [result("r", uri="gone.py", category="secret", secret_sha256=SECRET_HASH)],
        plugin=plugin,
    )
    assert finding.location.path == "gone.py"
    assert failure(store, [result("r", category="secret")], plugin=plugin).code is (
        SarifErrorCode.PROPERTIES
    )


def test_category_rules(store: SchemaStore) -> None:
    both = manifest("trivy", "dependency", "iac")
    assert failure(store, [result()], plugin=both).code is SarifErrorCode.MAPPING  # ambigua
    undeclared = result(category="secret", secret_sha256=SECRET_HASH)
    assert failure(store, [undeclared], plugin=both).code is SarifErrorCode.MAPPING
    (iac,) = run(store, [result("AVD-1", category="iac")], plugin=both)
    assert iac.category is Category.IAC
    # `quality` e' `code` e `test` e' `coverage` dalla Fase 2 (ADR-0026); `architecture` con G-10.
    assert (
        failure(store, [result()], plugin=manifest("x", "architecture")).code
        is SarifErrorCode.MAPPING
    )
    (quality,) = run(store, [result("F401")], plugin=manifest("ruff", "quality"))
    assert quality.category is Category.QUALITY


def test_license_kinds(store: SchemaStore) -> None:
    plugin = manifest("scan", "license")
    package = result("l", uri="x", line=None, license_spdx="MIT", purl="pkg:npm/a@1")
    file = result("l", uri="LICENSE", line=None, license_spdx="Apache-2.0")

    one, two = run(store, [package, file], plugin=plugin)

    assert one.fingerprint == fp.fingerprint_license_package(spdx="MIT", purl="pkg:npm/a@1")
    assert two.fingerprint == fp.fingerprint_license_file(path="LICENSE", spdx="Apache-2.0")
    assert (one.rule_id, one.license_spdx) == ("ca.license", "MIT")
    assert failure(store, [result("l", uri="x", line=None)], plugin=plugin).code is (
        SarifErrorCode.MAPPING
    )


def test_health_kind_and_helper(store: SchemaStore) -> None:
    plugin = manifest("semgrep", "health")
    (finding,) = run(store, [result("whatever", uri=None, line=None)], plugin=plugin)
    helper = health_finding(
        "semgrep", "timeout", repository="repo", commit=None, clock=FixedClock(NOW)
    )

    assert finding.fingerprint == helper.fingerprint == fp.fingerprint_health(plugin="semgrep")
    assert helper.rule_id == "ca.scanner-not-run" and helper.location.path is None
    assert helper.first_seen == NOW


def test_missing_rule_id_and_invalid_region_fail(store: SchemaStore) -> None:
    raw = result()
    del raw["ruleId"]
    assert failure(store, [raw]).code is SarifErrorCode.MAPPING
    bad = result()
    bad["locations"][0]["physicalLocation"]["region"]["endLine"] = 1
    assert failure(store, [bad]).code is SarifErrorCode.MAPPING


def test_long_text_is_capped(store: SchemaStore) -> None:
    raw = result()
    raw["message"] = {"text": "x" * 100_000}

    assert len(run(store, [raw])[0].message) == 4096


def adapt(name: str, per_result: Callable[[dict[str, Any]], dict[str, Any]]) -> ParsedSarif:
    """Come l'adattatore: URI relativi, niente `snippet` né `properties` dello scanner."""
    document = json.loads((SAMPLES / name).read_bytes())
    for entry in document["runs"][0]["results"]:
        entry.pop("properties", None)
        artifact = entry["locations"][0]["physicalLocation"]["artifactLocation"]
        artifact.pop("uriBaseId", None)
        artifact["uri"] = artifact["uri"].removeprefix("file://").removeprefix("/workspace/")
        artifact["uri"] = artifact["uri"].removeprefix("/workspace/")
        region = entry["locations"][0]["physicalLocation"].get("region", {})
        region.pop("snippet", None)
        entry["properties"] = per_result(entry)
    return parse_sarif(json.dumps(document).encode(), SchemaStore(ROOT / "schemas" / "vendor"))


def test_real_dependency_samples_normalize_one_finding_per_result() -> None:
    for name, tool in (("osv-scanner.sarif", "osv-scanner"), ("trivy.sarif", "trivy")):
        parsed = adapt(
            name,
            lambda e: {
                "category": "dependency",
                "purl": f"pkg:npm/{e['ruleId'].lower()}@1",
                "aliases": [e["ruleId"]],
            },
        )
        findings = normalize_sarif(
            parsed,
            manifest=manifest(tool, "dependency", "iac"),
            repository="repo",
            commit=None,
            workspace=WS,
            reader=InMemorySourceReader(),
            clock=FixedClock(NOW),
        )

        assert len(findings) == len(parsed.results) > 0
        assert all(f.category is Category.DEPENDENCY for f in findings)


@pytest.mark.parametrize(
    ("name", "tool"), [("bandit.sarif", "bandit"), ("semgrep.sarif", "semgrep")]
)
def test_real_code_samples_normalize(name: str, tool: str) -> None:
    parsed = adapt(name, lambda e: {})
    files = {
        r.data["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
        for r in parsed.results
    }
    reader = InMemorySourceReader({WS: {f: SOURCE.encode() for f in files}})

    findings = normalize_sarif(
        parsed,
        manifest=manifest(tool, "sast"),
        repository="repo",
        commit=None,
        workspace=WS,
        reader=reader,
        clock=FixedClock(NOW),
    )

    assert len(findings) == len(parsed.results) > 0
    assert {f.location.path for f in findings} == files


@settings(max_examples=50, deadline=None)
@given(data=st.data())
def test_fingerprints_do_not_depend_on_result_order(data: st.DataObject) -> None:
    store = SchemaStore(ROOT / "schemas" / "vendor")
    results = [result(line=n, column=c) for n in (1, 2, 3) for c in (1, 4)]
    shuffled = data.draw(st.permutations(results))

    assert sorted(f.fingerprint for f in run(store, shuffled)) == sorted(
        f.fingerprint for f in run(store, results)
    )


def test_coverage_result_without_a_region_gets_the_coverage_fingerprint(store: SchemaStore) -> None:
    plugin = manifest("coverage", "test")
    props = {"tool_severity": "medium", "metric": {"value": 20, "threshold": 50}}
    (finding,) = run(
        store,
        [result("ca.coverage.low-file-coverage", uri="pkg/a.py", line=None, **props)],
        plugin=plugin,
    )
    assert finding.category is Category.TEST
    assert finding.fingerprint == fp.fingerprint_coverage(
        rule_id="ca.coverage.low-file-coverage", path="pkg/a.py"
    )
    assert finding.evidence["coverage"]["metric"] == {"value": 20, "threshold": 50}
    assert finding.location.start_line is None


def test_coverage_result_needs_a_path(store: SchemaStore) -> None:
    plugin = manifest("coverage", "test")
    error = failure(store, [result("r", uri=None, line=None)], plugin=plugin)
    assert error.code is SarifErrorCode.MAPPING
