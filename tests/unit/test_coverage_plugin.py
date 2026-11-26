"""Plugin coverage (P-05) senza Docker: manifest, adattatore su workspace reali, Dockerfile.

L'adattatore non ha un motore: tutto si prova con file veri in cartelle temporanee, compresi i
collegamenti simbolici e i report ostili di `tests/fixtures/coverage` (F-03).
"""

import importlib.util
import json
import re
import sys
from pathlib import Path
from typing import Any

import pytest
import yaml
from jsonschema import Draft202012Validator

from ca_core.models import PluginManifest

ROOT = Path(__file__).resolve().parents[2]
COVERAGE = ROOT / "packages/ca-plugins/src/ca_plugins/builtin/coverage"
FIXTURES = ROOT / "tests/fixtures/coverage"
RECORDED = COVERAGE / "fixtures/output/coverage.sample.sarif"

_spec = importlib.util.spec_from_file_location("coverage_adapter", COVERAGE / "coverage_adapter.py")
assert _spec and _spec.loader
adapter = importlib.util.module_from_spec(_spec)
sys.modules["coverage_adapter"] = adapter
_spec.loader.exec_module(adapter)

MANIFEST: dict[str, Any] = yaml.safe_load((COVERAGE / "plugin.yaml").read_text())


def lcov(path: str, hits: list[int]) -> str:
    rows = [f"DA:{i},{h}" for i, h in enumerate(hits, 1)]
    return "\n".join(
        [
            f"SF:{path}",
            *rows,
            f"LF:{len(hits)}",
            f"LH:{sum(h > 0 for h in hits)}",
            "end_of_record",
            "",
        ]
    )


def workspace(tmp_path: Path, files: dict[str, str]) -> Path:
    ws = tmp_path / "ws"
    for rel, text in files.items():
        (ws / rel).parent.mkdir(parents=True, exist_ok=True)
        (ws / rel).write_text(text)
    return ws


def run(
    ws: Path, tmp_path: Path, reports: list[dict[str, Any]] | None
) -> tuple[int, dict[str, Any] | None]:
    config = tmp_path / "config.json"
    if reports is not None:
        config.write_text(json.dumps({"reports": reports}))
    out = tmp_path / "results.sarif"
    code = adapter.run(workspace=str(ws), out_file=str(out), config_file=str(config))
    return code, json.loads(out.read_text()) if out.exists() else None


def report(path: str, fmt: str = "lcov", base_dir: str | None = None) -> dict[str, Any]:
    return {"path": path, "format": fmt, "base_dir": base_dir}


def results(document: dict[str, Any] | None) -> list[dict[str, Any]]:
    assert document is not None
    return document["runs"][0]["results"]


def uris(document: dict[str, Any] | None) -> list[str]:
    return [
        r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] for r in results(document)
    ]


# --- manifest --------------------------------------------------------------------------------


def test_manifest_valid_for_schema_and_model() -> None:
    schema = json.loads((ROOT / "schemas" / "plugin-manifest.schema.json").read_text())
    Draft202012Validator(schema).validate(MANIFEST)
    model = PluginManifest.model_validate(MANIFEST)
    assert (model.name, model.network, model.inputs.config) == ("coverage", "none", "optional")
    assert [c.value for c in model.categories] == ["test"]


def test_manifest_has_no_real_registry_and_no_digest() -> None:
    image = MANIFEST["image"]
    assert image.startswith("registry.invalid/") and "@" not in image and ":latest" not in image


# --- finding ---------------------------------------------------------------------------------


def test_file_under_the_threshold_gives_one_finding_with_the_measured_value(tmp_path: Path) -> None:
    hits = [1] * 8 + [0] * 12  # 20 righe misurabili, 40% coperte
    ws = workspace(tmp_path, {"pkg/a.py": "x\n", "lcov.info": lcov("pkg/a.py", hits)})
    code, document = run(ws, tmp_path, [report("lcov.info")])
    assert code == 0
    [result] = results(document)
    assert result["ruleId"] == "ca.coverage.low-file-coverage"
    assert result["properties"] == {
        "tool_severity": "medium",
        "metric": {"value": 40, "threshold": 50},
    }
    assert "8 su 20" in result["message"]["text"]
    assert "region" not in result["locations"][0]["physicalLocation"]


@pytest.mark.parametrize(
    ("covered", "total", "reported"),
    [(10, 20, False), (9, 20, True), (0, 19, False), (0, 20, True), (20, 20, False)],
)
def test_threshold_and_minimum_lines_are_inclusive_where_the_adr_says(
    tmp_path: Path, covered: int, total: int, reported: bool
) -> None:
    hits = [1] * covered + [0] * (total - covered)
    ws = workspace(tmp_path, {"a.py": "x\n", "lcov.info": lcov("a.py", hits)})
    _, document = run(ws, tmp_path, [report("lcov.info")])
    assert bool(results(document)) is reported


def test_a_file_missing_from_the_report_gives_nothing(tmp_path: Path) -> None:
    ws = workspace(tmp_path, {"a.py": "x\n", "b.py": "x\n", "lcov.info": lcov("a.py", [1] * 20)})
    assert results(run(ws, tmp_path, [report("lcov.info")])[1]) == []


def test_two_reports_on_the_same_file_are_merged_line_by_line(tmp_path: Path) -> None:
    unit = lcov("a.py", [1] * 6 + [0] * 14)  # 30%
    integration = lcov("a.py", [0] * 6 + [1] * 6 + [0] * 8)  # 30%, altre righe
    ws = workspace(tmp_path, {"a.py": "x\n", "u.info": unit, "i.info": integration})
    assert len(results(run(ws, tmp_path, [report("u.info")])[1])) == 1
    assert len(results(run(ws, tmp_path, [report("i.info")])[1])) == 1
    assert results(run(ws, tmp_path, [report("u.info"), report("i.info")])[1]) == []  # 60%


def test_base_dir_makes_report_paths_relative_to_where_the_tests_ran(tmp_path: Path) -> None:
    ws = workspace(
        tmp_path, {"backend/pkg/a.py": "x\n", "backend/lcov.info": lcov("pkg/a.py", [0] * 20)}
    )
    document = run(ws, tmp_path, [report("backend/lcov.info", base_dir="backend")])[1]
    assert uris(document) == ["backend/pkg/a.py"]
    assert (
        results(run(ws, tmp_path, [report("backend/lcov.info")])[1]) == []
    )  # senza base_dir: scartato


def test_entries_for_files_that_do_not_exist_or_are_not_regular_are_discarded(
    tmp_path: Path,
) -> None:
    ws = workspace(tmp_path, {"real.py": "x\n"})
    (ws / "link.py").symlink_to("/etc/hostname")
    (ws / "d").mkdir()
    text = "".join(
        lcov(p, [0] * 20) for p in ("real.py", "ghost.py", "link.py", "d", "../out.py", "/etc/x")
    )
    (ws / "lcov.info").write_text(text)
    assert uris(run(ws, tmp_path, [report("lcov.info")])[1]) == ["real.py"]


def test_symlinked_directory_in_a_report_path_is_discarded(tmp_path: Path) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "x.py").write_text("x\n")
    ws = workspace(tmp_path, {"lcov.info": lcov("sub/x.py", [0] * 20)})
    (ws / "sub").symlink_to(outside)
    assert results(run(ws, tmp_path, [report("lcov.info")])[1]) == []


def test_no_reports_or_no_config_gives_an_empty_valid_sarif(tmp_path: Path) -> None:
    ws = workspace(tmp_path, {"a.py": "x\n"})
    for reports in (None, []):
        code, document = run(ws, tmp_path, reports)
        assert code == 0 and results(document) == []
        assert document and document["version"] == "2.1.0"


def test_a_configured_report_that_does_not_exist_is_not_an_error(tmp_path: Path) -> None:
    ws = workspace(tmp_path, {"a.py": "x\n"})
    code, document = run(ws, tmp_path, [report("absent.info")])
    assert code == 0 and results(document) == []


def test_recorded_output_matches_the_adapter_on_the_f03_valid_reports() -> None:
    text = RECORDED.read_text()
    assert "file://" not in text and "/home/" not in text and "snippet" not in text
    for result in json.loads(text)["runs"][0]["results"]:
        assert set(result["properties"]) == {"tool_severity", "metric"}


# --- report ostili: il plugin fallisce senza effetti -------------------------------------------


@pytest.mark.parametrize("name", sorted(p.name for p in (FIXTURES / "hostile").iterdir()))
def test_hostile_fixture_reports_are_refused_or_read_safely(tmp_path: Path, name: str) -> None:
    expected = yaml.safe_load((FIXTURES / "expected.yaml").read_text())["reports"][
        f"hostile/{name}"
    ]
    ws = workspace(tmp_path, {"pkg/inside.py": "x\n"})
    (ws / "r").write_bytes((FIXTURES / "hostile" / name).read_bytes())
    code, document = run(ws, tmp_path, [report("r", expected["format"])])
    if expected["outcome"] == "refused":
        assert code == adapter.EXIT_REPORT and document is None
    else:
        assert code == 0


def test_report_that_is_a_symlink_is_refused(tmp_path: Path) -> None:
    ws = workspace(tmp_path, {"a.py": "x\n"})
    (ws / "lcov.info").symlink_to("/etc/hostname")
    assert run(ws, tmp_path, [report("lcov.info")])[0] == adapter.EXIT_REPORT


def test_report_reached_through_a_symlinked_directory_is_refused(tmp_path: Path) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "lcov.info").write_text(lcov("a.py", [0] * 20))
    ws = workspace(tmp_path, {"a.py": "x\n"})
    (ws / "cov").symlink_to(outside)
    assert run(ws, tmp_path, [report("cov/lcov.info")])[0] == adapter.EXIT_REPORT


def test_report_that_is_not_a_regular_file_or_is_too_big_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ws = workspace(tmp_path, {"a.py": "x\n"})
    (ws / "dir.info").mkdir()
    assert run(ws, tmp_path, [report("dir.info")])[0] == adapter.EXIT_REPORT
    (ws / "big.info").write_text(lcov("a.py", [1] * 20))
    monkeypatch.setattr(adapter, "MAX_REPORT_BYTES", 10)
    assert run(ws, tmp_path, [report("big.info")])[0] == adapter.EXIT_REPORT


def test_xml_limits_on_elements_and_depth(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(adapter, "MAX_ELEMENTS", 50)
    many = "<coverage>" + "<a/>" * 100 + "</coverage>"
    with pytest.raises(adapter.ReportRefused):
        adapter.parse_cobertura(many.encode())
    deep = "<a>" * (adapter.MAX_DEPTH + 1) + "</a>" * (adapter.MAX_DEPTH + 1)
    monkeypatch.setattr(adapter, "MAX_ELEMENTS", 10_000)
    with pytest.raises(adapter.ReportRefused):
        adapter.parse_cobertura(deep.encode())


def test_lcov_line_length_limit() -> None:
    with pytest.raises(adapter.ReportRefused):
        adapter.parse_lcov(b"SF:" + b"a" * (adapter.MAX_LINE_LENGTH + 1))


@pytest.mark.parametrize(
    "data", [b"\xff\xfeSF:a\n", b"DA:1,1\n", b"SF:a\nDA:0,1\n", b"SF:a\nDA:1,-x\n"]
)
def test_malformed_lcov_is_refused(data: bytes) -> None:
    with pytest.raises(adapter.ReportRefused):
        adapter.parse_lcov(data)


# --- configurazione ----------------------------------------------------------------------------


@pytest.mark.parametrize(
    "content",
    [
        "non json",
        "[]",
        '{"reports": "x"}',
        '{"rules": []}',
        '{"reports": [{"path": "a", "format": "jacoco"}]}',
        '{"reports": [{"path": "/etc/x", "format": "lcov"}]}',
        '{"reports": [{"path": "../x", "format": "lcov"}]}',
        '{"reports": [{"path": "a", "format": "lcov", "base_dir": "../.."}]}',
        '{"reports": [{"path": "a", "format": "lcov", "url": "http://x"}]}',
        '{"reports": [{"path": "a\\nb", "format": "lcov"}]}',
        json.dumps({"reports": [{"path": f"r{i}", "format": "lcov"} for i in range(21)]}),
    ],
)
def test_invalid_config_is_exit_4_and_reads_nothing(tmp_path: Path, content: str) -> None:
    (tmp_path / "config.json").write_text(content)
    out = tmp_path / "results.sarif"
    code = adapter.run(
        workspace=str(tmp_path), out_file=str(out), config_file=str(tmp_path / "config.json")
    )
    assert code == 4 and not out.exists()


def test_resolve_rejects_what_leaves_the_workspace() -> None:
    for name in ("", "/a", "../a", "a/../../b", "a\\b", "C:/x", "a\x00b", "."):
        assert adapter.resolve(name, None) is None
    assert adapter.resolve("pkg/a.py", "backend") == "backend/pkg/a.py"
    # Un segmento `..` si scarta sempre, anche se il risultato resterebbe nel workspace.
    assert adapter.resolve("../shared/a.py", "backend/app") is None


def test_adapter_does_not_import_ca_core_or_third_parties() -> None:
    text = (COVERAGE / "coverage_adapter.py").read_text()
    assert not re.search(r"^\s*(?:from|import)\s+ca_", text, re.M)
    imports = set(re.findall(r"^(?:import|from)\s+([a-z_.]+)", text, re.M))
    assert imports <= {
        "json",
        "os",
        "posixpath",
        "re",
        "stat",
        "sys",
        "xml.parsers.expat",
        "pathlib",
        "typing",
        "urllib.parse",  # codifica dell'`uri` (ADR-0004)
    }


# --- immagine (statico) -------------------------------------------------------------------


def test_dockerfile_pins_the_base_and_has_no_dependencies() -> None:
    text = (COVERAGE / "Dockerfile").read_text()
    froms = re.findall(r"^FROM\s+(?:--platform=\S+\s+)?(\S+)", text, re.M)
    assert len(froms) == 1 and re.search(r"@sha256:[0-9a-f]{64}$", froms[0])
    code = "\n".join(line for line in text.splitlines() if not line.lstrip().startswith("#"))
    assert "latest" not in code.lower() and "pip" not in code and "npm" not in code
    assert 'ca.engines=""' in text and "org.opencontainers.image.licenses" not in text
    assert "USER 65534:65534" in text
    assert re.search(r'^ENTRYPOINT \["python", "/opt/ca-plugin/coverage_adapter.py"\]$', text, re.M)


def test_build_context_contains_only_what_the_image_needs() -> None:
    assert (COVERAGE / ".dockerignore").read_text().split() == [
        "*",
        "!coverage_adapter.py",
        "!licenses",
    ]


def test_notices_state_that_there_is_no_third_party_engine() -> None:
    notices = " ".join((COVERAGE / "licenses/THIRD-PARTY-NOTICES.md").read_text().split()).lower()
    assert "non dichiara la licenza del prodotto" in notices and "nessuno" in notices
