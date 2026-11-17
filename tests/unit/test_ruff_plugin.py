"""Plugin ruff (P-01) senza Docker: manifest, adattatore con il ruff reale, fixture, Dockerfile.

L'adattatore gira con il ruff dell'ambiente di sviluppo (stessa versione fissata dall'immagine) su
cartelle temporanee: la configurazione ostile, le soppressioni e i percorsi si provano su ruff vero.
"""

import importlib.util
import json
import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest
import yaml
from jsonschema import Draft202012Validator

from ca_core.models import PluginManifest

ROOT = Path(__file__).resolve().parents[2]
RUFF = ROOT / "packages/ca-plugins/src/ca_plugins/builtin/ruff"
FIXTURE = ROOT / "tests/fixtures/repos/quality-python"
RECORDED = RUFF / "fixtures/output/ruff.quality-python.sarif"
WHEEL_SHA256 = "40ca8afaac309b41a5b2e09e4e7beb1f824826b93c25697c4d74f573324fba4e"  # V-01
VENV_RUFF = ROOT / ".venv/bin/ruff"

_spec = importlib.util.spec_from_file_location("ruff_adapter", RUFF / "ruff_adapter.py")
assert _spec and _spec.loader
adapter = importlib.util.module_from_spec(_spec)
sys.modules["ruff_adapter"] = adapter
_spec.loader.exec_module(adapter)

MANIFEST: dict[str, Any] = yaml.safe_load((RUFF / "plugin.yaml").read_text())


def have_ruff() -> bool:
    if not VENV_RUFF.exists():
        return False
    out = subprocess.run([VENV_RUFF, "--version"], capture_output=True, text=True, check=False)
    return out.stdout.strip() == "ruff 0.17.5"


needs_ruff = pytest.mark.skipif(not have_ruff(), reason="ruff 0.17.5 non nell'ambiente")


def scan(workspace: Path, tmp_path: Path, disabled: list[str] | None = None) -> dict[str, Any]:
    config = tmp_path / "config.json"
    if disabled is not None:
        config.write_text(json.dumps({"disable_rules": disabled}))
    out = tmp_path / "results.sarif"
    code = adapter.run(
        ruff=str(VENV_RUFF),
        workspace=str(workspace),
        out_file=str(out),
        config_file=str(config),
        tmp_dir=str(tmp_path),
    )
    assert code == 0
    return json.loads(out.read_text())


def found(document: dict[str, Any]) -> set[tuple[str, str]]:
    return {
        (r["ruleId"], r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"])
        for r in document["runs"][0]["results"]
    }


# --- manifest ---------------------------------------------------------------------------


def test_manifest_valid_for_schema_and_model() -> None:
    schema = json.loads((ROOT / "schemas" / "plugin-manifest.schema.json").read_text())
    Draft202012Validator(schema).validate(MANIFEST)
    model = PluginManifest.model_validate(MANIFEST)
    assert (model.name, model.network, model.inputs.config) == ("ruff", "none", "optional")
    assert [c.value for c in model.categories] == ["quality"] and model.languages == ["python"]
    assert model.outputs.sarif == "/out/results.sarif"


def test_manifest_has_no_real_registry_and_no_digest() -> None:
    image = MANIFEST["image"]
    assert image.startswith("registry.invalid/") and "@" not in image and ":latest" not in image


# --- fixture registrata ----------------------------------------------------------------------


def test_recorded_output_is_clean_and_matches_the_fixture_expectations() -> None:
    text = RECORDED.read_text()
    assert "/workspace" not in text and "file://" not in text and "/home/" not in text
    assert not any(k in text for k in ("snippet", "fixes", "uriBaseId", '"source"'))
    document = json.loads(text)
    expected = {
        (e["rule_id"], e["path"])
        for e in yaml.safe_load((FIXTURE / "expected-findings.yaml").read_text())["expected"]
    }
    assert found(document) == expected
    for result in document["runs"][0]["results"]:
        assert set(result["properties"]) <= {"tool_severity", "metric"}


# --- adattatore con ruff vero -----------------------------------------------------------------


@needs_ruff
def test_real_run_reproduces_the_recorded_output(tmp_path: Path) -> None:
    assert scan(FIXTURE, tmp_path) == json.loads(RECORDED.read_text())


@needs_ruff
def test_metrics_are_extracted_as_numbers(tmp_path: Path) -> None:
    results = scan(FIXTURE, tmp_path)["runs"][0]["results"]
    metrics = {
        r["ruleId"]: r["properties"]["metric"] for r in results if "metric" in r["properties"]
    }
    assert metrics == {
        "C901": {"value": 18, "threshold": 10},
        "PLR0911": {"value": 14, "threshold": 6},
        "PLR0912": {"value": 18, "threshold": 12},
        "PLR0913": {"value": 9, "threshold": 5},
    }


@needs_ruff
def test_clean_file_has_no_findings(tmp_path: Path) -> None:
    assert not any(uri.endswith("clean.py") for _, uri in found(scan(FIXTURE, tmp_path)))


def hostile_workspace(tmp_path: Path) -> Path:
    ws = tmp_path / "ws"
    ws.mkdir()
    (ws / "pyproject.toml").write_text(
        '[tool.ruff]\nline-length = 1\n[tool.ruff.lint]\nselect = []\nignore = ["F401", "F841"]\n'
    )
    (ws / "ruff.toml").write_text(
        '[lint]\nignore = ["F401"]\nextend-per-file-ignores = {"*" = ["F"]}\n'
    )
    (ws / ".ruff.toml").write_text('[lint]\nignore = ["F401"]\n')
    (ws / ".gitignore").write_text("hidden.py\n")
    (ws / "hidden.py").write_text("import os\n")
    (ws / "noqa_line.py").write_text("import os  # no" + "qa: F401\n")
    (ws / "noqa_file.py").write_text("# ruff" + ": noqa\nimport sys\n")
    (ws / "noqa_blanket.py").write_text("import json  # no" + "qa\n")
    (ws / "broken.py").write_text("def f(:\n    pass\n")
    return ws


@needs_ruff
def test_repository_configuration_gitignore_and_noqa_have_no_effect(tmp_path: Path) -> None:
    ws = hostile_workspace(tmp_path)
    work = tmp_path / "work"
    work.mkdir()
    rules = found(scan(ws, work))
    assert ("F401", "hidden.py") in rules  # .gitignore non nasconde file
    assert ("F401", "noqa_line.py") in rules  # noqa in linea
    assert ("F401", "noqa_file.py") in rules  # soppressione a livello di file
    assert ("F401", "noqa_blanket.py") in rules  # soppressione generica
    assert ("invalid-syntax", "broken.py") in rules
    assert not (ws / ".ruff_cache").exists()
    assert sorted(p.name for p in ws.iterdir() if p.name.startswith(".ruff")) == [".ruff.toml"]


@needs_ruff
def test_syntax_error_is_a_high_severity_quality_finding(tmp_path: Path) -> None:
    ws = tmp_path / "ws"
    ws.mkdir()
    (ws / "bad.py").write_text("def f(:\n    pass\n")
    results = scan(ws, tmp_path)["runs"][0]["results"]
    assert {r["ruleId"] for r in results} == {"invalid-syntax"}
    assert all(r["properties"] == {"tool_severity": "high"} for r in results)


@needs_ruff
def test_disable_rules_from_config_remove_only_those_rules(tmp_path: Path) -> None:
    work = tmp_path / "work"
    work.mkdir()
    rules = {rule for rule, _ in found(scan(FIXTURE, work, ["F401", "PLR0913"]))}
    assert "F401" not in rules and "PLR0913" not in rules
    assert {"F841", "C901", "B006", "F821"} <= rules


@needs_ruff
def test_workspace_is_never_written(tmp_path: Path) -> None:
    ws = tmp_path / "ws"
    shutil.copytree(FIXTURE, ws)
    before = sorted(p.relative_to(ws).as_posix() for p in ws.rglob("*"))
    work = tmp_path / "work"
    work.mkdir()
    scan(ws, work)
    assert sorted(p.relative_to(ws).as_posix() for p in ws.rglob("*")) == before


# --- adattatore: unità --------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("rule", "severity"),
    [
        ("invalid-syntax", "high"),
        ("F821", "high"),
        ("F811", "medium"),
        ("F401", "low"),
        ("F841", "low"),
        ("B006", "medium"),
        ("C901", "medium"),
        ("PLR0913", "medium"),
        ("Z999", "low"),
    ],
)
def test_severity_table(rule: str, severity: str) -> None:
    assert adapter.severity_of(rule) == severity


def raw_sarif(*results: dict[str, Any]) -> bytes:
    return json.dumps(
        {"version": "2.1.0", "runs": [{"tool": {"driver": {}}, "results": list(results)}]}
    ).encode()


def raw_result(uri: str = "file:///workspace/a.py", **changes: Any) -> dict[str, Any]:
    result = {
        "ruleId": "F401",
        "level": "error",
        "message": {"text": "`os` imported but unused"},
        "locations": [
            {"physicalLocation": {"artifactLocation": {"uri": uri}, "region": {"startLine": 1}}}
        ],
        "fixes": [{"description": {"text": "Remove unused import: `os`"}}],
    }
    return {**result, **changes}


def test_adapt_drops_fixes_level_and_rewrites_the_uri() -> None:
    [result] = json.loads(adapter.adapt(raw_sarif(raw_result())))["runs"][0]["results"]
    assert set(result) == {"ruleId", "message", "locations", "properties"}
    assert result["locations"][0]["physicalLocation"]["artifactLocation"] == {"uri": "a.py"}
    assert result["properties"] == {"tool_severity": "low"}


def test_adapt_keeps_a_message_that_does_not_match_the_metric_expression() -> None:
    changed = raw_result(ruleId="C901", message={"text": "formato nuovo del motore"})
    [result] = json.loads(adapter.adapt(raw_sarif(changed)))["runs"][0]["results"]
    assert result["properties"] == {"tool_severity": "medium"}  # senza metrica, ma il finding resta


@pytest.mark.parametrize(
    "raw",
    [
        b"non json",
        b"[]",
        json.dumps({"version": "2.0.0", "runs": []}).encode(),
        json.dumps({"version": "2.1.0", "runs": []}).encode(),
        raw_sarif(raw_result(uri="file:///etc/passwd")),
        raw_sarif(raw_result(uri="file:///other/a.py")),
        raw_sarif(raw_result(ruleId=None)),
        raw_sarif(raw_result(locations=[])),
        raw_sarif(raw_result(locations=[{"physicalLocation": {"artifactLocation": {}}}])),
        b"[" * 100_000,
    ],
)
def test_adapt_rejects_what_it_cannot_make_conforming(raw: bytes) -> None:
    with pytest.raises(adapter.InvalidOutput):
        adapter.adapt(raw)


@pytest.mark.parametrize(
    ("content", "expected"),
    [
        (None, []),
        ("{}", []),
        ('{"disable_rules": []}', []),
        ('{"disable_rules": ["F401", "C901", "F401"]}', ["C901", "F401"]),
        (
            '{"disable_rules": ["@typescript-eslint/no-explicit-any"]}',
            ["@typescript-eslint/no-explicit-any"],
        ),
    ],
)
def test_load_disabled_accepts_valid_config(
    tmp_path: Path, content: str | None, expected: list[str]
) -> None:
    path = tmp_path / "config.json"
    if content is not None:
        path.write_text(content)
    assert adapter.load_disabled(str(path)) == expected


@pytest.mark.parametrize(
    "content",
    [
        "non json",
        "[]",
        '{"disable_rules": "F401"}',
        '{"disable_rules": ["F401 E501"]}',
        '{"disable_rules": ["--config"]}',
        '{"disable_rules": ["*"]}',
        '{"disable_rules": [""]}',
        '{"disable_rules": [1]}',
        '{"select": ["ALL"]}',
        '{"disable_rules": ["F401"], "isolated": false}',
        json.dumps({"disable_rules": [f"R{i}" for i in range(501)]}),
    ],
)
def test_load_disabled_rejects_anything_else(tmp_path: Path, content: str) -> None:
    path = tmp_path / "config.json"
    path.write_text(content)
    with pytest.raises(adapter.InvalidConfig):
        adapter.load_disabled(str(path))


def test_invalid_config_is_exit_4_and_runs_nothing(tmp_path: Path) -> None:
    (tmp_path / "config.json").write_text('{"disable_rules": ["--output-format"]}')
    out = tmp_path / "results.sarif"
    code = adapter.run(
        ruff="/nonexistent/ruff",
        out_file=str(out),
        config_file=str(tmp_path / "config.json"),
        tmp_dir=str(tmp_path),
    )
    assert code == 4 and not out.exists()


def test_command_uses_the_fixed_isolated_arguments() -> None:
    argv = adapter.command("/opt/venv/bin/ruff", "/workspace", ["F401", "B006"])
    for flag in ("--isolated", "--no-cache", "--no-respect-gitignore", "--ignore-noqa"):
        assert flag in argv
    assert argv[argv.index("--ignore") + 1] == "F401,B006" and argv[-1] == "/workspace"
    assert "--config" in argv and "--exit-zero" in argv
    assert "--fix" not in argv and not any(a.startswith("--select=") for a in argv)


def test_run_tool_failure_is_exit_3(tmp_path: Path) -> None:
    out = tmp_path / "results.sarif"
    code = adapter.run(
        ruff="/nonexistent/ruff",
        out_file=str(out),
        config_file="/nonexistent",
        tmp_dir=str(tmp_path),
    )
    assert code == 3 and not out.exists()


def test_adapter_does_not_import_ca_core() -> None:
    assert not re.search(r"^\s*(?:from|import)\s+ca_", (RUFF / "ruff_adapter.py").read_text(), re.M)


# --- immagine (statico) -------------------------------------------------------------------


def test_dockerfile_pins_base_wheel_and_labels() -> None:
    text = (RUFF / "Dockerfile").read_text()
    froms = re.findall(r"^FROM\s+(?:--platform=\S+\s+)?(\S+)", text, re.M)
    assert len(froms) == 2 and all(re.search(r"@sha256:[0-9a-f]{64}$", f) for f in froms)
    code = "\n".join(line for line in text.splitlines() if not line.lstrip().startswith("#"))
    assert "latest" not in code.lower()
    assert "--require-hashes" in text and "--only-binary=:all:" in text
    assert 'ca.engines="ruff"' in text and "org.opencontainers.image.licenses" not in text
    assert "USER 65534:65534" in text
    assert re.search(r'^ENTRYPOINT \["python", "/opt/ca-plugin/ruff_adapter.py"\]$', text, re.M)


def test_lock_pins_the_published_wheel_hash_and_nothing_else() -> None:
    lock = (RUFF / "requirements.lock").read_text()
    assert re.findall(r"^([A-Za-z0-9_.-]+)==", lock, re.M) == ["ruff"] and WHEEL_SHA256 in lock
    assert "ruff==0.17.5" in lock


def test_build_context_contains_only_what_the_image_needs() -> None:
    assert (RUFF / ".dockerignore").read_text().split() == [
        "*",
        "!ruff_adapter.py",
        "!requirements.lock",
        "!licenses",
    ]


def test_license_files_are_the_release_texts_without_a_product_license() -> None:
    notices = (RUFF / "licenses/THIRD-PARTY-NOTICES.md").read_text()
    assert "non dichiara la licenza del prodotto" in " ".join(notices.split()).lower()
    licence = (RUFF / "licenses/ruff/LICENSE").read_text()
    assert "MIT License" in licence and "Permission is hereby granted" in licence
