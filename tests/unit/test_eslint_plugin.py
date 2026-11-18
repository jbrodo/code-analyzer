"""Plugin eslint (P-02) senza Docker: manifest, adattatore con l'eslint reale, fixture, Dockerfile.

L'adattatore gira con l'eslint installato in `web/node_modules`, alle stesse versioni fissate dal
`package-lock.json` del plugin: la configurazione ostile, le soppressioni e la risoluzione dei
moduli si provano su eslint vero. Senza Node o con versioni diverse i test reali si saltano.
"""

import importlib.util
import json
import re
import shutil
import sys
from pathlib import Path
from typing import Any

import pytest
import yaml
from jsonschema import Draft202012Validator

from ca_core.models import PluginManifest

ROOT = Path(__file__).resolve().parents[2]
ESLINT = ROOT / "packages/ca-plugins/src/ca_plugins/builtin/eslint"
FIXTURE = ROOT / "tests/fixtures/repos/quality-js-ts"
RECORDED = ESLINT / "fixtures/output/eslint.quality-js-ts.sarif"
MODULES = ROOT / "web/node_modules"
NODE = shutil.which("node")
PINNED = {
    "eslint": "10.14.0",
    "@eslint/js": "10.0.1",
    "typescript": "6.0.3",
    "typescript-eslint": "8.72.2",
}

_spec = importlib.util.spec_from_file_location("eslint_adapter", ESLINT / "eslint_adapter.py")
assert _spec and _spec.loader
adapter = importlib.util.module_from_spec(_spec)
sys.modules["eslint_adapter"] = adapter
_spec.loader.exec_module(adapter)

MANIFEST: dict[str, Any] = yaml.safe_load((ESLINT / "plugin.yaml").read_text())
LOCK: dict[str, Any] = json.loads((ESLINT / "package-lock.json").read_text())


def have_pinned_eslint() -> bool:
    if NODE is None:
        return False
    try:
        return all(
            json.loads((MODULES / name / "package.json").read_text())["version"] == version
            for name, version in PINNED.items()
        )
    except OSError, ValueError:
        return False


needs_eslint = pytest.mark.skipif(
    not have_pinned_eslint(), reason="eslint alle versioni fissate assente"
)


@pytest.fixture
def image(tmp_path: Path) -> Path:
    """Cartella che fa le veci di /opt/ca-plugin: configurazione dell'immagine e moduli."""
    folder = tmp_path / "image"
    folder.mkdir()
    shutil.copy(ESLINT / "eslint.config.mjs", folder)
    (folder / "node_modules").symlink_to(MODULES)
    return folder


def scan(
    image: Path, workspace: Path, tmp_path: Path, disabled: list[str] | None = None
) -> dict[str, Any]:
    config = tmp_path / "config.json"
    if disabled is not None:
        config.write_text(json.dumps({"disable_rules": disabled}))
    out = tmp_path / "results.sarif"
    code = adapter.run(
        node=str(NODE),
        eslint=str(image / "node_modules/eslint/bin/eslint.js"),
        eslint_config=str(image / "eslint.config.mjs"),
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
    assert (model.name, model.network, model.inputs.config) == ("eslint", "none", "optional")
    assert [c.value for c in model.categories] == ["quality"]
    assert model.languages == ["javascript", "typescript"]


def test_manifest_has_no_real_registry_and_no_digest() -> None:
    image = MANIFEST["image"]
    assert image.startswith("registry.invalid/") and "@" not in image and ":latest" not in image


# --- fixture registrata ----------------------------------------------------------------------


def test_recorded_output_is_clean_and_covers_the_fixture_expectations() -> None:
    text = RECORDED.read_text()
    assert "/workspace" not in text and "file://" not in text and "/home/" not in text
    assert not any(k in text for k in ("snippet", "suggestions", "uriBaseId", '"source"', "fix"))
    document = json.loads(text)
    expected = {
        (e["rule_id"], e["path"])
        for e in yaml.safe_load((FIXTURE / "expected-findings.yaml").read_text())["expected"]
    }
    assert expected <= found(document)
    assert not any(uri.endswith("clean.ts") for _, uri in found(document))
    for result in document["runs"][0]["results"]:
        assert set(result["properties"]) <= {"tool_severity", "metric"}


# --- adattatore con eslint vero -----------------------------------------------------------------


@needs_eslint
def test_real_run_reproduces_the_recorded_output(image: Path, tmp_path: Path) -> None:
    assert scan(image, FIXTURE, tmp_path) == json.loads(RECORDED.read_text())


@needs_eslint
def test_metrics_are_extracted_as_numbers(image: Path, tmp_path: Path) -> None:
    results = scan(image, FIXTURE, tmp_path)["runs"][0]["results"]
    metrics = sorted(
        (r["ruleId"], r["properties"]["metric"]["value"], r["properties"]["metric"]["threshold"])
        for r in results
        if "metric" in r["properties"]
    )
    assert metrics == [
        ("complexity", 26, 10),
        ("max-depth", 5, 4),
        ("max-depth", 6, 4),
        ("max-lines-per-function", 51, 50),
        ("max-params", 6, 5),
    ]


@needs_eslint
def test_severities_come_from_our_configuration(image: Path, tmp_path: Path) -> None:
    by_rule = {
        r["ruleId"]: r["properties"]["tool_severity"]
        for r in scan(image, FIXTURE, tmp_path)["runs"][0]["results"]
    }
    assert by_rule["complexity"] == "low" and by_rule["no-empty"] == "medium"


def hostile_workspace(tmp_path: Path) -> tuple[Path, Path]:
    ws = tmp_path / "ws"
    (ws / "src").mkdir(parents=True)
    marker = tmp_path / "executed"
    (ws / "eslint.config.js").write_text(
        f'import {{ writeFileSync }} from "node:fs";\nwriteFileSync("{marker}", "x");\n'
        "export default [{ rules: {} }];\n"
    )
    (ws / "eslint.config.mjs").write_text((ws / "eslint.config.js").read_text())
    (ws / "package.json").write_text(
        '{"type": "module", "eslintConfig": {"rules": {"no-eval": "off"}}}'
    )
    (ws / ".eslintrc.json").write_text('{"rules": {"no-eval": "off", "no-empty": "off"}}')
    (ws / ".eslintignore").write_text("src/\n")
    (ws / "tsconfig.json").write_text('{"compilerOptions": {"strict": true}}')
    pkg = ws / "node_modules/typescript-eslint"
    pkg.mkdir(parents=True)
    (pkg / "package.json").write_text('{"name": "typescript-eslint", "main": "index.js"}')
    (pkg / "index.js").write_text(f'require("fs").writeFileSync("{marker}", "node_modules");\n')
    (ws / "src/inline.ts").write_text(
        "/* eslint-disable */\nconst a: any = 1;\ntry { a; } catch (e) {}\n"
    )
    (ws / "src/line.ts").write_text(
        "// eslint-disable-next-line no-empty\ntry { 1; } catch (e) {}\n"
    )
    (ws / "src/broken.ts").write_text("const = ;\n")
    return ws, marker


@needs_eslint
def test_repository_configuration_and_inline_directives_have_no_effect(
    image: Path, tmp_path: Path
) -> None:
    ws, marker = hostile_workspace(tmp_path)
    work = tmp_path / "work"
    work.mkdir()
    rules = found(scan(image, ws, work))
    assert not marker.exists()  # nessun codice del repository e' stato eseguito
    assert ("@typescript-eslint/no-explicit-any", "src/inline.ts") in rules  # eslint-disable
    assert ("no-empty", "src/inline.ts") in rules
    assert ("no-empty", "src/line.ts") in rules  # eslint-disable-next-line
    assert ("parse-error", "src/broken.ts") in rules
    assert not any(uri.startswith("node_modules/") for _, uri in rules)


@needs_eslint
def test_parse_error_is_a_high_severity_finding(image: Path, tmp_path: Path) -> None:
    ws = tmp_path / "ws"
    ws.mkdir()
    (ws / "bad.ts").write_text("const = ;\n")
    [result] = scan(image, ws, tmp_path)["runs"][0]["results"]
    assert result["ruleId"] == "parse-error" and result["properties"] == {"tool_severity": "high"}
    assert "const = ;" not in json.dumps(result)


@needs_eslint
def test_disable_rules_from_config_remove_only_those_rules(image: Path, tmp_path: Path) -> None:
    work = tmp_path / "work"
    work.mkdir()
    rules = {rule for rule, _ in found(scan(image, FIXTURE, work, ["max-params", "no-empty"]))}
    assert "max-params" not in rules and "no-empty" not in rules
    assert {"complexity", "max-depth", "@typescript-eslint/no-explicit-any"} <= rules


@needs_eslint
def test_workspace_is_never_written(image: Path, tmp_path: Path) -> None:
    ws = tmp_path / "ws"
    shutil.copytree(FIXTURE, ws)
    before = sorted(p.relative_to(ws).as_posix() for p in ws.rglob("*"))
    work = tmp_path / "work"
    work.mkdir()
    scan(image, ws, work)
    assert sorted(p.relative_to(ws).as_posix() for p in ws.rglob("*")) == before


# --- adattatore: unità --------------------------------------------------------------------------


def entry(path: str = "/workspace/a.ts", **message: Any) -> dict[str, Any]:
    base = {
        "ruleId": "no-empty",
        "severity": 2,
        "message": "Empty block statement.",
        "line": 3,
        "column": 1,
    }
    return {"filePath": path, "messages": [{**base, **message}], "source": "const secret = 'x';\n"}


def test_adapt_drops_source_and_rewrites_the_path() -> None:
    document = json.loads(adapter.adapt(json.dumps([entry()]).encode()))
    [result] = document["runs"][0]["results"]
    assert "secret" not in json.dumps(document)
    assert result["locations"][0]["physicalLocation"]["artifactLocation"] == {"uri": "a.ts"}
    assert result["properties"] == {"tool_severity": "medium"}


def test_adapt_skips_files_without_messages() -> None:
    clean = {"filePath": "/workspace/ok.ts", "messages": []}
    assert json.loads(adapter.adapt(json.dumps([clean]).encode()))["runs"][0]["results"] == []


def test_adapt_keeps_a_message_that_does_not_match_the_metric_expression() -> None:
    changed = entry(ruleId="complexity", severity=1, message="messaggio nuovo")
    [result] = json.loads(adapter.adapt(json.dumps([changed]).encode()))["runs"][0]["results"]
    assert result["properties"] == {"tool_severity": "low"}


@pytest.mark.parametrize(
    "raw",
    [
        b"non json",
        b"{}",
        json.dumps([{"messages": []}]).encode(),
        json.dumps([{"filePath": "/workspace/a.ts"}]).encode(),
        json.dumps([entry("/etc/passwd")]).encode(),
        json.dumps([entry("/workspace")]).encode(),
        json.dumps([entry(ruleId=7)]).encode(),
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
        (
            '{"disable_rules": ["max-params", "@typescript-eslint/no-explicit-any", "max-params"]}',
            ["@typescript-eslint/no-explicit-any", "max-params"],
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
        '{"disable_rules": "no-empty"}',
        '{"disable_rules": ["no-empty: off"]}',
        '{"disable_rules": ["--no-inline-config"]}',
        '{"disable_rules": ["*"]}',
        '{"disable_rules": [1]}',
        '{"rules": {"no-eval": "off"}}',
        json.dumps({"disable_rules": [f"r{i}" for i in range(501)]}),
    ],
)
def test_load_disabled_rejects_anything_else(tmp_path: Path, content: str) -> None:
    path = tmp_path / "config.json"
    path.write_text(content)
    with pytest.raises(adapter.InvalidConfig):
        adapter.load_disabled(str(path))


def test_command_uses_the_fixed_arguments() -> None:
    argv = adapter.command(
        "node",
        "/opt/ca-plugin/node_modules/eslint/bin/eslint.js",
        "/opt/ca-plugin/eslint.config.mjs",
        ["max-params"],
    )
    for flag in ("--no-config-lookup", "--no-inline-config", "--no-warn-ignored"):
        assert flag in argv
    assert argv[argv.index("-c") + 1] == "/opt/ca-plugin/eslint.config.mjs"
    assert argv[argv.index("--rule") + 1] == "max-params: off" and argv[-1] == "."
    assert "--fix" not in argv and "--cache" not in argv


def test_invalid_config_is_exit_4_and_runs_nothing(tmp_path: Path) -> None:
    (tmp_path / "config.json").write_text('{"disable_rules": ["--fix"]}')
    out = tmp_path / "results.sarif"
    code = adapter.run(
        node="/nonexistent",
        out_file=str(out),
        config_file=str(tmp_path / "config.json"),
        tmp_dir=str(tmp_path),
    )
    assert code == 4 and not out.exists()


def test_run_tool_failure_is_exit_3(tmp_path: Path) -> None:
    out = tmp_path / "results.sarif"
    code = adapter.run(
        node="/nonexistent",
        workspace=str(tmp_path),
        out_file=str(out),
        config_file="/nonexistent",
        tmp_dir=str(tmp_path),
    )
    assert code == 3 and not out.exists()


def test_adapter_does_not_import_ca_core() -> None:
    assert not re.search(
        r"^\s*(?:from|import)\s+ca_", (ESLINT / "eslint_adapter.py").read_text(), re.M
    )


# --- configurazione dell'immagine ----------------------------------------------------------------


def test_image_configuration_does_not_read_the_repository() -> None:
    text = (ESLINT / "eslint.config.mjs").read_text()
    code = "\n".join(line for line in text.splitlines() if not line.lstrip().startswith("//"))
    assert "projectService" not in code and not re.search(r"\bproject\s*:", code)
    assert "readFile" not in code and "process.cwd" not in code


# --- immagine (statico) -------------------------------------------------------------------


def test_lock_pins_the_declared_dependencies_with_integrity() -> None:
    declared = json.loads((ESLINT / "package.json").read_text())["dependencies"]
    assert declared == PINNED
    packages = {k: v for k, v in LOCK["packages"].items() if k}
    assert all(
        v["integrity"].startswith("sha512-")
        and v["resolved"].startswith("https://registry.npmjs.org/")
        for v in packages.values()
    )
    for name, version in PINNED.items():
        assert packages[f"node_modules/{name}"]["version"] == version


def test_dockerfile_pins_bases_and_installs_without_scripts() -> None:
    text = (ESLINT / "Dockerfile").read_text()
    froms = re.findall(r"^FROM\s+(?:--platform=\S+\s+)?(\S+)", text, re.M)
    assert len(froms) == 2 and all(re.search(r"@sha256:[0-9a-f]{64}$", f) for f in froms)
    code = "\n".join(line for line in text.splitlines() if not line.lstrip().startswith("#"))
    assert "latest" not in code.lower()
    assert "npm ci" in code and "--ignore-scripts" in code and "--omit=dev" in code
    assert 'ca.engines="eslint"' in text and "org.opencontainers.image.licenses" not in text
    assert "USER 65534:65534" in text
    assert re.search(r'^ENTRYPOINT \["python", "/opt/ca-plugin/eslint_adapter.py"\]$', text, re.M)


def test_build_context_contains_only_what_the_image_needs() -> None:
    assert (ESLINT / ".dockerignore").read_text().split() == [
        "*",
        "!eslint_adapter.py",
        "!eslint.config.mjs",
        "!package.json",
        "!package-lock.json",
        "!licenses",
    ]


def test_license_files_are_the_release_texts_without_a_product_license() -> None:
    notices = (ESLINT / "licenses/THIRD-PARTY-NOTICES.md").read_text()
    assert "non dichiara la licenza del prodotto" in " ".join(notices.split()).lower()
    licence = (ESLINT / "licenses/eslint/LICENSE").read_text()
    assert "Permission is hereby granted" in licence


def fake_node(tmp_path: Path, stderr: str, code: int) -> str:
    script = tmp_path / "node"
    script.write_text(f"#!/bin/sh\nprintf '%s' '{stderr}' >&2\nexit {code}\n")
    script.chmod(0o755)
    return str(script)


NO_FILES_MESSAGE = (
    'Oops! Something went wrong! :(\n\nESLint: 10.14.0\n\nYou are linting ".", but all of the '
    'files matching the glob pattern "." are ignored.\n\nIf you do want to lint these files'
)


def run_fake(tmp_path: Path, stderr: str, code: int) -> tuple[int, Path]:
    out = tmp_path / "results.sarif"
    done = adapter.run(
        node=fake_node(tmp_path, stderr, code),
        workspace=str(tmp_path),
        out_file=str(out),
        config_file="/nonexistent",
        tmp_dir=str(tmp_path),
    )
    return done, out


def test_a_repository_with_nothing_to_lint_is_an_empty_result_not_a_failure(tmp_path: Path) -> None:
    """Saleor ha un `package.json` ma nessun file JavaScript: eslint esce con 2 e il plugin falliva,
    rendendo `partial` ogni scansione (X-02, 2026-11-18)."""
    code, out = run_fake(tmp_path, NO_FILES_MESSAGE, 2)
    assert code == 0
    document = json.loads(out.read_text())
    assert document["runs"][0]["results"] == []


def test_other_eslint_failures_stay_failures(tmp_path: Path) -> None:
    assert run_fake(tmp_path, "Error: Cannot find module 'x'", 2)[0] == 3
    assert (
        run_fake(tmp_path, NO_FILES_MESSAGE, 1)[0] == 3
    )  # solo l'uscita 2 conta come «niente da analizzare»
    # un messaggio che cita un altro pattern non è quello di eslint per «niente da analizzare»
    other = NO_FILES_MESSAGE.replace('".", but', '"src/**", but')
    assert run_fake(tmp_path, other, 2)[0] == 3
