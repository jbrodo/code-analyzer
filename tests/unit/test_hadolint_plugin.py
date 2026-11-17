"""Plugin hadolint (P-04) senza Docker: manifest, adattatore, fixture registrate, Dockerfile.

La conversione si prova sul JSON nativo registrato. Le prove con l'hadolint vero (pragma,
configurazione ostile, collegamenti simbolici) girano solo con `CA_HADOLINT_BIN`, il percorso di un
hadolint 2.15.1: nessuna rete (regola 7 di AGENTS.md), quindi nessun download nel test.
"""

import importlib.util
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest
import yaml
from jsonschema import Draft202012Validator

from ca_core.models import PluginManifest

ROOT = Path(__file__).resolve().parents[2]
HADOLINT = ROOT / "packages/ca-plugins/src/ca_plugins/builtin/hadolint"
FIXTURE = ROOT / "tests/fixtures/repos/iac-app"
NATIVE = HADOLINT / "fixtures/native/hadolint.iac-app.json"
RECORDED = HADOLINT / "fixtures/output/hadolint.iac-app.sarif"
BINARY_SHA256 = "c7187db94eeeeca956519a6af171adc31453941a1e777961f6e680f697c8c507"  # V-01
LICENSE_SHA256 = "589ed823e9a84c56feb95ac58e7cf384626b9cbf4fda2a907bc36e103de1bad2"

_spec = importlib.util.spec_from_file_location("hadolint_adapter", HADOLINT / "hadolint_adapter.py")
assert _spec and _spec.loader
adapter = importlib.util.module_from_spec(_spec)
sys.modules["hadolint_adapter"] = adapter
_spec.loader.exec_module(adapter)

MANIFEST: dict[str, Any] = yaml.safe_load((HADOLINT / "plugin.yaml").read_text())
BIN = os.environ.get("CA_HADOLINT_BIN")


def have_hadolint() -> bool:
    if not BIN or not Path(BIN).exists():
        return False
    out = subprocess.run([BIN, "--version"], capture_output=True, text=True, check=False)
    return out.stdout.strip().endswith("2.15.1")


needs_hadolint = pytest.mark.skipif(not have_hadolint(), reason="CA_HADOLINT_BIN: hadolint 2.15.1")


def scan(workspace: Path, tmp_path: Path, disabled: list[str] | None = None) -> dict[str, Any]:
    config = tmp_path / "config.json"
    if disabled is not None:
        config.write_text(json.dumps({"disable_rules": disabled}))
    out = tmp_path / "results.sarif"
    scratch = tmp_path / "tmp"
    scratch.mkdir(exist_ok=True)
    code = adapter.run(
        hadolint=str(BIN),
        workspace=str(workspace),
        out_file=str(out),
        config_file=str(config),
        tmp_dir=str(scratch),
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
    assert (model.name, model.network, model.inputs.config) == ("hadolint", "none", "optional")
    assert [c.value for c in model.categories] == ["iac"]


def test_manifest_has_no_real_registry_and_no_digest() -> None:
    image = MANIFEST["image"]
    assert image.startswith("registry.invalid/") and "@" not in image and ":latest" not in image


# --- fixture registrate ------------------------------------------------------------------------


def test_recorded_output_covers_the_fixture_expectations_and_is_clean() -> None:
    text = RECORDED.read_text()
    assert "file://" not in text and "/workspace" not in text and "/tmp/" not in text
    document = json.loads(text)
    expected = {
        (e["rule_id"], e["path"])
        for e in yaml.safe_load((FIXTURE / "expected-findings.yaml").read_text())["expected"]
        if "hadolint" in e["tools"]
    }
    assert found(document) == expected and len(expected) == 8
    for result in document["runs"][0]["results"]:
        assert set(result["properties"]) == {"tool_severity"}


def test_adapting_the_native_sample_reproduces_the_recorded_sarif() -> None:
    assert adapter.adapt(NATIVE.read_bytes()) == RECORDED.read_bytes().rstrip(b"\n")


# --- adattatore con hadolint vero -------------------------------------------------------------


@needs_hadolint
def test_real_run_reproduces_the_recorded_output(tmp_path: Path) -> None:
    assert scan(FIXTURE, tmp_path) == json.loads(RECORDED.read_text())


def hostile(tmp_path: Path) -> Path:
    ws = tmp_path / "ws"
    (ws / "sub").mkdir(parents=True)
    (ws / "Dockerfile").write_text(
        "# hadolint global ignore=DL3007\nFROM debian:latest\n"
        "# hadolint ignore=DL3020\nADD . /app\nRUN apt-get update && apt-get install -y curl\n"
    )
    (ws / ".hadolint.yaml").write_text("ignored:\n  - DL3007\n  - DL3020\n  - DL3008\n")
    (ws / "sub/.hadolint.yaml").write_text("ignored:\n  - DL3009\n")
    (ws / "sub/Dockerfile.prod").write_text('FROM\nRUN echo "\n')
    return ws


@needs_hadolint
def test_repository_configuration_and_pragmas_have_no_effect(tmp_path: Path) -> None:
    ws = hostile(tmp_path)
    work = tmp_path / "work"
    work.mkdir()
    rules = found(scan(ws, work))
    assert ("DL3007", "Dockerfile") in rules  # `global ignore` e .hadolint.yaml
    assert ("DL3020", "Dockerfile") in rules  # `ignore` della riga
    assert ("DL3008", "Dockerfile") in rules
    assert ("DL3009", "Dockerfile") in rules
    assert ("DL1000", "sub/Dockerfile.prod") in rules  # errore di sintassi: un finding


@needs_hadolint
def test_hadolint_environment_variables_do_not_reach_the_engine(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("HADOLINT_IGNORE", "DL3007,DL3020,DL3008")
    monkeypatch.setenv("HADOLINT_FAILURE_THRESHOLD", "error")
    work = tmp_path / "work"
    work.mkdir()
    assert ("DL3007", "Dockerfile") in found(scan(hostile(tmp_path), work))


@needs_hadolint
def test_disable_rules_remove_only_those_rules(tmp_path: Path) -> None:
    work = tmp_path / "work"
    work.mkdir()
    rules = {rule for rule, _ in found(scan(FIXTURE, work, ["DL3007", "DL3020"]))}
    assert "DL3007" not in rules and "DL3020" not in rules
    assert {"DL3004", "DL3008"} <= rules


@needs_hadolint
def test_symlinks_and_other_files_are_not_analysed_and_workspace_is_not_written(
    tmp_path: Path,
) -> None:
    ws = tmp_path / "ws"
    ws.mkdir()
    (ws / "Dockerfile").write_text("FROM debian:latest\n")
    (ws / "Dockerfile.link").symlink_to("/etc/hostname")
    (ws / "README.md").write_text("FROM debian:latest\n")
    before = sorted(p.name for p in ws.iterdir())
    work = tmp_path / "work"
    work.mkdir()
    assert {uri for _, uri in found(scan(ws, work))} == {"Dockerfile"}
    assert sorted(p.name for p in ws.iterdir()) == before


# --- adattatore: unità --------------------------------------------------------------------------


def native(*items: dict[str, Any]) -> bytes:
    return json.dumps(list(items)).encode()


def item(**changes: Any) -> dict[str, Any]:
    base = {
        "code": "DL3007",
        "column": 1,
        "file": "/workspace/Dockerfile",
        "level": "warning",
        "line": 1,
        "message": "Using latest is prone to errors",
    }
    return {**base, **changes}


@pytest.mark.parametrize(
    ("level", "severity"),
    [("error", "high"), ("warning", "medium"), ("info", "low"), ("style", "low"), ("nuovo", "low")],
)
def test_severity_comes_from_the_engine_level(level: str, severity: str) -> None:
    [result] = json.loads(adapter.adapt(native(item(level=level))))["runs"][0]["results"]
    assert result["properties"] == {"tool_severity": severity}


def test_adapt_rewrites_the_path_and_keeps_line_and_column() -> None:
    [result] = json.loads(adapter.adapt(native(item(file="/workspace/a/Dockerfile.dev", line=7))))[
        "runs"
    ][0]["results"]
    assert result["locations"][0]["physicalLocation"] == {
        "artifactLocation": {"uri": "a/Dockerfile.dev"},
        "region": {"startLine": 7, "startColumn": 1},
    }


def test_adapt_accepts_an_empty_list() -> None:
    assert json.loads(adapter.adapt(b"[]"))["runs"][0]["results"] == []


@pytest.mark.parametrize(
    "raw",
    [
        b"non json",
        b"{}",
        json.dumps([1]).encode(),
        native(item(code=None)),
        native(item(file=None)),
        native(item(file="/etc/passwd")),
        native(item(file="/workspace/../etc/x")),
        native(item(file="/workspace/a//b")),
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
        ('{"disable_rules": ["DL3008", "DL3007", "DL3008"]}', ["DL3007", "DL3008"]),
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
        '{"disable_rules": "DL3008"}',
        '{"disable_rules": ["--no-fail"]}',
        '{"disable_rules": ["DL3008 DL3009"]}',
        '{"disable_rules": [1]}',
        '{"ignored": ["DL3008"]}',
        json.dumps({"disable_rules": [f"DL{i}" for i in range(501)]}),
    ],
)
def test_load_disabled_rejects_anything_else(tmp_path: Path, content: str) -> None:
    path = tmp_path / "config.json"
    path.write_text(content)
    with pytest.raises(adapter.InvalidConfig):
        adapter.load_disabled(str(path))


def test_find_dockerfiles_takes_only_regular_dockerfiles(tmp_path: Path) -> None:
    ws = tmp_path / "ws"
    for rel in ("Dockerfile", "a/Dockerfile.prod", "b/web.dockerfile", "c/Containerfile"):
        (ws / rel).parent.mkdir(parents=True, exist_ok=True)
        (ws / rel).write_text("FROM x\n")
    for rel in ("README.md", "node_modules/p/Dockerfile", ".git/Dockerfile", "Dockerfiles.txt"):
        (ws / rel).parent.mkdir(parents=True, exist_ok=True)
        (ws / rel).write_text("x\n")
    (ws / "link.Dockerfile").symlink_to("/etc/hostname")
    (ws / "big").mkdir()
    (ws / "big/Dockerfile").write_text("#" * (adapter.MAX_FILE_BYTES + 1))
    names = sorted(Path(p).relative_to(ws).as_posix() for p in adapter.find_dockerfiles(str(ws)))
    assert names == ["Dockerfile", "a/Dockerfile.prod", "b/web.dockerfile", "c/Containerfile"]


def test_find_dockerfiles_respects_the_count_cap(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(adapter, "MAX_FILES", 2)
    for i in range(5):
        (tmp_path / f"Dockerfile.{i}").write_text("FROM x\n")
    assert len(adapter.find_dockerfiles(str(tmp_path))) == 2


def test_command_disables_pragmas_and_never_reads_a_configuration_file() -> None:
    argv = adapter.command(
        "/usr/local/bin/hadolint", ["/workspace/Dockerfile"], ["DL3008", "DL3007"]
    )
    assert "--disable-ignore-pragma" in argv and "--no-fail" in argv
    assert argv.count("--ignore") == 2 and argv[-1] == "/workspace/Dockerfile"
    assert not any(a in argv for a in ("--config", "-c", "--trusted-registry", "--require-label"))


def test_workspace_without_dockerfiles_gives_an_empty_valid_sarif(tmp_path: Path) -> None:
    ws = tmp_path / "ws"
    ws.mkdir()
    out = tmp_path / "results.sarif"
    code = adapter.run(
        hadolint="/nonexistent", workspace=str(ws), out_file=str(out), config_file="/nonexistent"
    )
    assert code == 0 and json.loads(out.read_text())["runs"][0]["results"] == []


def test_invalid_config_is_exit_4_and_runs_nothing(tmp_path: Path) -> None:
    (tmp_path / "config.json").write_text('{"disable_rules": ["--no-fail"]}')
    out = tmp_path / "results.sarif"
    code = adapter.run(
        hadolint="/nonexistent",
        out_file=str(out),
        config_file=str(tmp_path / "config.json"),
        tmp_dir=str(tmp_path),
    )
    assert code == 4 and not out.exists()


def test_run_tool_failure_is_exit_3(tmp_path: Path) -> None:
    ws = tmp_path / "ws"
    ws.mkdir()
    (ws / "Dockerfile").write_text("FROM x\n")
    out = tmp_path / "results.sarif"
    code = adapter.run(
        hadolint="/nonexistent",
        workspace=str(ws),
        out_file=str(out),
        config_file="/nonexistent",
        tmp_dir=str(tmp_path),
    )
    assert code == 3 and not out.exists()


def test_adapter_does_not_import_ca_core() -> None:
    assert not re.search(
        r"^\s*(?:from|import)\s+ca_", (HADOLINT / "hadolint_adapter.py").read_text(), re.M
    )


# --- immagine (statico) -------------------------------------------------------------------


def test_dockerfile_pins_the_bases_and_checks_the_downloads() -> None:
    text = (HADOLINT / "Dockerfile").read_text()
    froms = re.findall(r"^FROM\s+(?:--platform=\S+\s+)?(\S+)", text, re.M)
    assert len(froms) == 2 and all(re.search(r"@sha256:[0-9a-f]{64}$", f) for f in froms)
    assert (
        f"--checksum=sha256:{BINARY_SHA256}" in text
        and f"--checksum=sha256:{LICENSE_SHA256}" in text
    )
    assert "hadolint/releases/download/v2.15.1/hadolint-linux-x86_64" in text
    code = "\n".join(line for line in text.splitlines() if not line.lstrip().startswith("#"))
    assert "latest" not in code.lower()
    assert 'ca.engines="hadolint"' in text and "org.opencontainers.image.licenses" not in text
    assert "USER 65534:65534" in text
    assert re.search(r'^ENTRYPOINT \["python", "/opt/ca-plugin/hadolint_adapter.py"\]$', text, re.M)


def test_build_context_has_no_copy_of_the_engine_license() -> None:
    """Il testo si scarica dal tag durante la build: nel repository non c'e' (D2-14)."""
    assert (HADOLINT / ".dockerignore").read_text().split() == [
        "*",
        "!hadolint_adapter.py",
        "!licenses",
    ]
    assert sorted(p.name for p in (HADOLINT / "licenses").iterdir()) == ["THIRD-PARTY-NOTICES.md"]


def test_notices_carry_the_source_offer_and_the_internal_use_scope() -> None:
    notices = " ".join((HADOLINT / "licenses/THIRD-PARTY-NOTICES.md").read_text().split())
    assert "non dichiara la licenza del prodotto" in notices.lower()
    assert "v2.15.1" in notices and "2eece55955ced00200be9729e9728cb7dacca505" in notices
    assert "solo per uso interno" in notices and "Offerta della sorgente" in notices
