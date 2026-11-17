"""Plugin checkov (P-03) senza Docker: manifest, adattatore, fixture registrate, Dockerfile.

La conversione si prova sul JSON nativo registrato. Le prove con il checkov vero (configurazione
ostile, soppressioni, collegamenti simbolici) girano solo con `CA_CHECKOV_BIN`, il percorso di un
checkov 3.4.5: nessuna rete (regola 7 di AGENTS.md), quindi nessuna installazione nel test.
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
CHECKOV = ROOT / "packages/ca-plugins/src/ca_plugins/builtin/checkov"
FIXTURE = ROOT / "tests/fixtures/repos/iac-app"
NATIVE = CHECKOV / "fixtures/native/checkov.iac-app.json"
RECORDED = CHECKOV / "fixtures/output/checkov.iac-app.sarif"
WHEEL_SHA256 = "64210c48a957ecb85dfb38057e00faa150b5e46e76b08e710d29beb687b7ced2"  # V-01

_spec = importlib.util.spec_from_file_location("checkov_adapter", CHECKOV / "checkov_adapter.py")
assert _spec and _spec.loader
adapter = importlib.util.module_from_spec(_spec)
sys.modules["checkov_adapter"] = adapter
_spec.loader.exec_module(adapter)

MANIFEST: dict[str, Any] = yaml.safe_load((CHECKOV / "plugin.yaml").read_text())
BIN = os.environ.get("CA_CHECKOV_BIN")


def have_checkov() -> bool:
    if not BIN or not Path(BIN).exists():
        return False
    out = subprocess.run([BIN, "--version"], capture_output=True, text=True, check=False)
    return out.stdout.strip() == "3.4.5"


needs_checkov = pytest.mark.skipif(not have_checkov(), reason="CA_CHECKOV_BIN: checkov 3.4.5")


def scan(workspace: Path, tmp_path: Path, disabled: list[str] | None = None) -> dict[str, Any]:
    config = tmp_path / "config.json"
    if disabled is not None:
        config.write_text(json.dumps({"disable_rules": disabled}))
    out = tmp_path / "results.sarif"
    scratch = tmp_path / "tmp"
    scratch.mkdir(exist_ok=True)
    code = adapter.run(
        checkov=str(BIN),
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
    assert (model.name, model.network, model.inputs.config) == ("checkov", "none", "optional")
    assert [c.value for c in model.categories] == ["iac"]


def test_manifest_has_no_real_registry_and_no_digest() -> None:
    image = MANIFEST["image"]
    assert image.startswith("registry.invalid/") and "@" not in image and ":latest" not in image


# --- fixture registrate ------------------------------------------------------------------------


def test_recorded_output_is_clean_and_covers_the_fixture_expectations() -> None:
    text = RECORDED.read_text()
    assert not any(k in text for k in ("snippet", "code_block", "file://", "/tmp/", "/home/"))
    assert "Pod.default" not in text and "aws_security_group" not in text  # nomi di risorsa
    document = json.loads(text)
    expected = {
        (e["rule_id"], e["path"])
        for e in yaml.safe_load((FIXTURE / "expected-findings.yaml").read_text())["expected"]
        if "checkov" in e["tools"]
    }
    assert expected <= found(document)
    assert len(document["runs"][0]["results"]) == 34  # 5 Dockerfile, 20 Kubernetes, 9 Terraform
    for result in document["runs"][0]["results"]:
        assert set(result["properties"]) <= {"tool_severity"}
        assert result["properties"].get("tool_severity") != "error"


def keys_of(value: Any) -> set[str]:
    if isinstance(value, dict):
        return set(value).union(*(keys_of(v) for v in value.values()))
    if isinstance(value, list):
        return set().union(*(keys_of(v) for v in value))
    return set()


def test_native_sample_carries_what_the_adapter_must_not_let_out() -> None:
    """Il JSON nativo ha frammenti e nomi di risorsa: e' il motivo della conversione."""
    leaked = {"code_block", "resource", "file_abs_path", "fixed_definition", "guideline"}
    assert leaked <= keys_of(json.loads(NATIVE.read_text()))
    assert not keys_of(json.loads(adapter.adapt(NATIVE.read_bytes()))) & leaked


def test_adapting_the_native_sample_reproduces_the_recorded_sarif() -> None:
    assert adapter.adapt(NATIVE.read_bytes()) == RECORDED.read_bytes().rstrip(b"\n")


# --- adattatore con checkov vero -------------------------------------------------------------


@needs_checkov
def test_real_run_reproduces_the_recorded_output(tmp_path: Path) -> None:
    assert scan(FIXTURE, tmp_path) == json.loads(RECORDED.read_text())


def hostile(tmp_path: Path) -> Path:
    ws = tmp_path / "ws"
    shutil_copy = __import__("shutil").copytree
    shutil_copy(FIXTURE, ws)
    (ws / ".checkov.yaml").write_text(
        "soft-fail: true\nskip-check:\n  - CKV_DOCKER_7\n  - CKV_K8S_16\n"
    )
    (ws / ".checkov.baseline").write_text('{"failed_checks": []}')
    (ws / ".checkov").mkdir()
    (ws / ".checkov/custom.py").write_text("raise SystemExit('eseguito')\n")
    (ws / "skipped").mkdir()
    (ws / "skipped/Dockerfile").write_text(
        "#checkov:skip=CKV_DOCKER_7:motivo\nFROM debian:latest\nUSER app\nHEALTHCHECK CMD true\n"
    )
    return ws


@needs_checkov
def test_repository_configuration_has_no_effect(tmp_path: Path) -> None:
    ws = hostile(tmp_path)
    work = tmp_path / "work"
    work.mkdir()
    rules = found(scan(ws, work))
    assert ("CKV_DOCKER_7", "Dockerfile") in rules  # `.checkov.yaml` non lo salta
    assert ("CKV_K8S_16", "k8s/pod.yaml") in rules
    assert not (tmp_path / "ws/.checkov_ran").exists()


@needs_checkov
def test_inline_skip_comment_still_gives_a_finding(tmp_path: Path) -> None:
    ws = hostile(tmp_path)
    work = tmp_path / "work"
    work.mkdir()
    assert ("CKV_DOCKER_7", "skipped/Dockerfile") in found(scan(ws, work))


@needs_checkov
def test_symlink_and_oversized_files_are_not_copied(tmp_path: Path) -> None:
    ws = tmp_path / "ws"
    ws.mkdir()
    (ws / "Dockerfile").write_text("FROM debian:latest\n")
    (ws / "outside.tf").symlink_to("/etc/hostname")
    big = ws / "big.yaml"
    big.write_text("a: " + "x" * (adapter.MAX_FILE_BYTES + 10) + "\n")
    work = tmp_path / "work"
    work.mkdir()
    assert {uri for _, uri in found(scan(ws, work))} == {"Dockerfile"}


@needs_checkov
def test_disable_rules_remove_only_those_checks(tmp_path: Path) -> None:
    work = tmp_path / "work"
    work.mkdir()
    rules = {rule for rule, _ in found(scan(FIXTURE, work, ["CKV_DOCKER_7", "CKV_K8S_16"]))}
    assert "CKV_DOCKER_7" not in rules and "CKV_K8S_16" not in rules
    assert {"CKV_DOCKER_4", "CKV_AWS_24"} <= rules


@needs_checkov
def test_workspace_is_never_written_and_the_copy_is_removed(tmp_path: Path) -> None:
    ws = tmp_path / "ws"
    __import__("shutil").copytree(FIXTURE, ws)
    before = sorted(p.relative_to(ws).as_posix() for p in ws.rglob("*"))
    work = tmp_path / "work"
    work.mkdir()
    scan(ws, work)
    assert sorted(p.relative_to(ws).as_posix() for p in ws.rglob("*")) == before
    assert not list((work / "tmp").glob("ckv-*"))


# --- adattatore: unità --------------------------------------------------------------------------


def native(*checks: dict[str, Any], skipped: tuple[dict[str, Any], ...] = ()) -> bytes:
    return json.dumps(
        [
            {
                "check_type": "dockerfile",
                "results": {"failed_checks": list(checks), "skipped_checks": list(skipped)},
            }
        ]
    ).encode()


def check(**changes: Any) -> dict[str, Any]:
    base = {
        "check_id": "CKV_DOCKER_7",
        "check_name": "Ensure the base image uses a non latest version tag",
        "file_path": "/Dockerfile",
        "file_line_range": [1, 1],
        "code_block": [[1, "FROM secret:latest\n"]],
        "resource": "/Dockerfile.FROM",
    }
    return {**base, **changes}


def test_adapt_keeps_only_id_name_file_and_range() -> None:
    out = adapter.adapt(native(check()))
    [result] = json.loads(out)["runs"][0]["results"]
    assert "secret" not in out.decode()
    assert result["locations"][0]["physicalLocation"] == {
        "artifactLocation": {"uri": "Dockerfile"},
        "region": {"startLine": 1, "endLine": 1},
    }
    assert result["properties"] == {"tool_severity": "medium"}


def test_checks_without_a_known_severity_have_no_severity_and_never_error() -> None:
    [result] = json.loads(adapter.adapt(native(check(check_id="CKV_DOCKER_2"))))["runs"][0][
        "results"
    ]
    assert result["properties"] == {}
    assert "error" not in set(adapter.SEVERITY.values())


def test_skipped_checks_become_findings_and_duplicates_are_merged() -> None:
    out = json.loads(
        adapter.adapt(native(check(), skipped=(check(file_path="/b/Dockerfile"), check())))
    )
    assert sorted(
        r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
        for r in out["runs"][0]["results"]
    ) == [
        "Dockerfile",
        "b/Dockerfile",
    ]


def test_adapt_accepts_a_single_report_and_an_empty_one() -> None:
    single = json.dumps({"check_type": "x", "results": {"failed_checks": [check()]}}).encode()
    assert len(json.loads(adapter.adapt(single))["runs"][0]["results"]) == 1
    empty = json.dumps([{"check_type": "x", "results": {}}]).encode()
    assert json.loads(adapter.adapt(empty))["runs"][0]["results"] == []


@pytest.mark.parametrize(
    "raw",
    [
        b"non json",
        b"7",
        json.dumps([1]).encode(),
        json.dumps([{"check_type": "x"}]).encode(),
        native(check(check_id=None)),
        native(check(file_path="/../etc/passwd")),
        native(check(file_path="//a")),
        native(check(file_path="/")),
        native(check(file_path="/a/./b")),
        native("riga"),  # type: ignore[arg-type]
        b"[" * 100_000,
    ],
)
def test_adapt_rejects_what_it_cannot_make_conforming(raw: bytes) -> None:
    with pytest.raises(adapter.InvalidOutput):
        adapter.adapt(raw)


@pytest.mark.parametrize("name", [".checkov.yaml", ".checkov.yml", ".checkov.baseline"])
def test_configuration_names_are_never_staged(tmp_path: Path, name: str) -> None:
    ws, dest = tmp_path / "ws", tmp_path / "dest"
    ws.mkdir()
    dest.mkdir()
    (ws / name).write_text("soft-fail: true\n")
    (ws / ".checkov").mkdir()
    (ws / ".checkov/x.yaml").write_text("a: 1\n")
    (ws / "ok.yaml").write_text("a: 1\n")
    adapter.stage(str(ws), str(dest))
    assert sorted(p.name for p in dest.rglob("*") if p.is_file()) == ["ok.yaml"]


def test_stage_copies_only_what_the_frameworks_read(tmp_path: Path) -> None:
    ws, dest = tmp_path / "ws", tmp_path / "dest"
    for rel in ("Dockerfile", "app/Dockerfile.prod", "web.dockerfile", "m/main.tf", "k8s/a.yml"):
        (ws / rel).parent.mkdir(parents=True, exist_ok=True)
        (ws / rel).write_text("x\n")
    for rel in ("src/app.py", "node_modules/p/x.yaml", ".git/c.yaml", "README.md"):
        (ws / rel).parent.mkdir(parents=True, exist_ok=True)
        (ws / rel).write_text("x\n")
    dest.mkdir()
    copied, skipped = adapter.stage(str(ws), str(dest))
    staged = sorted(p.relative_to(dest).as_posix() for p in dest.rglob("*") if p.is_file())
    assert staged == [
        "Dockerfile",
        "app/Dockerfile.prod",
        "k8s/a.yml",
        "m/main.tf",
        "web.dockerfile",
    ]
    assert (copied, skipped) == (5, 0)


def test_stage_respects_the_file_count_cap(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(adapter, "MAX_FILES", 2)
    ws, dest = tmp_path / "ws", tmp_path / "dest"
    ws.mkdir()
    dest.mkdir()
    for i in range(5):
        (ws / f"f{i}.yaml").write_text("a: 1\n")
    assert adapter.stage(str(ws), str(dest)) == (2, 3)


def test_command_is_offline_and_limited_to_three_frameworks() -> None:
    argv = adapter.command("/opt/venv/bin/checkov", "/tmp/x/ws", ["CKV_DOCKER_7", "CKV_K8S_16"])
    assert "--skip-download" in argv and argv[argv.index("-o") + 1] == "json"
    frameworks = argv[argv.index("--framework") + 1 : argv.index("--skip-download")]
    assert frameworks == ["dockerfile", "kubernetes", "terraform"]
    assert argv[argv.index("--skip-check") + 1] == "CKV_DOCKER_7,CKV_K8S_16"
    assert not any(
        a in argv for a in ("--config-file", "--external-checks-dir", "--download-external-modules")
    )


def test_invalid_config_is_exit_4_and_runs_nothing(tmp_path: Path) -> None:
    (tmp_path / "config.json").write_text('{"disable_rules": ["--soft-fail"]}')
    out = tmp_path / "results.sarif"
    code = adapter.run(
        checkov="/nonexistent",
        out_file=str(out),
        config_file=str(tmp_path / "config.json"),
        tmp_dir=str(tmp_path),
    )
    assert code == 4 and not out.exists()


def test_run_tool_failure_is_exit_3_and_cleans_up(tmp_path: Path) -> None:
    out = tmp_path / "results.sarif"
    ws = tmp_path / "ws"
    ws.mkdir()
    code = adapter.run(
        checkov="/nonexistent",
        workspace=str(ws),
        out_file=str(out),
        config_file="/nonexistent",
        tmp_dir=str(tmp_path),
    )
    assert code == 3 and not out.exists() and not list(tmp_path.glob("ckv-*"))


def test_adapter_does_not_import_ca_core() -> None:
    assert not re.search(
        r"^\s*(?:from|import)\s+ca_", (CHECKOV / "checkov_adapter.py").read_text(), re.M
    )


# --- immagine (statico) -------------------------------------------------------------------


def test_dockerfile_pins_base_and_wheels_and_labels() -> None:
    text = (CHECKOV / "Dockerfile").read_text()
    froms = re.findall(r"^FROM\s+(?:--platform=\S+\s+)?(\S+)", text, re.M)
    assert len(froms) == 2 and all(re.search(r"@sha256:[0-9a-f]{64}$", f) for f in froms)
    code = "\n".join(line for line in text.splitlines() if not line.lstrip().startswith("#"))
    assert "latest" not in code.lower()
    assert "--require-hashes" in text and "--only-binary=:all:" in text and "--no-deps" in text
    assert 'ca.engines="checkov"' in text and "org.opencontainers.image.licenses" not in text
    assert "USER 65534:65534" in text
    assert re.search(r'^ENTRYPOINT \["python", "/opt/ca-plugin/checkov_adapter.py"\]$', text, re.M)


def test_lock_pins_every_package_with_a_hash() -> None:
    lock = (CHECKOV / "requirements.lock").read_text()
    names = re.findall(r"^([A-Za-z0-9_.-]+)==", lock, re.M)
    assert len(names) == 96 and "checkov" in names and WHEEL_SHA256 in lock
    blocks = re.split(r"^(?=[A-Za-z0-9_.-]+==)", lock, flags=re.M)[1:]
    assert all("--hash=sha256:" in b for b in blocks)
    assert (CHECKOV / "requirements.in").read_text().strip() == "checkov==3.4.5"


def test_build_context_contains_only_what_the_image_needs() -> None:
    assert (CHECKOV / ".dockerignore").read_text().split() == [
        "*",
        "!checkov_adapter.py",
        "!requirements.lock",
        "!licenses",
    ]


def test_license_files_are_the_release_texts_without_a_product_license() -> None:
    notices = (CHECKOV / "licenses/THIRD-PARTY-NOTICES.md").read_text()
    assert "non dichiara la licenza del prodotto" in " ".join(notices.split()).lower()
    licence = (CHECKOV / "licenses/checkov/LICENSE").read_text()
    assert "Apache License" in licence and "Version 2.0, January 2004" in licence
