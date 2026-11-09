"""Plugin bandit (P-08) senza Docker: manifest, adattatore, fixture registrate, Dockerfile.

Le prove sull'immagine reale sono in `tests/integration/test_bandit_image.py`. L'output registrato
in `fixtures/output/` e' letto anche dal test di contratto T-04 (`tests/contract/plugins`).
"""

import importlib.util
import json
import re
import stat
import sys
from pathlib import Path
from typing import Any

import pytest
import yaml
from jsonschema import Draft202012Validator

from ca_core.models import PluginManifest

ROOT = Path(__file__).resolve().parents[2]
BANDIT = ROOT / "packages/ca-plugins/src/ca_plugins/builtin/bandit"
OUTPUTS = sorted((BANDIT / "fixtures/output").glob("bandit.*.sarif"))
WHEEL_SHA256 = "f89ffa663767f5a0585ea075f01020207e966a9c0f2b9ef56a57c7963a3f6f8e"  # V-01

_spec = importlib.util.spec_from_file_location("bandit_adapter", BANDIT / "bandit_adapter.py")
assert _spec and _spec.loader
adapter = importlib.util.module_from_spec(_spec)
sys.modules["bandit_adapter"] = adapter
_spec.loader.exec_module(adapter)

MANIFEST: dict[str, Any] = yaml.safe_load((BANDIT / "plugin.yaml").read_text())


def location(uri: str) -> dict[str, Any]:
    return {
        "physicalLocation": {
            "artifactLocation": {"uri": uri, "uriBaseId": "%SRCROOT%"},
            "region": {"startLine": 3, "snippet": {"text": "password = 'hunter2'"}},
            "contextRegion": {"startLine": 1, "snippet": {"text": "secret context"}},
        }
    }


def sarif(**changes: Any) -> dict[str, Any]:
    document: dict[str, Any] = {
        "version": "2.1.0",
        "runs": [
            {
                "tool": {"driver": {"name": "Bandit", "rules": [{"id": "B602", "name": "x"}]}},
                "invocations": [{"endTimeUtc": "2026-11-08T15:41:22Z"}],
                "properties": {"metrics": {"/workspace/app.py": {"loc": 1}}},
                "results": [
                    {
                        "ruleId": "B602",
                        "level": "error",
                        "message": {"text": "Possible shell injection."},
                        "locations": [location("file:///workspace/app/handlers.py")],
                        "properties": {"issue_severity": "HIGH", "issue_confidence": "HIGH"},
                    }
                ],
            }
        ],
    }
    return {**document, **changes}


# --- manifest ---------------------------------------------------------------------------


def test_manifest_valid_for_schema_and_model() -> None:
    schema = json.loads((ROOT / "schemas" / "plugin-manifest.schema.json").read_text())
    Draft202012Validator(schema).validate(MANIFEST)
    model = PluginManifest.model_validate(MANIFEST)
    assert (model.name, model.network, model.inputs.config) == ("bandit", "none", "none")
    assert model.outputs.sarif == "/out/results.sarif" and model.outputs.cyclonedx is None
    assert [c.value for c in model.categories] == ["sast"] and model.languages == ["python"]


def test_manifest_has_no_real_registry_and_no_digest() -> None:
    image = MANIFEST["image"]
    assert image.startswith("registry.invalid/") and "@" not in image  # D-0005 aperta
    assert not image.endswith(":latest")


def test_manifest_limits_cover_the_measured_values() -> None:
    assert MANIFEST["outputs"]["max_bytes"] >= 3 * 19_185_152  # massimo misurato (saleor)
    assert MANIFEST["resources"]["timeout"] == "300s" and MANIFEST["resources"]["pids"] == 32
    assert "X-02" in (BANDIT / "plugin.yaml").read_text()


# --- fixture registrate ---------------------------------------------------------------------


def test_recorded_outputs_exist_for_both_fixture_repositories() -> None:
    assert [p.name for p in OUTPUTS] == ["bandit.js-ts-app.sarif", "bandit.python-app.sarif"]


@pytest.mark.parametrize("path", OUTPUTS, ids=lambda p: p.name)
def test_recorded_outputs_are_clean(path: Path) -> None:
    text = path.read_text()
    assert "/workspace" not in text and "/home/" not in text and "/tmp/" not in text
    assert "snippet" not in text and "uriBaseId" not in text and "file://" not in text
    for result in json.loads(text)["runs"][0]["results"]:
        assert set(result["properties"]) == {"tool_severity"}


def test_recorded_python_output_has_the_expected_rules_and_not_the_skipped_ones() -> None:
    document = json.loads((BANDIT / "fixtures/output/bandit.python-app.sarif").read_text())
    found = {
        (r["ruleId"], r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"], line)
        for r in document["runs"][0]["results"]
        if (line := r["locations"][0]["physicalLocation"]["region"]["startLine"])
    }
    expected = {
        (e["rule_id"], e["path"], e["start_line"])
        for e in yaml.safe_load(
            (ROOT / "tests/fixtures/repos/python-app/expected-findings.yaml").read_text()
        )["expected"]
        if "bandit" in e["tools"]
    }
    assert expected <= found
    assert not {"B105", "B106", "B107"} & {rule for rule, _, _ in found}


# --- adattatore ---------------------------------------------------------------------------


def test_adapt_rewrites_uri_and_drops_snippets_and_foreign_properties() -> None:
    out = json.loads(adapter.adapt(json.dumps(sarif()).encode()))
    run = out["runs"][0]
    (result,) = run["results"]
    assert result["locations"][0]["physicalLocation"]["artifactLocation"] == {
        "uri": "app/handlers.py"
    }
    assert result["properties"] == {"tool_severity": "HIGH"}
    assert result["level"] == "error" and result["ruleId"] == "B602"
    text = json.dumps(out)
    assert "snippet" not in text and "hunter2" not in text and "contextRegion" not in text
    assert "/workspace" not in text and "properties" not in run and "invocations" not in run


def test_adapt_keeps_a_relative_path_that_contains_the_word_workspace() -> None:
    document = sarif()
    document["runs"][0]["results"][0]["locations"] = [
        location("file:///workspace/src/workspace/a.py")
    ]
    out = json.loads(adapter.adapt(json.dumps(document).encode()))
    uri = out["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"][
        "uri"
    ]
    assert uri == "src/workspace/a.py"


@pytest.mark.parametrize(
    "raw",
    [
        b"not json",
        b"[]",
        json.dumps(sarif(version="2.0.0")).encode(),
        json.dumps(sarif(runs=[])).encode(),
        json.dumps(sarif(runs=[{}, {}])).encode(),
        json.dumps(
            sarif(runs=[{"results": [{"locations": [location("file:///etc/passwd")]}]}])
        ).encode(),
        json.dumps(
            sarif(
                runs=[
                    {"results": [{"locations": [{"physicalLocation": {"artifactLocation": {}}}]}]}
                ]
            )
        ).encode(),
    ],
    ids=["not-json", "not-object", "version", "no-run", "two-runs", "outside-workspace", "no-uri"],
)
def test_adapt_rejects_what_it_cannot_make_conforming(raw: bytes) -> None:
    with pytest.raises(adapter.InvalidOutput):
        adapter.adapt(raw)


def fake_bandit(tmp_path: Path, body: str) -> str:
    script = tmp_path / "bandit"
    script.write_text(f"#!/bin/sh\n{body}\n")
    script.chmod(script.stat().st_mode | stat.S_IXUSR)
    return str(script)


def run_adapter(tmp_path: Path, body: str) -> tuple[int, Path]:
    out = tmp_path / "results.sarif"
    code = adapter.run(
        bandit=fake_bandit(tmp_path, body),
        workspace="/workspace",
        out_file=str(out),
        tmp_dir=str(tmp_path),
    )
    return code, out


def write_raw(document: dict[str, Any], exit_code: int) -> str:
    # lo script scrive il SARIF nel file passato a `-o` (argomento 6) ed esce con `exit_code`
    return f"cat > \"$6\" <<'EOF'\n{json.dumps(document)}\nEOF\nexit {exit_code}"


@pytest.mark.parametrize("exit_code", [0, 1])
def test_run_passes_the_fixed_arguments_and_accepts_exit_0_and_1(
    tmp_path: Path, exit_code: int
) -> None:
    args = tmp_path / "args"
    code, out = run_adapter(tmp_path, f'echo "$@" > {args}\n' + write_raw(sarif(), exit_code))
    assert code == 0
    assert args.read_text().split() == [
        "-r", "/workspace", "-f", "sarif", "-o", f"{tmp_path}/bandit.sarif",
        "--skip", "B105,B106,B107", "--ini", f"{tmp_path}/bandit.ini", "--ignore-nosec", "-q",
    ]  # fmt: skip
    assert (tmp_path / "bandit.ini").read_text() == "[bandit]\n"  # ignora la config del repo
    assert json.loads(out.read_text())["runs"][0]["results"][0]["ruleId"] == "B602"


def test_run_tool_error_is_exit_3_and_writes_nothing(tmp_path: Path) -> None:
    code, out = run_adapter(tmp_path, write_raw(sarif(), 2))
    assert (code, out.exists()) == (adapter.EXIT_TOOL, False)


def test_run_without_output_is_exit_3(tmp_path: Path) -> None:
    assert run_adapter(tmp_path, "exit 0")[0] == adapter.EXIT_TOOL


def test_run_missing_binary_is_exit_3(tmp_path: Path) -> None:
    code = adapter.run(
        bandit=str(tmp_path / "nope"), out_file=str(tmp_path / "o"), tmp_dir=str(tmp_path)
    )
    assert code == adapter.EXIT_TOOL


def test_run_nonconforming_output_is_exit_5_and_writes_nothing(tmp_path: Path) -> None:
    code, out = run_adapter(tmp_path, "echo '{}' > \"$6\"")
    assert (code, out.exists()) == (adapter.EXIT_INVALID, False)


def test_run_never_leaks_stderr_or_stdout(
    tmp_path: Path, capfd: pytest.CaptureFixture[str]
) -> None:
    run_adapter(tmp_path, "echo token=abc; echo token=abc >&2; exit 2")
    assert capfd.readouterr() == ("", "")


def test_adapter_does_not_import_ca_core() -> None:
    assert not re.search(
        r"^\s*(?:from|import)\s+ca_", (BANDIT / "bandit_adapter.py").read_text(), re.M
    )


# --- immagine (statico) -------------------------------------------------------------------


def test_dockerfile_pins_base_wheels_and_labels() -> None:
    text = (BANDIT / "Dockerfile").read_text()
    froms = re.findall(r"^FROM\s+(?:--platform=\S+\s+)?(\S+)", text, re.M)
    assert len(froms) == 2 and all(re.search(r"@sha256:[0-9a-f]{64}$", f) for f in froms)
    code = "\n".join(line for line in text.splitlines() if not line.lstrip().startswith("#"))
    assert "latest" not in code.lower()
    assert "--require-hashes" in text and "--only-binary=:all:" in text
    assert 'ca.engines="bandit"' in text
    assert "org.opencontainers.image.licenses" not in text  # D-0015
    assert "USER 65534:65534" in text
    assert re.search(r'^ENTRYPOINT \["python", "/opt/ca-plugin/bandit_adapter.py"\]$', text, re.M)


def test_lock_pins_bandit_1_9_4_with_the_published_wheel_hash_and_the_sarif_extra() -> None:
    lock = (BANDIT / "requirements.lock").read_text()
    assert re.search(r"^bandit==1\.9\.4 ", lock, re.M) and WHEEL_SHA256 in lock
    assert re.search(r"^sarif-om==", lock, re.M) and re.search(r"^jschema-to-python==", lock, re.M)
    names = re.findall(r"^([A-Za-z0-9_.-]+)==", lock, re.M)
    assert lock.count("--hash=sha256:") >= len(names)


def test_build_context_contains_only_what_the_image_needs() -> None:
    assert (BANDIT / ".dockerignore").read_text().split() == [
        "*",
        "!bandit_adapter.py",
        "!requirements.lock",
        "!licenses",
    ]


def test_license_files_are_the_release_texts_without_a_product_license() -> None:
    notices = (BANDIT / "licenses/THIRD-PARTY-NOTICES.md").read_text()
    assert "Apache-2.0" in notices
    assert "non dichiara la licenza del prodotto" in " ".join(notices.split()).lower()
    licence = (BANDIT / "licenses/bandit/LICENSE").read_text()
    assert "Apache License" in licence and "Version 2.0, January 2004" in licence
