"""Plugin scancode (P-06) senza Docker: manifest, adattatore, fixture registrate, Dockerfile.

Le prove sull'immagine reale sono in `tests/integration/test_scancode_image.py`.
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
SCANCODE = ROOT / "packages/ca-plugins/src/ca_plugins/builtin/scancode"
OUTPUTS = sorted((SCANCODE / "fixtures/output").glob("scancode.*.sarif"))
WHEEL_SHA256 = "f6bc16880d495393c8475a77155ddc38a800c0b7f8f75e81a165a00fadb4ca06"  # V-01

_spec = importlib.util.spec_from_file_location("scancode_adapter", SCANCODE / "scancode_adapter.py")
assert _spec and _spec.loader
adapter = importlib.util.module_from_spec(_spec)
sys.modules["scancode_adapter"] = adapter
_spec.loader.exec_module(adapter)

MANIFEST: dict[str, Any] = yaml.safe_load((SCANCODE / "plugin.yaml").read_text())


def entry(path: str, spdx: str | None, *lines: tuple[int, int], **changes: Any) -> dict[str, Any]:
    matches = [{"start_line": a, "end_line": b, "matched_text": "SECRET-TEXT"} for a, b in lines]
    result: dict[str, Any] = {
        "path": path,
        "type": "file",
        "detected_license_expression_spdx": spdx,
        "license_detections": [{"matches": matches}] if matches else [],
        "scan_errors": [],
    }
    return {**result, **changes}


def native(*files: dict[str, Any], errors: list[str] | None = None) -> bytes:
    document = {
        "headers": [{"tool_name": "scancode-toolkit", "errors": errors or []}],
        "files": list(files),
    }
    return json.dumps(document).encode()


# --- manifest ---------------------------------------------------------------------------


def test_manifest_valid_for_schema_and_model() -> None:
    schema = json.loads((ROOT / "schemas" / "plugin-manifest.schema.json").read_text())
    Draft202012Validator(schema).validate(MANIFEST)
    model = PluginManifest.model_validate(MANIFEST)
    assert (model.name, model.network, model.inputs.config) == ("scancode", "none", "none")
    assert model.outputs.sarif == "/out/results.sarif" and model.languages == []
    assert [c.value for c in model.categories] == ["license"]


def test_manifest_has_no_real_registry_and_no_digest() -> None:
    image = MANIFEST["image"]
    assert image.startswith("registry.invalid/") and "@" not in image  # D-0005 aperta
    assert not image.endswith(":latest")


def test_manifest_limits_are_documented_and_cover_the_measurements() -> None:
    text = (SCANCODE / "plugin.yaml").read_text()
    assert "X-02" in text and "V-08" in text and "249 s" in text
    assert MANIFEST["outputs"]["max_bytes"] >= 1000 * 8830  # massimo misurato (excalidraw)
    res = MANIFEST["resources"]
    assert (res["cpu"], res["memory"], res["timeout"], res["pids"]) == ("4", "6Gi", "600s", 128)


# --- fixture registrate ---------------------------------------------------------------------


def test_recorded_outputs_exist_for_both_fixture_repositories() -> None:
    assert [p.name for p in OUTPUTS] == ["scancode.js-ts-app.sarif", "scancode.python-app.sarif"]


@pytest.mark.parametrize("path", OUTPUTS, ids=lambda p: p.name)
def test_recorded_outputs_are_clean(path: Path) -> None:
    text = path.read_text()
    assert "/workspace" not in text and "/home/" not in text and "/tmp/" not in text
    assert "snippet" not in text and "matched_text" not in text and "uriBaseId" not in text
    for result in json.loads(text)["runs"][0]["results"]:
        assert result["ruleId"] == "ca.license" and set(result["properties"]) == {"license_spdx"}
        assert not result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"].startswith(
            ("/", "workspace/")
        )


@pytest.mark.parametrize("repo", ["python-app", "js-ts-app"])
def test_recorded_outputs_contain_the_expected_license_findings(repo: str) -> None:
    document = json.loads((SCANCODE / f"fixtures/output/scancode.{repo}.sarif").read_text())
    found = {
        (
            r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],
            r["properties"]["license_spdx"],
        )
        for r in document["runs"][0]["results"]
    }
    expected_file = ROOT / "tests/fixtures/repos" / repo / "expected-findings.yaml"
    expected = yaml.safe_load(expected_file.read_text())["expected"]
    for item in expected:
        if item["category"] == "license" and "scancode" in item["tools"]:
            paths = {p for p, _ in found}
            assert item["path"] in paths, item["path"]
    spdx = {s for _, s in found}
    assert "AGPL-3.0-only" in spdx and any("GPL-3.0-only" in s for s in spdx)


# --- adattatore ---------------------------------------------------------------------------


def test_adapt_makes_one_result_per_file_with_a_license_and_no_text() -> None:
    raw = native(
        entry("a/b.py", "MIT AND GPL-3.0-only", (21, 21), (31, 33)),
        entry("c.js", "AGPL-3.0-only", (1, 1)),
        entry("none.txt", None),
        entry("clue.txt", ""),
        {"path": "dir", "type": "directory", "detected_license_expression_spdx": "MIT"},
    )
    out = json.loads(adapter.adapt(raw))
    first, second = out["runs"][0]["results"]
    assert first["locations"][0]["physicalLocation"] == {
        "artifactLocation": {"uri": "a/b.py"},
        "region": {"startLine": 21, "endLine": 33},  # copre tutte le corrispondenze
    }
    assert first["properties"] == {"license_spdx": "MIT AND GPL-3.0-only"}
    assert (first["ruleId"], first["message"]["text"]) == ("ca.license", adapter.MESSAGE)
    assert second["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "c.js"
    assert "SECRET-TEXT" not in json.dumps(out) and "snippet" not in json.dumps(out)


def test_adapt_without_matches_has_no_region_and_output_is_sorted() -> None:
    raw = native(entry("z.txt", "MIT"), entry("a.txt", "MIT"))
    results = json.loads(adapter.adapt(raw))["runs"][0]["results"]
    assert [r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] for r in results] == [
        "a.txt",
        "z.txt",
    ]
    assert "region" not in results[0]["locations"][0]["physicalLocation"]


@pytest.mark.parametrize(
    "raw",
    [
        b"not json",
        b"[]",
        json.dumps({"files": []}).encode(),
        json.dumps({"headers": [], "files": []}).encode(),
        native(errors=["boom"]),
        native(entry("a", "MIT", scan_errors=["timeout"])),
        native(entry("/etc/passwd", "MIT")),
        native(entry("../x", "MIT")),
        native(entry("a/../x", "MIT")),
        native(entry("", "MIT")),
    ],
    ids=["not-json", "list", "no-headers", "empty-headers", "header-errors", "scan-errors",
         "absolute", "dotdot", "dotdot-inner", "empty-path"],
)  # fmt: skip
def test_adapt_rejects_what_it_cannot_make_conforming(raw: bytes) -> None:
    with pytest.raises(adapter.InvalidOutput):
        adapter.adapt(raw)


def test_processes_follow_the_cgroup_quota(tmp_path: Path) -> None:
    quota = tmp_path / "cpu.max"
    for text, expected in (("400000 100000\n", 4), ("150000 100000\n", 2), ("max 100000\n", 1)):
        quota.write_text(text)
        assert adapter.processes(str(quota)) == expected
    assert adapter.processes(str(tmp_path / "missing")) == 1


def test_command_runs_only_the_license_detection_with_the_documented_flags() -> None:
    argv = adapter.command("/s", "/workspace", "/tmp/r.json", 3)
    assert argv[:3] == ["/s", "--license", "--only-findings"]
    assert {"--strip-root", "--quiet"} <= set(argv) and "--copyright" not in argv
    assert argv[argv.index("-n") + 1] == "3" and argv[argv.index("--timeout") + 1] == "120"
    assert argv[argv.index("--ignore") + 1] == ".git/*" and argv[-3:] == [
        "--json", "/tmp/r.json", "/workspace",
    ]  # fmt: skip


def fake_scancode(tmp_path: Path, body: str) -> str:
    script = tmp_path / "scancode"
    script.write_text(f"#!/bin/sh\n{body}\n")
    script.chmod(script.stat().st_mode | stat.S_IXUSR)
    return str(script)


def run_adapter(tmp_path: Path, body: str) -> tuple[int, Path]:
    out = tmp_path / "results.sarif"
    code = adapter.run(
        scancode=fake_scancode(tmp_path, body),
        workspace="/workspace",
        out_file=str(out),
        tmp_dir=str(tmp_path),
        nproc=1,
    )
    return code, out


def write_raw(document: bytes, exit_code: int = 0) -> str:
    # il file del JSON e' l'argomento che segue `--json`
    loop = 'while [ $# -gt 0 ]; do [ "$1" = --json ] && f=$2; shift; done'
    return f"{loop}\ncat > \"$f\" <<'EOF'\n{document.decode()}\nEOF\nexit {exit_code}"


def test_run_writes_the_adapted_file(tmp_path: Path) -> None:
    code, out = run_adapter(tmp_path, write_raw(native(entry("a.py", "MIT", (1, 1)))))
    assert code == 0
    assert json.loads(out.read_text())["runs"][0]["results"][0]["properties"] == {
        "license_spdx": "MIT"
    }


def test_run_tool_error_is_exit_3_and_writes_nothing(tmp_path: Path) -> None:
    code, out = run_adapter(tmp_path, write_raw(native(), 2))
    assert (code, out.exists()) == (adapter.EXIT_TOOL, False)


def test_run_without_output_is_exit_3(tmp_path: Path) -> None:
    assert run_adapter(tmp_path, "exit 0")[0] == adapter.EXIT_TOOL


def test_run_missing_binary_is_exit_3(tmp_path: Path) -> None:
    code = adapter.run(
        scancode=str(tmp_path / "nope"), out_file=str(tmp_path / "o"), tmp_dir=str(tmp_path)
    )
    assert code == adapter.EXIT_TOOL


def test_run_scan_errors_or_nonconforming_output_are_exit_5(tmp_path: Path) -> None:
    code, out = run_adapter(tmp_path, write_raw(native(entry("a", "MIT", scan_errors=["x"]))))
    assert (code, out.exists()) == (adapter.EXIT_INVALID, False)
    assert run_adapter(tmp_path, write_raw(b"{}"))[0] == adapter.EXIT_INVALID


def test_run_never_leaks_stderr_or_stdout(
    tmp_path: Path, capfd: pytest.CaptureFixture[str]
) -> None:
    run_adapter(tmp_path, "echo token=abc; echo token=abc >&2; exit 2")
    assert capfd.readouterr() == ("", "")


def test_adapter_does_not_import_ca_core() -> None:
    text = (SCANCODE / "scancode_adapter.py").read_text()
    assert not re.search(r"^\s*(?:from|import)\s+ca_", text, re.M)


# --- immagine (statico) -------------------------------------------------------------------


def test_dockerfile_pins_base_wheels_and_collects_the_about_files() -> None:
    text = (SCANCODE / "Dockerfile").read_text()
    froms = re.findall(r"^FROM\s+(?:--platform=\S+\s+)?(\S+)", text, re.M)
    assert len(froms) == 2 and all(re.search(r"@sha256:[0-9a-f]{64}$", f) for f in froms)
    code = "\n".join(line for line in text.splitlines() if not line.lstrip().startswith("#"))
    assert "latest" not in code.lower()
    assert "--require-hashes" in text and "--only-binary=:all:" in text
    assert "*.ABOUT" in text and "/licenses/scancode/about" in text
    assert 'ca.engines="scancode"' in text and "org.opencontainers.image.licenses" not in text
    assert "USER 65534:65534" in text
    assert re.search(r'^ENTRYPOINT \["python", "/opt/ca-plugin/scancode_adapter.py"\]$', text, re.M)


def test_lock_pins_scancode_with_the_published_wheel_hash_and_pluggy_below_1_7() -> None:
    lock = (SCANCODE / "requirements.lock").read_text()
    assert re.search(r"^scancode-toolkit==32\.5\.0 ", lock, re.M) and WHEEL_SHA256 in lock
    pluggy = re.search(r"^pluggy==(\d+)\.(\d+)\.", lock, re.M)
    assert pluggy and (int(pluggy[1]), int(pluggy[2])) < (1, 7)


def test_build_context_contains_only_what_the_image_needs() -> None:
    assert (SCANCODE / ".dockerignore").read_text().split() == [
        "*",
        "!scancode_adapter.py",
        "!requirements.lock",
        "!licenses",
    ]


def test_license_files_are_the_release_texts_without_a_product_license() -> None:
    notices = " ".join((SCANCODE / "licenses/THIRD-PARTY-NOTICES.md").read_text().split())
    assert "Apache-2.0" in notices and "CC-BY-4.0" in notices and ".ABOUT" in notices
    assert "non dichiara la licenza del prodotto" in notices.lower()
    notice = (SCANCODE / "licenses/scancode/NOTICE").read_text()
    assert "Apache-2.0 AND CC-BY-4.0" in notice
    assert (
        "Version 2.0, January 2004"
        in (SCANCODE / "licenses/scancode/apache-2.0.LICENSE").read_text()
    )
    assert "Attribution 4.0" in (SCANCODE / "licenses/scancode/cc-by-4.0.LICENSE").read_text()
