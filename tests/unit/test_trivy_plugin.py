"""Plugin trivy (P-04, P-05) senza Docker e senza rete: manifest, adattatore, fixture, immagine.

Le prove sull'immagine reale sono in `tests/integration/test_trivy_image.py`. L'output registrato
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
PLUGIN = ROOT / "packages/ca-plugins/src/ca_plugins/builtin/trivy"
OUTPUTS = sorted((PLUGIN / "fixtures/output").glob("trivy.*.sarif"))
SHA256 = "bc0fc726e017b8927a62b2d3531d7a84ee01769daf5c99ed866dced54089fdbf"  # V-01

_spec = importlib.util.spec_from_file_location("trivy_adapter", PLUGIN / "trivy_adapter.py")
assert _spec and _spec.loader
adapter = importlib.util.module_from_spec(_spec)
sys.modules["trivy_adapter"] = adapter
_spec.loader.exec_module(adapter)

MANIFEST: dict[str, Any] = yaml.safe_load((PLUGIN / "plugin.yaml").read_text())
VECTOR = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"


def native() -> dict[str, Any]:
    vulnerability = {
        "VulnerabilityID": "CVE-2021-3749",
        "VendorIDs": ["GHSA-cph5-m8f7-6c5x"],
        "PkgName": "axios",
        "PkgIdentifier": {"PURL": "pkg:npm/axios@0.21.0", "UID": "x"},
        "InstalledVersion": "0.21.0",
        "SeveritySource": "ghsa",
        "Title": "nodejs-axios: ReDoS\nin trim",
        "Severity": "HIGH",
        "CVSS": {
            "nvd": {"V3Vector": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H", "V3Score": 7.4},
            "ghsa": {"V3Vector": VECTOR, "V3Score": 7.5},
        },
    }
    misconfiguration = {
        "ID": "DS-0001",
        "Title": "':latest' tag used",
        # Message puo' riportare dati del repository: non deve arrivare nel SARIF.
        "Message": "Specify a tag in the 'FROM' statement for image 'node'",
        "Severity": "MEDIUM",
        "Status": "FAIL",
        "CauseMetadata": {"StartLine": 1, "EndLine": 1, "Code": {"Lines": [{"Content": "SECRET"}]}},
    }
    return {
        "Results": [
            {
                "Target": "package-lock.json",
                "Class": "lang-pkgs",
                "Vulnerabilities": [vulnerability],
            },
            {
                "Target": "Dockerfile",
                "Class": "config",
                "Misconfigurations": [
                    misconfiguration,
                    {**misconfiguration, "ID": "DS-0002", "Status": "PASS"},
                    {"ID": "DS-0026", "Severity": "LOW", "Status": "FAIL", "CauseMetadata": {}},
                ],
            },
            {"Target": "infra", "Class": "config", "MisconfSummary": {}},
        ]
    }


def sarif_of(document: dict[str, Any]) -> dict[str, Any]:
    result: dict[str, Any] = json.loads(adapter.adapt(json.dumps(document).encode()))
    return result


# --- manifest ---------------------------------------------------------------------------


def test_manifest_valid_for_schema_and_model() -> None:
    schema = json.loads((ROOT / "schemas" / "plugin-manifest.schema.json").read_text())
    Draft202012Validator(schema).validate(MANIFEST)
    model = PluginManifest.model_validate(MANIFEST)
    assert model.name == "trivy"
    assert [c.value for c in model.categories] == ["dependency", "iac"]  # category per risultato
    assert model.outputs.sarif == "/out/results.sarif" and model.outputs.cyclonedx is None
    assert (model.inputs.sbom, model.inputs.config, model.network) == ("none", "none", "none")


def test_manifest_has_no_real_registry_and_no_digest() -> None:
    image = MANIFEST["image"]
    assert image.startswith("registry.invalid/") and "@" not in image  # D-0005 aperta
    assert not image.endswith(":latest")


def test_manifest_limits_cover_the_measured_outputs() -> None:
    assert "X-02" in (PLUGIN / "plugin.yaml").read_text()
    assert MANIFEST["outputs"]["max_bytes"] > 100 * max(p.stat().st_size for p in OUTPUTS)


def test_feeds_block_has_the_sync_command_and_no_ecosystem_list() -> None:
    feeds = PluginManifest.model_validate(MANIFEST).feeds
    assert feeds is not None
    assert feeds.ecosystems == []  # vuoto: trivy non scarica per ecosistema (ADR-0006)
    assert feeds.mount == "/feeds"
    assert feeds.sync_command == ["python", "/opt/ca-plugin/trivy_adapter.py", "sync"]
    assert feeds.sync_timeout != MANIFEST["resources"]["timeout"]


# --- fixture registrate ---------------------------------------------------------------------


def test_recorded_outputs_exist_for_both_fixture_repositories() -> None:
    assert [p.name for p in OUTPUTS] == ["trivy.js-ts-app.sarif", "trivy.python-app.sarif"]


@pytest.mark.parametrize("path", OUTPUTS, ids=lambda p: p.name)
def test_recorded_outputs_have_the_contract_shape(path: Path) -> None:
    text = path.read_text()
    assert "/workspace" not in text and "/home/" not in text and "/tmp/" not in text
    assert "snippet" not in text and "uriBaseId" not in text
    document = json.loads(text)
    assert document["version"] == "2.1.0" and len(document["runs"]) == 1
    for result in document["runs"][0]["results"]:
        props = result["properties"]
        assert props["category"] in {"dependency", "iac"}
        assert ("purl" in props) == (props["category"] == "dependency")
        assert "uri" in result["locations"][0]["physicalLocation"]["artifactLocation"]


@pytest.mark.parametrize("fixture", ["js-ts-app", "python-app"])
def test_recorded_outputs_report_the_expected_findings(fixture: str) -> None:
    expected = yaml.safe_load(
        (ROOT / "tests/fixtures/repos" / fixture / "expected-findings.yaml").read_text()
    )["expected"]
    results = json.loads((PLUGIN / f"fixtures/output/trivy.{fixture}.sarif").read_text())["runs"][
        0
    ]["results"]
    found = {(r["properties"]["category"], r["ruleId"]) for r in results}
    wanted = {
        (e["category"], e.get("cve") or e["rule_id"])
        for e in expected
        if e["category"] in {"dependency", "iac"} and "trivy" in e["tools"]
    }
    assert wanted <= found
    for e in expected:  # i percorsi attesi sono quelli dei risultati, senza prefissi
        if "trivy" in e["tools"]:
            ids = {e.get("cve") or e["rule_id"]}
            uris = {
                r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
                for r in results
                if r["ruleId"] in ids
            }
            assert e["path"] in uris


# --- adattatore: conversione ---------------------------------------------------------------


def test_adapt_vulnerability_has_purl_aliases_cvss_and_category() -> None:
    sarif = sarif_of(native())
    assert sarif["version"] == "2.1.0" and len(sarif["runs"]) == 1
    vulnerability = sarif["runs"][0]["results"][0]
    assert vulnerability["ruleId"] == "CVE-2021-3749"
    assert vulnerability["properties"] == {
        "category": "dependency",
        "purl": "pkg:npm/axios@0.21.0",
        "aliases": ["GHSA-cph5-m8f7-6c5x"],  # VendorIDs: gli alias che il SARIF di trivy non ha
        "cvss": {"version": "3.1", "vector": VECTOR, "score": 7.5},  # SeveritySource per primo
        "tool_severity": "HIGH",
    }
    assert vulnerability["level"] == "error"
    assert vulnerability["message"]["text"].endswith("'CVE-2021-3749': nodejs-axios: ReDoS in trim")
    location = vulnerability["locations"][0]["physicalLocation"]
    assert location == {"artifactLocation": {"uri": "package-lock.json"}}  # niente uriBaseId


def test_adapt_misconfiguration_keeps_only_failures_and_never_the_repo_values() -> None:
    results = sarif_of(native())["runs"][0]["results"][1:]
    assert [r["ruleId"] for r in results] == ["DS-0001", "DS-0026"]  # PASS escluso
    first, second = results
    assert first["properties"] == {"category": "iac", "tool_severity": "MEDIUM"}
    assert first["locations"][0]["physicalLocation"] == {
        "artifactLocation": {"uri": "Dockerfile"},
        "region": {"startLine": 1, "endLine": 1},
    }
    assert (
        "region" not in second["locations"][0]["physicalLocation"]
    )  # nessuna riga: nessuna regione
    text = json.dumps(results)
    assert "SECRET" not in text and "image 'node'" not in text  # Message e Code non escono


def test_adapt_os_packages_have_no_location() -> None:
    document = native()
    document["Results"] = [
        {
            "Target": "alpine 3.18 (alpine 3.18.0)",
            "Class": "os-pkgs",
            "Vulnerabilities": document["Results"][0]["Vulnerabilities"],
        }
    ]
    result = sarif_of(document)["runs"][0]["results"][0]
    assert "locations" not in result and result["properties"]["category"] == "dependency"


def test_adapt_makes_workspace_targets_relative_and_drops_duplicates() -> None:
    document = native()
    document["Results"][0]["Target"] = "/workspace/web/package-lock.json"
    document["Results"][0]["Vulnerabilities"] *= 2
    results = sarif_of(document)["runs"][0]["results"]
    uri = results[0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
    assert uri == "web/package-lock.json"
    assert [r["ruleId"] for r in results].count("CVE-2021-3749") == 1


def test_adapt_without_results_has_zero_results() -> None:
    assert sarif_of({})["runs"][0]["results"] == []
    assert sarif_of({"Results": None})["runs"][0]["results"] == []


@pytest.mark.parametrize("severity", ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"])
def test_adapt_maps_severity_to_a_sarif_level(severity: str) -> None:
    document = native()
    document["Results"][0]["Vulnerabilities"][0]["Severity"] = severity
    level = sarif_of(document)["runs"][0]["results"][0]["level"]
    assert level == {"CRITICAL": "error", "HIGH": "error", "MEDIUM": "warning"}.get(
        severity, "note"
    )


@pytest.mark.parametrize(
    "mutate",
    [
        lambda d: d["Results"][0].update(Target="/etc/passwd"),
        lambda d: d["Results"][0].update(Target="../x"),
        lambda d: d["Results"][0].update(Target="file:///x"),
        lambda d: d["Results"][0]["Vulnerabilities"][0].pop("PkgIdentifier"),
        lambda d: d["Results"][0]["Vulnerabilities"][0].pop("VulnerabilityID"),
        lambda d: d.update(Results="x"),
    ],
    ids=["absolute", "dotdot", "scheme", "no-purl", "no-id", "not-a-list"],
)
def test_adapt_rejects_what_it_cannot_make_conforming(mutate: Any) -> None:
    document = native()
    mutate(document)
    with pytest.raises(adapter.InvalidOutput):
        adapter.adapt(json.dumps(document).encode())


@pytest.mark.parametrize("raw", [b"not json", b"[]"], ids=["not-json", "not-object"])
def test_adapt_rejects_non_documents(raw: bytes) -> None:
    with pytest.raises(adapter.InvalidOutput):
        adapter.adapt(raw)


# --- adattatore: esecuzione ----------------------------------------------------------------


def fake_trivy(tmp_path: Path, body: str) -> str:
    script = tmp_path / "trivy"
    script.write_text(f"#!/bin/sh\n{body}\n")
    script.chmod(script.stat().st_mode | stat.S_IXUSR)
    return str(script)


def run_adapter(tmp_path: Path, body: str) -> tuple[int, Path]:
    out = tmp_path / "results.sarif"
    code = adapter.run(
        trivy=fake_trivy(tmp_path, body),
        workspace="/workspace",
        cache_dir="/feeds/trivy",
        out_file=str(out),
        tmp_file=str(tmp_path / "raw.json"),
    )
    return code, out


def writing(document: dict[str, Any], status: int = 0) -> str:
    return (
        'while [ $# -gt 0 ]; do [ "$1" = --output ] && f="$2"; shift; done\n'
        f"cat > \"$f\" <<'EOF'\n{json.dumps(document)}\nEOF\nexit {status}"
    )


def test_run_passes_the_offline_arguments_and_writes_the_sarif(tmp_path: Path) -> None:
    args = tmp_path / "args"
    body = f'echo "$@" > {args}; pwd > {tmp_path}/cwd; printf "%s|" "$@" > {tmp_path}/exact\n'
    code, out = run_adapter(tmp_path, body + writing(native()))
    assert code == 0
    argv = args.read_text().split()
    assert argv[:4] == ["fs", "--scanners", "vuln,misconfig", "--offline-scan"]
    assert "license" not in argv[2] and "secret" not in argv[2]
    for flag in (
        "--skip-db-update",
        "--skip-check-update",
        "--skip-version-check",
        "--disable-telemetry",
    ):
        assert flag in argv
    assert argv[argv.index("--cache-dir") + 1] == "/feeds/trivy"
    exact = (tmp_path / "exact").read_text().split("|")  # N-01: nessun file del repository
    assert exact[exact.index("--config") + 1] == "" and exact[exact.index("--ignorefile") + 1] == ""
    assert not (tmp_path / "cwd").read_text().strip().startswith(("/workspace", str(tmp_path)))
    assert argv[-1] == "/workspace" and argv[argv.index("--format") + 1] == "json"
    assert {
        r["properties"]["category"] for r in json.loads(out.read_text())["runs"][0]["results"]
    } == {"dependency", "iac"}


def test_run_trivy_failure_is_exit_3_and_writes_nothing(tmp_path: Path) -> None:
    code, out = run_adapter(
        tmp_path, "echo secret-from-repo >&2; exit 1"
    )  # per esempio: nessun database
    assert (code, out.exists()) == (adapter.EXIT_TRIVY, False)


def test_run_trivy_without_output_is_exit_3(tmp_path: Path) -> None:
    assert run_adapter(tmp_path, "exit 0")[0] == adapter.EXIT_TRIVY


def test_run_missing_binary_is_exit_3(tmp_path: Path) -> None:
    assert (
        adapter.run(trivy=str(tmp_path / "nope"), out_file=str(tmp_path / "o"))
        == adapter.EXIT_TRIVY
    )


def test_run_nonconforming_output_is_exit_5_and_writes_nothing(tmp_path: Path) -> None:
    code, out = run_adapter(tmp_path, writing({"Results": "x"}))
    assert (code, out.exists()) == (adapter.EXIT_INVALID, False)


def test_run_never_leaks_stderr_or_stdout(
    tmp_path: Path, capfd: pytest.CaptureFixture[str]
) -> None:
    run_adapter(tmp_path, "echo token=abc; echo token=abc >&2; exit 1")
    assert capfd.readouterr() == ("", "")


def test_sync_downloads_database_then_rules_without_workspace(tmp_path: Path) -> None:
    log = tmp_path / "calls"
    body = f'echo "$@" >> {log}'
    assert adapter.sync(trivy=fake_trivy(tmp_path, body), cache_dir="/feeds/trivy") == 0
    first, second = log.read_text().splitlines()
    assert first.split()[:3] == ["fs", "--download-db-only", "--cache-dir"]
    assert second.split()[:2] == ["config", "--cache-dir"]
    assert (
        "/workspace" not in first + second and "/feeds/trivy" in first and "/feeds/trivy" in second
    )


@pytest.mark.parametrize("failing", ["--download-db-only", "config"])
def test_sync_fails_when_either_step_fails(tmp_path: Path, failing: str) -> None:
    body = f'for a in "$@"; do [ "$a" = {failing} ] && exit 1; done; exit 0'
    assert adapter.sync(trivy=fake_trivy(tmp_path, body)) == adapter.EXIT_SYNC


def test_main_dispatch() -> None:
    assert adapter.main(["--help"]) == adapter.EXIT_TRIVY
    assert adapter.main(["sync", "extra"]) == adapter.EXIT_TRIVY


def test_adapter_does_not_import_ca_core() -> None:
    assert not re.search(
        r"^\s*(?:from|import)\s+ca_", (PLUGIN / "trivy_adapter.py").read_text(), re.M
    )


# --- immagine (statico) -------------------------------------------------------------------


def test_dockerfile_pins_base_binary_and_labels() -> None:
    text = (PLUGIN / "Dockerfile").read_text()
    froms = re.findall(r"^FROM\s+(?:--platform=\S+\s+)?(\S+)", text, re.M)
    assert froms and all(re.search(r"@sha256:[0-9a-f]{64}$", f) for f in froms)
    code = "\n".join(line for line in text.splitlines() if not line.lstrip().startswith("#"))
    assert "latest" not in code.lower()
    assert f"--checksum=sha256:{SHA256}" in text
    assert "trivy_0.76.2_Linux-64bit.tar.gz" in text
    assert 'ca.engines="trivy"' in text
    assert "org.opencontainers.image.licenses" not in text  # D-0015
    assert "USER 65534:65534" in text
    assert re.search(r'^ENTRYPOINT \["python", "/opt/ca-plugin/trivy_adapter.py"\]$', text, re.M)


def test_build_context_contains_only_what_the_image_needs() -> None:
    assert (PLUGIN / ".dockerignore").read_text().split() == ["*", "!trivy_adapter.py", "!licenses"]


def test_license_files_are_the_release_texts_without_a_product_license() -> None:
    notices = (PLUGIN / "licenses/THIRD-PARTY-NOTICES.md").read_text()
    assert "Apache-2.0" in notices
    assert "non dichiara la licenza del prodotto" in " ".join(notices.split()).lower()
    licence = (PLUGIN / "licenses/trivy/LICENSE").read_text()
    assert "Apache License" in licence and "Version 2.0, January 2004" in licence
    assert "Aqua Security" in (PLUGIN / "licenses/trivy/NOTICE").read_text()
