"""Plugin osv-scanner (P-02, P-03) senza Docker e senza rete: manifest, adattatore, sync, fixture.

Le prove sull'immagine reale sono in `tests/integration/test_osv_scanner_image.py`. L'output
registrato in `fixtures/output/` e' letto anche dal test di contratto T-04.
Il test di `sync` usa un server HTTP su 127.0.0.1 (nessun servizio esterno, §16 regola 7).
"""

import http.server
import importlib.util
import io
import json
import re
import stat
import sys
import threading
import zipfile
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
import yaml
from jsonschema import Draft202012Validator

from ca_core.models import PluginManifest

ROOT = Path(__file__).resolve().parents[2]
PLUGIN = ROOT / "packages/ca-plugins/src/ca_plugins/builtin/osv_scanner"
OUTPUTS = sorted((PLUGIN / "fixtures/output").glob("osv-scanner.*.sarif"))
SHA256 = "160c6253e2922e9e0a6a9771c5c4c40a4b3c6090b34a3cdd5e80c96cc2e4218b"  # V-01

_spec = importlib.util.spec_from_file_location(
    "osv_scanner_adapter", PLUGIN / "osv_scanner_adapter.py"
)
assert _spec and _spec.loader
adapter = importlib.util.module_from_spec(_spec)
sys.modules["osv_scanner_adapter"] = adapter
_spec.loader.exec_module(adapter)

MANIFEST: dict[str, Any] = yaml.safe_load((PLUGIN / "plugin.yaml").read_text())


def native(**package: Any) -> dict[str, Any]:
    """JSON nativo minimo: lodash con un gruppo di due id (GHSA e CVE) e uno senza CVE."""
    vulns = [
        {
            "id": "GHSA-35jh-r3h4-6jhm",
            "aliases": ["CVE-2021-23337"],
            "summary": "Command Injection\nin lodash",
            "severity": [
                {"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H"},
                {"type": "CVSS_V4", "score": "CVSS:4.0/AV:N/AC:L/AT:N/PR:H/UI:N/VC:H/VI:H/VA:H"},
            ],
            "database_specific": {"severity": "HIGH"},
        },
        {"id": "PYSEC-2021-1", "aliases": ["CVE-2021-23337"]},
        {"id": "GHSA-aaaa-bbbb-cccc", "summary": "senza CVE", "severity": []},
    ]
    groups = [
        {"ids": ["GHSA-35jh-r3h4-6jhm", "PYSEC-2021-1"], "aliases": ["CVE-2021-23337"]},
        {"ids": ["GHSA-aaaa-bbbb-cccc"], "aliases": ["GHSA-aaaa-bbbb-cccc"]},
    ]
    return {
        "results": [
            {
                "source": {"path": "/workspace/web/package-lock.json", "type": "lockfile"},
                "packages": [
                    {
                        "package": {
                            "name": "lodash",
                            "version": "4.17.15",
                            "ecosystem": "npm",
                            "purl": "pkg:npm/lodash@4.17.15?source=PUBLIC_REGISTRY",
                            **package,
                        },
                        "vulnerabilities": vulns,
                        "groups": groups,
                    }
                ],
            }
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
    assert model.name == "osv-scanner"
    assert [c.value for c in model.categories] == ["dependency"]
    assert model.outputs.sarif == "/out/results.sarif"
    assert model.outputs.cyclonedx is None
    assert (model.inputs.sbom, model.inputs.config, model.network) == ("none", "none", "none")


def test_manifest_has_no_real_registry_and_no_digest() -> None:
    image = MANIFEST["image"]
    assert image.startswith("registry.invalid/") and "@" not in image  # D-0005 aperta
    assert not image.endswith(":latest")


def test_manifest_limits_cover_the_measured_outputs() -> None:
    text = (PLUGIN / "plugin.yaml").read_text()
    assert "X-02" in text
    assert MANIFEST["outputs"]["max_bytes"] > 100 * max(p.stat().st_size for p in OUTPUTS)
    assert MANIFEST["outputs"]["max_bytes"] >= 16 * 239_500  # massimo misurato: excalidraw


def test_feeds_block_is_the_closed_list_of_the_adapter() -> None:
    feeds = PluginManifest.model_validate(MANIFEST).feeds
    assert feeds is not None
    ecosystems = [e.value for e in feeds.ecosystems]
    assert ecosystems and set(ecosystems) <= set(adapter.ECOSYSTEMS)  # ADR-0006: mai vuoto
    assert feeds.mount == "/feeds"
    assert feeds.sync_command == [
        "python",
        "/opt/ca-plugin/osv_scanner_adapter.py",
        "sync",
        *ecosystems,
    ]
    assert re.fullmatch(r"\d+s", feeds.sync_timeout)
    assert feeds.sync_timeout != MANIFEST["resources"]["timeout"]


# --- fixture registrate ---------------------------------------------------------------------


def test_recorded_outputs_exist_for_both_fixture_repositories() -> None:
    assert [p.name for p in OUTPUTS] == [
        "osv-scanner.js-ts-app.sarif",
        "osv-scanner.python-app.sarif",
    ]


@pytest.mark.parametrize("path", OUTPUTS, ids=lambda p: p.name)
def test_recorded_outputs_have_the_contract_shape(path: Path) -> None:
    text = path.read_text()
    assert "/workspace" not in text and "/home/" not in text and "/tmp/" not in text
    assert "snippet" not in text and "uriBaseId" not in text
    document = json.loads(text)
    assert document["version"] == "2.1.0" and len(document["runs"]) == 1
    results = document["runs"][0]["results"]
    assert results
    for result in results:
        props = result["properties"]
        assert props["category"] == "dependency"
        assert props["purl"].startswith("pkg:") and "?" not in props["purl"]
        uri = result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
        assert uri in {"package-lock.json", "poetry.lock"}


@pytest.mark.parametrize("fixture", ["js-ts-app", "python-app"])
def test_recorded_outputs_report_the_expected_cves(fixture: str) -> None:
    expected = yaml.safe_load(
        (ROOT / "tests/fixtures/repos" / fixture / "expected-findings.yaml").read_text()
    )
    wanted = {e["cve"] for e in expected["expected"] if e["category"] == "dependency"}
    results = json.loads((PLUGIN / f"fixtures/output/osv-scanner.{fixture}.sarif").read_text())[
        "runs"
    ][0]["results"]
    assert {r["ruleId"] for r in results} >= wanted
    cvss = [r["properties"]["cvss"] for r in results if "cvss" in r["properties"]]
    assert cvss and all(c["vector"].startswith("CVSS:3.") for c in cvss)


# --- CVSS -------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("vector", "score"),
    [
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),
        ("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N", 8.6),
        ("CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H", 7.2),
        ("CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N", 0.0),
    ],
)
def test_cvss3_score_matches_the_specification(vector: str, score: float) -> None:
    assert adapter.cvss3(vector) == {"version": vector[5:8], "vector": vector, "score": score}


@pytest.mark.parametrize(
    "vector",
    [
        "",
        "AV:N/AC:L",
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:H/UI:N/VC:H/VI:H/VA:H",
        "CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    ],
)
def test_cvss3_rejects_what_it_cannot_score(vector: str) -> None:
    assert adapter.cvss3(vector) is None


# --- adattatore: conversione ---------------------------------------------------------------


def test_adapt_builds_sarif_with_aliases_cvss_and_purl() -> None:
    sarif = sarif_of(native())
    assert sarif["version"] == "2.1.0" and len(sarif["runs"]) == 1
    first, second = sarif["runs"][0]["results"]
    assert first["ruleId"] == "CVE-2021-23337"
    assert first["properties"] == {
        "category": "dependency",
        "purl": "pkg:npm/lodash@4.17.15",  # senza `?source=...`: come gli altri scanner (fusione)
        "aliases": ["GHSA-35jh-r3h4-6jhm", "PYSEC-2021-1"],
        "cvss": {
            "version": "3.1",
            "vector": "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H",
            "score": 7.2,
        },
        "tool_severity": "HIGH",
    }
    assert first["level"] == "error"
    assert first["message"]["text"] == (
        "Package 'lodash@4.17.15' is vulnerable to 'CVE-2021-23337': Command Injection in lodash"
    )
    assert first["locations"][0]["physicalLocation"]["artifactLocation"] == {
        "uri": "web/package-lock.json"
    }
    assert second["ruleId"] == "GHSA-aaaa-bbbb-cccc"  # nessuna CVE: l'id primario
    assert "aliases" not in second["properties"] and "cvss" not in second["properties"]
    assert second["level"] == "warning"


def test_adapt_without_vulnerabilities_has_zero_results() -> None:
    document = native()
    document["results"][0]["packages"][0]["groups"] = []
    assert sarif_of(document)["runs"][0]["results"] == []
    assert sarif_of({"results": []})["runs"][0]["results"] == []


def test_adapt_writes_no_snippet_and_no_base_id() -> None:
    text = json.dumps(sarif_of(native()))
    assert "snippet" not in text and "uriBaseId" not in text and "/workspace" not in text


@pytest.mark.parametrize(
    "raw",
    [
        b"not json",
        b"[]",
        b"{}",
        json.dumps({"results": [{"source": {"path": "/etc/passwd"}, "packages": []}]}).encode(),
        json.dumps({"results": [{"source": {"path": "/workspace/../x"}, "packages": []}]}).encode(),
        json.dumps(native(purl="nope")).encode(),
        json.dumps(
            {"results": [{"source": {"path": "/workspace/a"}, "packages": [{"groups": [{}]}]}]}
        ).encode(),
    ],
    ids=["not-json", "not-object", "no-results", "outside", "dotdot", "bad-purl", "bad-package"],
)
def test_adapt_rejects_what_it_cannot_make_conforming(raw: bytes) -> None:
    with pytest.raises(adapter.InvalidOutput):
        adapter.adapt(raw)


# --- adattatore: esecuzione ----------------------------------------------------------------


def fake_scanner(tmp_path: Path, body: str) -> str:
    script = tmp_path / "osv-scanner"
    script.write_text(f"#!/bin/sh\n{body}\n")
    script.chmod(script.stat().st_mode | stat.S_IXUSR)
    return str(script)


def run_adapter(tmp_path: Path, body: str) -> tuple[int, Path]:
    out = tmp_path / "results.sarif"
    code = adapter.run(
        scanner=fake_scanner(tmp_path, body),
        workspace="/workspace",
        feeds="/feeds-under-test",
        out_file=str(out),
        tmp_file=str(tmp_path / "raw.json"),
    )
    return code, out


def writing(document: dict[str, Any], status: int, log: str = "") -> str:
    """Corpo dello scanner finto: scrive il JSON nel file di `--output-file`, stampa `log`."""
    return (
        'while [ $# -gt 0 ]; do [ "$1" = --output-file ] && f="$2"; shift; done\n'
        f"cat > \"$f\" <<'EOF'\n{json.dumps(document)}\nEOF\n"
        f"echo '{log}'; exit {status}"
    )


def test_run_passes_the_fixed_arguments_and_the_feeds_directory(tmp_path: Path) -> None:
    args = tmp_path / "args"
    body = f'echo "$@" > {args}; echo "$OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY" > {tmp_path}/env\n'
    body += writing(native(), 1)
    code, out = run_adapter(tmp_path, body)
    assert code == 0  # exit 1 = vulnerabilita' trovate: non e' un fallimento
    assert args.read_text().split() == [
        "scan", "source", "--offline-vulnerabilities", "--no-resolve", "-r", "--format", "json",
        "--output-file", str(tmp_path / "raw.json"), "/workspace",
    ]  # fmt: skip
    assert (tmp_path / "env").read_text().strip() == "/feeds-under-test"
    assert json.loads(out.read_text())["runs"][0]["results"][0]["ruleId"] == "CVE-2021-23337"


def test_run_exit_0_without_vulnerabilities(tmp_path: Path) -> None:
    code, out = run_adapter(tmp_path, writing({"results": []}, 0))
    assert (code, json.loads(out.read_text())["runs"][0]["results"]) == (0, [])


def test_run_no_packages_is_an_empty_outcome_not_a_failure(tmp_path: Path) -> None:
    code, out = run_adapter(tmp_path, "echo 'No package sources found, --help for usage'; exit 128")
    assert (code, json.loads(out.read_text())["runs"][0]["results"]) == (0, [])


def test_run_exit_128_for_another_reason_is_a_failure(tmp_path: Path) -> None:
    code, out = run_adapter(tmp_path, "echo 'invalid flag'; exit 128")
    assert (code, out.exists()) == (adapter.EXIT_SCANNER, False)


@pytest.mark.parametrize("status", [0, 1, 127])
def test_run_could_not_load_db_fails_the_plugin_whatever_the_exit(
    tmp_path: Path, status: int
) -> None:
    log = (
        "could not load db for PyPI ecosystem: unable to fetch OSV database"  # ecosistema mancante
    )
    code, out = run_adapter(tmp_path, writing(native(), status, log))
    assert (code, out.exists()) == (adapter.EXIT_SCANNER, False)  # niente risultati parziali


@pytest.mark.parametrize("status", [2, 127, 137])
def test_run_unexpected_exit_is_a_failure(tmp_path: Path, status: int) -> None:
    code, out = run_adapter(tmp_path, writing(native(), status))
    assert (code, out.exists()) == (adapter.EXIT_SCANNER, False)


def test_run_without_output_file_is_a_failure(tmp_path: Path) -> None:
    assert run_adapter(tmp_path, "exit 1")[0] == adapter.EXIT_SCANNER


def test_run_missing_binary_is_a_failure(tmp_path: Path) -> None:
    assert (
        adapter.run(scanner=str(tmp_path / "nope"), out_file=str(tmp_path / "o"))
        == adapter.EXIT_SCANNER
    )


def test_run_nonconforming_output_is_exit_5_and_writes_nothing(tmp_path: Path) -> None:
    code, out = run_adapter(tmp_path, writing({"results": "x"}, 1))
    assert (code, out.exists()) == (adapter.EXIT_INVALID, False)


def test_run_never_leaks_stderr_or_stdout(
    tmp_path: Path, capfd: pytest.CaptureFixture[str]
) -> None:
    run_adapter(tmp_path, "echo token=abc; echo token=abc >&2; exit 2")
    assert capfd.readouterr() == ("", "")


def test_main_rejects_unknown_arguments() -> None:
    assert adapter.main(["--help"]) == adapter.EXIT_SCANNER


# --- sync ---------------------------------------------------------------------------------


def zip_bytes(names: tuple[str, ...] = ("GHSA-1.json",)) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        for name in names:
            archive.writestr(name, "{}")
    return buffer.getvalue()


@pytest.fixture
def server() -> Iterator[tuple[str, list[str]]]:
    requested: list[str] = []
    routes = {
        "/npm/all.zip": zip_bytes(),
        "/PyPI/all.zip": zip_bytes(("a.json", "b.json")),
        "/bad/all.zip": b"x",
    }

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802 - API di http.server
            requested.append(self.path)
            body = routes.get(self.path)
            self.send_response(200 if body is not None else 404)
            self.end_headers()
            self.wfile.write(body or b"")

        def log_message(self, *args: object) -> None:
            pass

    httpd = http.server.HTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{httpd.server_port}", requested
    httpd.shutdown()
    thread.join()


def test_sync_downloads_each_listed_ecosystem_into_the_osv_scalibr_layout(
    tmp_path: Path, server: tuple[str, list[str]]
) -> None:
    base, requested = server
    assert adapter.sync(["npm", "PyPI"], feeds=str(tmp_path), base_url=base) == 0
    assert requested == ["/npm/all.zip", "/PyPI/all.zip"]
    for eco in ("npm", "PyPI"):
        assert zipfile.is_zipfile(tmp_path / "osv-scalibr" / eco / "all.zip")
    assert sorted(p.name for p in tmp_path.rglob("*") if p.is_file()) == [
        "all.zip",
        "all.zip",
    ]  # niente .part


def test_sync_rejects_ecosystems_outside_the_closed_list_without_any_request(
    tmp_path: Path, server: tuple[str, list[str]]
) -> None:
    base, requested = server
    for bad in (["Go"], ["npm", "../x"], ["npm", "npm"], [], ["npm", "http://evil/x"]):
        assert adapter.sync(bad, feeds=str(tmp_path), base_url=base) == adapter.EXIT_SYNC
    assert requested == [] and list(tmp_path.iterdir()) == []


def test_sync_failure_leaves_no_partial_file(tmp_path: Path, server: tuple[str, list[str]]) -> None:
    base, _ = server
    assert (
        adapter.sync(["npm"], feeds=str(tmp_path), base_url=base + "/missing") == adapter.EXIT_SYNC
    )
    assert (
        adapter.sync(["npm"], feeds=str(tmp_path), base_url="http://127.0.0.1:1")
        == adapter.EXIT_SYNC
    )
    assert [p for p in tmp_path.rglob("*") if p.is_file()] == []


def test_sync_rejects_a_download_that_is_not_a_zip(
    tmp_path: Path, server: tuple[str, list[str]], monkeypatch: pytest.MonkeyPatch
) -> None:
    base, _ = server
    monkeypatch.setattr(adapter, "ECOSYSTEMS", ("bad",))
    assert adapter.sync(["bad"], feeds=str(tmp_path), base_url=base) == adapter.EXIT_SYNC
    assert [p for p in tmp_path.rglob("*") if p.is_file()] == []


def test_sync_stops_a_download_over_the_limit(
    tmp_path: Path, server: tuple[str, list[str]], monkeypatch: pytest.MonkeyPatch
) -> None:
    base, _ = server
    monkeypatch.setattr(adapter, "MAX_ZIP_BYTES", 10)
    assert adapter.sync(["npm"], feeds=str(tmp_path), base_url=base) == adapter.EXIT_SYNC
    assert [p for p in tmp_path.rglob("*") if p.is_file()] == []


def test_sync_takes_the_ecosystems_only_from_argv() -> None:
    source = (PLUGIN / "osv_scanner_adapter.py").read_text()
    assert "/workspace" not in source.split("def sync(")[1].split("def main(")[0]
    assert (
        adapter.main(["sync"]) == adapter.EXIT_SYNC
    )  # senza elenco: nessun default dal repository


def test_adapter_does_not_import_ca_core() -> None:
    assert not re.search(
        r"^\s*(?:from|import)\s+ca_", (PLUGIN / "osv_scanner_adapter.py").read_text(), re.M
    )


# --- immagine (statico) -------------------------------------------------------------------


def test_dockerfile_pins_base_binary_and_labels() -> None:
    text = (PLUGIN / "Dockerfile").read_text()
    froms = re.findall(r"^FROM\s+(?:--platform=\S+\s+)?(\S+)", text, re.M)
    assert froms and all(re.search(r"@sha256:[0-9a-f]{64}$", f) for f in froms)
    code = "\n".join(line for line in text.splitlines() if not line.lstrip().startswith("#"))
    assert "latest" not in code.lower()
    assert f"--checksum=sha256:{SHA256}" in text
    assert "releases/download/v2.7.0/osv-scanner_linux_amd64" in text
    assert 'ca.engines="osv-scanner"' in text
    assert "org.opencontainers.image.licenses" not in text  # D-0015
    assert "USER 65534:65534" in text
    assert re.search(
        r'^ENTRYPOINT \["python", "/opt/ca-plugin/osv_scanner_adapter.py"\]$', text, re.M
    )


def test_build_context_contains_only_what_the_image_needs() -> None:
    assert (PLUGIN / ".dockerignore").read_text().split() == [
        "*",
        "!osv_scanner_adapter.py",
        "!licenses",
    ]


def test_license_files_are_the_release_texts_without_a_product_license() -> None:
    notices = (PLUGIN / "licenses/THIRD-PARTY-NOTICES.md").read_text()
    assert "Apache-2.0" in notices
    assert "non dichiara la licenza del prodotto" in " ".join(notices.split()).lower()
    licence = (PLUGIN / "licenses/osv-scanner/LICENSE").read_text()
    assert "Apache License" in licence and "Version 2.0, January 2004" in licence
