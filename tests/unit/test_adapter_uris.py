"""L'`uri` di ogni adattatore torna al percorso del file attraverso la lettura dell'host (ADR-0004).

L'host rifiuta un `uri` con `?` o `#` e decodifica le sequenze `%XX`: un percorso scritto grezzo
fa fallire il plugin, o attacca il finding a un file diverso. I nomi qui sotto sono nomi di file
legittimi (in `vitejs/vite` una cartella si chiama `#`).
"""

import importlib.util
import json
import os
import sys
from pathlib import Path
from typing import Any

import pytest

from ca_core.normalize import relative_path
from ca_core.sarif import checks

BUILTIN = Path(__file__).resolve().parents[2] / "packages/ca-plugins/src/ca_plugins/builtin"
NAMES = [
    "dir/#/Dockerfile",
    "a?b/Dockerfile",
    "100%41/Dockerfile",  # senza codifica l'host leggerebbe `100A`
    "con spazio/è/Dockerfile",
    "a:b/Dockerfile",
    "semplice/a_b-c.1~/Dockerfile",
]
NOT_UTF8 = os.fsdecode(b"x\xff/Dockerfile")  # nome non UTF-8, come lo restituisce il file system


def load(folder: str) -> Any:
    name = f"uri_probe_{folder}"
    spec = importlib.util.spec_from_file_location(name, BUILTIN / folder / f"{folder}_adapter.py")
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def checkov(adapter: Any, path: str) -> bytes:
    check = {"check_id": "CKV_DOCKER_3", "check_name": "n", "file_path": f"/{path}",
             "file_line_range": [1, 1]}  # fmt: skip
    report = {"check_type": "dockerfile", "results": {"failed_checks": [check]}}
    return adapter.adapt(json.dumps(report).encode())


def hadolint(adapter: Any, path: str) -> bytes:
    item = {"code": "DL3007", "column": 1, "file": f"/workspace/{path}", "level": "warning",
            "line": 1, "message": "m"}  # fmt: skip
    return adapter.adapt(json.dumps([item]).encode())


def scancode(adapter: Any, path: str) -> bytes:
    entry = {"path": path, "type": "file", "detected_license_expression_spdx": "MIT",
             "license_detections": [], "scan_errors": []}  # fmt: skip
    document = {"headers": [{"tool_name": "scancode-toolkit", "errors": []}], "files": [entry]}
    return adapter.adapt(json.dumps(document).encode())


def trivy(adapter: Any, path: str) -> bytes:
    failed = {"ID": "DS-0026", "Severity": "LOW", "Status": "FAIL", "CauseMetadata": {}}
    result = {"Target": path, "Class": "config", "Misconfigurations": [failed]}
    return adapter.adapt(json.dumps({"Results": [result]}).encode())


def osv_scanner(adapter: Any, path: str) -> bytes:
    package = {
        "package": {"name": "lodash", "version": "4.17.15", "ecosystem": "npm",
                    "purl": "pkg:npm/lodash@4.17.15"},
        "vulnerabilities": [{"id": "GHSA-aaaa-bbbb-cccc", "summary": "s"}],
        "groups": [{"ids": ["GHSA-aaaa-bbbb-cccc"], "aliases": []}],
    }  # fmt: skip
    source = {"path": f"/workspace/{path}", "type": "lockfile"}
    return adapter.adapt(
        json.dumps({"results": [{"source": source, "packages": [package]}]}).encode()
    )


def coverage(adapter: Any, path: str) -> bytes:
    lines = dict.fromkeys(range(1, 31), 0)
    return adapter.sarif(adapter.findings({path: lines}))


def semgrep(adapter: Any, path: str) -> bytes:
    """Il motore scrive il percorso grezzo, sotto il workspace."""
    result = {"ruleId": "r", "message": {"text": "m"}, "locations": [
        {"physicalLocation": {"artifactLocation": {"uri": f"/workspace/{path}"}}}]}  # fmt: skip
    document = {
        "version": "2.1.0",
        "runs": [{"tool": {"driver": {"rules": []}}, "results": [result]}],
    }
    return adapter.adapt(json.dumps(document).encode())


def gitleaks(adapter: Any, path: str) -> bytes:
    result = {"ruleId": "github-pat", "locations": [{"physicalLocation": {
        "artifactLocation": {"uri": f"/workspace/{path}"},
        "region": {"startLine": 1, "snippet": {"text": "valore-finto"}}}}]}  # fmt: skip
    document = {"version": "2.1.0", "runs": [{"results": [result]}]}
    return adapter.adapt(json.dumps(document).encode())


ADAPTERS = {
    f.__name__: f
    for f in (checkov, hadolint, scancode, trivy, osv_scanner, coverage, semgrep, gitleaks)
}


def test_bandit_drops_what_it_found_through_a_symlink(tmp_path: Path) -> None:
    """bandit segue i collegamenti e scrive l'`uri` già codificato."""
    (tmp_path / "#").mkdir()
    (tmp_path / "#" / "a.py").write_text("x = 1\n")
    (tmp_path / "link.py").symlink_to("#/a.py")
    (tmp_path / "linked").symlink_to("#", target_is_directory=True)
    uris = ["%23/a.py", "link.py", "linked/a.py"]
    results = [
        {"ruleId": "B102", "message": {"text": "m"}, "locations": [
            {"physicalLocation": {"artifactLocation": {"uri": f"{tmp_path}/{u}"}}}]}
        for u in uris
    ]  # fmt: skip
    document = {
        "version": "2.1.0",
        "runs": [{"tool": {"driver": {"rules": []}}, "results": results}],
    }
    out = json.loads(load("bandit").adapt(json.dumps(document).encode(), str(tmp_path)))
    kept = [r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
            for r in out["runs"][0]["results"]]  # fmt: skip
    assert kept == ["%23/a.py"]


@pytest.mark.parametrize("folder", sorted(ADAPTERS))
@pytest.mark.parametrize("path", NAMES)
def test_the_host_reads_back_the_path_of_the_file(folder: str, path: str) -> None:
    out = json.loads(ADAPTERS[folder](load(folder), path))
    [result] = out["runs"][0]["results"]
    uri = result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
    assert relative_path(uri, "/x") == path


@pytest.mark.parametrize("path", NAMES)
def test_gitleaks_output_passes_the_host_check_on_the_redacted_message(path: str) -> None:
    out = json.loads(gitleaks(load("gitleaks"), path))
    checks.gitleaks_redacted(out)


@pytest.mark.parametrize("folder", sorted(ADAPTERS))
def test_a_name_that_is_not_utf8_survives_the_round_trip(folder: str) -> None:
    out = json.loads(ADAPTERS[folder](load(folder), NOT_UTF8))
    [result] = out["runs"][0]["results"]
    uri = result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
    assert uri.isascii() and relative_path(uri, "/x") == NOT_UTF8
