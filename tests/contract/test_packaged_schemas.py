"""ADR-0003 (emendamento per R-09): gli schemi di terzi fissati stanno nel pacchetto `ca-core`.

Il wheel si costruisce con `uv build` e si installa in un ambiente pulito; fuori dal repository si
apre `SchemaStore.packaged()` e si valida un SARIF minimo. Serve `uv`, nessuna rete.
"""

import hashlib
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from ca_core import schema_validation
from ca_core.schema_validation import (
    MANIFEST_NAME,
    VENDOR_MANIFEST_SHA256,
    SchemaRefusedError,
    SchemaStore,
)

ROOT = Path(__file__).resolve().parents[2]
PACKAGED = ROOT / "packages" / "ca-core" / "src" / "ca_core" / "vendor_schemas"
HAVE_UV = shutil.which("uv") is not None


def test_vendor_dir_is_a_relative_symlink_to_the_packaged_files() -> None:
    link = ROOT / "schemas" / "vendor"
    assert link.is_symlink() and os.readlink(link) == (
        "../packages/ca-core/src/ca_core/vendor_schemas"
    )
    assert link.resolve() == PACKAGED.resolve()


def test_manifest_sha_is_anchored_in_code() -> None:
    raw = (PACKAGED / MANIFEST_NAME).read_bytes()
    assert hashlib.sha256(raw).hexdigest() == VENDOR_MANIFEST_SHA256
    assert (
        VENDOR_MANIFEST_SHA256 == "82ad8f2e84978094bba46e18204cc08a17357f02303e85ed004d8968e95596db"
    )


def test_pre_commit_does_not_rewrite_the_packaged_schemas() -> None:
    text = (ROOT / ".pre-commit-config.yaml").read_text()
    exclude = next(line for line in text.splitlines() if line.startswith("exclude:"))
    assert (
        "packages/ca-core/src/ca_core/vendor_schemas/" in exclude and "schemas/vendor/" in exclude
    )


def test_packaged_store_validates_a_minimal_sarif() -> None:
    store = SchemaStore.packaged()
    sarif = {"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "t"}}, "results": []}]}
    assert store.validate_sarif(sarif) == []
    assert store.validate_sarif({"version": "2.1.0"}) != []


def test_a_changed_manifest_is_refused_before_the_store_is_built(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(schema_validation, "VENDOR_MANIFEST_SHA256", "0" * 64)
    with pytest.raises(SchemaRefusedError, match="SHA-256"):
        SchemaStore.packaged()


def test_vendor_schema_store_uses_the_packaged_store_never_a_tree_search() -> None:
    import inspect

    from ca_cli.composition import vendor_schema_store

    assert "SchemaStore.packaged()" in inspect.getsource(vendor_schema_store)
    assert "parents" not in inspect.getsource(vendor_schema_store)


@pytest.mark.skipif(not HAVE_UV, reason="richiede uv")
def test_built_wheel_installed_outside_the_repository_opens_the_packaged_store(
    tmp_path: Path,
) -> None:
    venv = (
        tmp_path / "venv"
    )  # installazione dal lock: funziona offline anche con la sola cache di `uv sync`
    subprocess.run(
        [
            "uv", "sync", "--frozen", "--offline", "--no-dev", "--no-editable",
            "--package", "ca-core", "--python", sys.executable,
        ],
        cwd=ROOT,
        env={**os.environ, "UV_PROJECT_ENVIRONMENT": str(venv)},
        check=True,
        capture_output=True,
        timeout=300,
    )  # fmt: skip
    python = venv / "bin" / "python"
    work = tmp_path / "elsewhere"  # fuori dal repository: nessun `schemas/vendor` da risalire
    work.mkdir()
    script = (
        "import json\n"
        "from ca_core.schema_validation import SchemaStore\n"
        "import ca_core\n"
        "store = SchemaStore.packaged()\n"
        "doc = {'version': '2.1.0', 'runs': [{'tool': {'driver': {'name': 't'}}, 'results': []}]}\n"
        "print(json.dumps({'errors': store.validate_sarif(doc), 'where': ca_core.__file__}))\n"
    )
    done = subprocess.run(
        [str(python), "-I", "-c", script],
        cwd=work,
        capture_output=True,
        text=True,
        check=True,
        timeout=120,
        env={"PATH": os.environ.get("PATH", "")},
    )
    data = json.loads(done.stdout)
    assert data["errors"] == [] and str(venv) in data["where"] and str(ROOT) not in data["where"]
