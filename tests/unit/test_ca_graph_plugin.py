"""Plugin ca-graph (G-09) senza Docker: manifest, adattatore, contesto di build, Dockerfile.

L'immagine vera si prova a parte (profilo `hardened-container`): qui si prova che l'adattatore
dia gli stessi byte dell'estrazione in processo, che i fallimenti abbiano codici chiari, e che il
contesto di build sia fatto solo di ciò che serve.
"""

import importlib.util
import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest
import yaml
from jsonschema import Draft202012Validator

pytest.importorskip("tree_sitter")

from ca_core.models import PluginManifest  # noqa: E402
from ca_graph.treesitter import files as fs  # noqa: E402
from ca_graph.treesitter.extract import extract_graph, to_json  # noqa: E402

ROOT = Path(__file__).resolve().parents[2]
PLUGIN = ROOT / "packages/ca-plugins/src/ca_plugins/builtin/ca_graph"
FIXTURES = ROOT / "tests/fixtures/repos"
STAGE = ROOT / "deploy/docker/stage-context.sh"
LOCK_SHA256 = {
    "tree-sitter==0.26.1": "7b14ac81a2afdcf75610f714f1d2eeaac40da93965c104cabb5c4c2b536a488a",  # cp312
    "tree-sitter-python==0.25.0": "86f118e5eecad616ecdb81d171a36dde9bef5a0b21ed71ea9c3e390813c3baf5",
    "tree-sitter-javascript==0.25.0": "9dc04ba91fc8583344e57c1f1ed5b2c97ecaaf47480011b92fbeab8dda96db75",
    "tree-sitter-typescript==0.23.2": "e96d36b85bcacdeb8ff5c2618d75593ef12ebaf1b4eace3477e2bdb2abb1752c",
}

_spec = importlib.util.spec_from_file_location("ca_graph_adapter", PLUGIN / "ca_graph_adapter.py")
assert _spec and _spec.loader
adapter = importlib.util.module_from_spec(_spec)
sys.modules["ca_graph_adapter"] = adapter
_spec.loader.exec_module(adapter)

MANIFEST: dict[str, Any] = yaml.safe_load((PLUGIN / "plugin.yaml").read_text())


# --- manifest -----------------------------------------------------------------------------------


def test_manifest_valid_for_schema_and_model() -> None:
    schema = json.loads((ROOT / "schemas" / "plugin-manifest.schema.json").read_text())
    Draft202012Validator(schema).validate(MANIFEST)
    model = PluginManifest.model_validate(MANIFEST)
    assert (model.name, model.network, model.inputs.config) == ("ca-graph", "none", "none")
    assert [c.value for c in model.categories] == ["architecture"]
    assert model.outputs.graph == "/out/graph.json" and model.outputs.sarif is None
    assert model.outputs.max_bytes == adapter.MAX_BYTES  # un solo valore: adattatore e manifest


def test_manifest_has_no_real_registry_and_no_digest() -> None:
    image = MANIFEST["image"]
    assert image.startswith("registry.invalid/") and "@" not in image and ":latest" not in image


# --- adattatore ---------------------------------------------------------------------------------


@pytest.mark.parametrize("fixture", ["graph-python", "graph-js-ts", "python-app", "js-ts-app"])
def test_the_adapter_writes_exactly_the_in_process_extraction(fixture: str, tmp_path: Path) -> None:
    out = tmp_path / "graph.json"
    assert adapter.run(workspace=str(FIXTURES / fixture), out_file=str(out)) == 0
    assert out.read_bytes() == to_json(extract_graph(str(FIXTURES / fixture)))


def test_the_recorded_output_is_the_graph_python_fixture() -> None:
    recorded = PLUGIN / "fixtures/output/ca-graph.graph-python.graph.json"
    assert recorded.read_bytes() == to_json(extract_graph(str(FIXTURES / "graph-python")))


def test_a_limit_failure_is_exit_3_and_writes_nothing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(fs, "MAX_FILES", 2)
    out = tmp_path / "graph.json"
    assert adapter.run(workspace=str(FIXTURES / "graph-python"), out_file=str(out)) == 3
    assert not out.exists()


def test_a_graph_over_the_byte_limit_is_exit_5_and_writes_nothing(tmp_path: Path) -> None:
    out = tmp_path / "graph.json"
    code = adapter.run(workspace=str(FIXTURES / "graph-python"), out_file=str(out), max_bytes=100)
    assert code == 5 and not out.exists()


def test_an_unwritable_output_is_exit_3(tmp_path: Path) -> None:
    code = adapter.run(
        workspace=str(FIXTURES / "python-app"), out_file=str(tmp_path / "no/such/dir/graph.json")
    )
    assert code == 3


def test_a_missing_workspace_gives_an_empty_valid_graph_not_a_crash(tmp_path: Path) -> None:
    out = tmp_path / "graph.json"
    assert adapter.run(workspace=str(tmp_path / "absent"), out_file=str(out)) in (0, 3)


def test_the_adapter_imports_only_the_extractor_and_the_standard_library() -> None:
    text = (PLUGIN / "ca_graph_adapter.py").read_text()
    imports = re.findall(r"^(?:from|import)\s+([\w.]+)", text, re.M)
    assert set(imports) <= {
        "sys",
        "pathlib",
        "ca_graph.treesitter.extract",
        "ca_graph.treesitter.files",
    }
    assert not re.search(r"^\s*(?:from|import)\s+ca_core", text, re.M)


# --- contesto di build ---------------------------------------------------------------------------


def staged(context: Path) -> Path:
    done = subprocess.run([str(STAGE), str(context)], capture_output=True, text=True, check=False)
    assert done.returncode == 0, done.stderr
    return Path(done.stdout.strip())


def listing(root: Path) -> list[str]:
    return sorted(p.relative_to(root).as_posix() for p in root.rglob("*") if p.is_file())


def test_the_staged_context_has_the_extractor_and_no_other_package_code(tmp_path: Path) -> None:
    root = staged(PLUGIN)
    try:
        files = listing(root)
        assert "ca_graph/__init__.py" in files and "ca_graph_adapter.py" in files
        assert {f for f in files if f.startswith("ca_graph/")} == {
            "ca_graph/__init__.py",
            *(
                f"ca_graph/treesitter/{n}.py"
                for n in (
                    "__init__",
                    "entrypoints",
                    "extract",
                    "files",
                    "history",
                    "javascript",
                    "python",
                    "refs",
                )
            ),
        }
        assert "context.sources" not in files and not any(
            "__pycache__" in f or f.endswith(".pyc") for f in files
        )
        assert not any(
            f.startswith("ca_graph/")
            and f.split("/")[1] in ("deps.py", "smells", "pagerank.py", "step.py")
            for f in files
        )
        # la sorgente dell'estrattore e' una sola: i byte sono quelli di packages/ca-graph
        source = ROOT / "packages/ca-graph/src/ca_graph/treesitter/files.py"
        assert (root / "ca_graph/treesitter/files.py").read_bytes() == source.read_bytes()
    finally:
        subprocess.run(["rm", "-rf", str(root)], check=True)


def test_a_plugin_without_context_sources_is_built_from_its_own_folder() -> None:
    folder = ROOT / "packages/ca-plugins/src/ca_plugins/builtin/ruff"
    assert staged(folder) == folder


def make_context(tmp_path: Path, lines: str) -> Path:
    context = tmp_path / "ctx"
    context.mkdir()
    (context / "Dockerfile").write_text("FROM scratch\n")
    (context / "context.sources").write_text(lines)
    return context


@pytest.mark.parametrize(
    "line",
    [
        "../secrets.txt x",
        "/etc/passwd x",
        "pyproject.toml ../out",
        "pyproject.toml /abs",
        "no/such/file x",
        "pyproject.toml",
        "pyproject.toml a b",
        "packages/../pyproject.toml x",
    ],
)
def test_the_stage_script_refuses_unsafe_or_malformed_lines(tmp_path: Path, line: str) -> None:
    done = subprocess.run(
        [str(STAGE), str(make_context(tmp_path, line + "\n"))],
        capture_output=True,
        text=True,
        check=False,
    )
    assert done.returncode == 2 and done.stdout.strip() == ""


def test_the_stage_script_refuses_a_symlink_source(tmp_path: Path) -> None:
    link = ROOT / "tests/unit/.stage-link-for-test"
    link.symlink_to("/etc/hostname")
    try:
        done = subprocess.run(
            [str(STAGE), str(make_context(tmp_path, "tests/unit/.stage-link-for-test x\n"))],
            capture_output=True,
            text=True,
            check=False,
        )
    finally:
        link.unlink()
    assert done.returncode == 2


def test_comments_and_blank_lines_are_ignored_and_the_original_is_untouched(tmp_path: Path) -> None:
    context = make_context(tmp_path, "# commento\n\npyproject.toml copied/pyproject.toml\n")
    root = staged(context)
    try:
        assert listing(root) == ["Dockerfile", "copied/pyproject.toml"]
        assert (context / "context.sources").exists()
    finally:
        subprocess.run(["rm", "-rf", str(root)], check=True)


# --- immagine (statico) -------------------------------------------------------------------------


def test_dockerfile_pins_the_base_and_installs_with_hashes() -> None:
    text = (PLUGIN / "Dockerfile").read_text()
    froms = re.findall(r"^FROM\s+(?:--platform=\S+\s+)?(\S+)", text, re.M)
    assert len(froms) == 2 and all(re.search(r"@sha256:[0-9a-f]{64}$", f) for f in froms)
    code = "\n".join(line for line in text.splitlines() if not line.lstrip().startswith("#"))
    assert "latest" not in code.lower()
    assert "--require-hashes" in text and "--only-binary=:all:" in text and "--no-deps" in text
    assert 'ca.engines="tree-sitter"' in text and "org.opencontainers.image.licenses" not in text
    assert "USER 65534:65534" in text
    assert re.search(r'^ENTRYPOINT \["python", "/opt/ca-plugin/ca_graph_adapter.py"\]$', text, re.M)


def test_lock_pins_the_four_packages_with_the_wheel_hashes_of_v01() -> None:
    lock = (PLUGIN / "requirements.lock").read_text()
    assert set(re.findall(r"^([A-Za-z0-9_.-]+==[\d.]+)", lock, re.M)) == set(LOCK_SHA256)
    for package, digest in LOCK_SHA256.items():
        block = lock[lock.index(package) :].split("\n    # via")[0]
        assert "--hash=sha256:" in block
        assert digest in lock, package
    assert set((PLUGIN / "requirements.in").read_text().split()) == set(LOCK_SHA256)


def test_build_context_and_license_files() -> None:
    assert (PLUGIN / ".dockerignore").read_text().split() == [
        "*", "!ca_graph", "!ca_graph_adapter.py", "!requirements.lock", "!licenses",
    ]  # fmt: skip
    assert (PLUGIN / "context.sources").exists()
    notices = " ".join((PLUGIN / "licenses/THIRD-PARTY-NOTICES.md").read_text().split()).lower()
    assert "non dichiara la licenza del prodotto" in notices and "input non fidato" in notices
    for name in ("LICENSE", "LICENSE.python", "LICENSE.javascript", "LICENSE.typescript"):
        assert (
            "Permission is hereby granted" in (PLUGIN / "licenses/tree-sitter" / name).read_text()
        )


def test_the_cli_image_and_package_scripts_include_the_ca_graph_wheel() -> None:
    assert "ca-graph" in (ROOT / "deploy/docker/package-cli.sh").read_text()
    assert "ca_graph" in (ROOT / "deploy/docker/cli/build-cli-image.sh").read_text()
