"""G-02, G-03: il grafo estratto è conforme a C-02, deterministico e regge a input ostile (S-02)."""

import json
import os
from pathlib import Path

import pytest
from graph_builders import build, graph, modules
from jsonschema import Draft202012Validator

pytest.importorskip("tree_sitter")

from ca_core.models.graph import Graph  # noqa: E402
from ca_graph.treesitter import files as fs  # noqa: E402
from ca_graph.treesitter.extract import extract_graph, to_json  # noqa: E402

ROOT = Path(__file__).resolve().parents[3]
SCHEMA = json.loads((ROOT / "schemas/graph.schema.json").read_text())
REPOS = ROOT / "tests/fixtures/repos"


def conforms(document: dict) -> None:
    assert list(Draft202012Validator(SCHEMA).iter_errors(document)) == []
    Graph.model_validate(document)  # ordine, unicità e riferimenti: invarianti del modello


@pytest.mark.parametrize(
    "fixture", ["python-app", "js-ts-app", "quality-python", "quality-js-ts", "iac-app"]
)
def test_graph_of_the_fixture_repositories_conforms_to_the_contract(fixture: str) -> None:
    document = extract_graph(str(REPOS / fixture))
    conforms(document)
    assert document["stats"]["files_parsed"] == len(document["modules"])


def test_python_app_fixture_has_the_expected_modules_and_externals() -> None:
    document = extract_graph(str(REPOS / "python-app"))
    assert {"app/db.py", "app/handlers.py"} <= set(modules(document))
    assert {e["name"] for e in document["externals"]} >= {"requests", "yaml"}


def test_js_ts_app_fixture_has_its_external_packages() -> None:
    document = extract_graph(str(REPOS / "js-ts-app"))
    assert {e["name"] for e in document["externals"]} == {"express"}
    assert modules(document)["src/server.ts"]["language"] == "typescript"


def test_a_mixed_workspace_conforms_and_is_deterministic(tmp_path: Path) -> None:
    files = {
        "py/__init__.py": "",
        "py/a.py": "from . import b\nimport requests\nimport os\n",
        "py/b.py": "from .a import x\n",
        "web/tsconfig.json": '{"compilerOptions": {"paths": {"@/*": ["src/*"]}}}',
        "web/src/index.ts": "import u from '@/u';\nimport r from 'react';\n",
        "web/src/u.ts": "import { i } from './index';\n",
        "web/src/view.tsx": "import React from 'react';\nexport const V = () => <p/>;\n",
        "web/src/plain.js": "const x = require('./u');\n",
    }
    first = graph(tmp_path / "one", files)
    conforms(first)
    # stessi file creati in un altro ordine: stessi byte
    second = graph(tmp_path / "two", dict(reversed(list(files.items()))))
    assert to_json(first) == to_json(second)
    assert to_json(first).endswith(b"\n") and first["entrypoints"] == [] and first["packages"] == []
    assert first["history"] == {"status": "assente", "window_days": 90}


def test_an_empty_workspace_gives_an_empty_valid_graph(tmp_path: Path) -> None:
    document = graph(tmp_path, {"README.md": "x\n"})
    conforms(document)
    assert document["modules"] == [] and document["stats"]["files_parsed"] == 0


# --- input ostile ----------------------------------------------------------------------------------


def test_symlinks_and_special_files_are_never_followed_or_read(tmp_path: Path) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret.py").write_text("import leaked_from_outside\n")
    ws = build(tmp_path / "ws", {"ok.py": "import real\n"})
    (ws / "link.py").symlink_to(outside / "secret.py")
    (ws / "dirlink").symlink_to(outside)
    os.mkfifo(ws / "pipe.py")
    document = extract_graph(str(ws))
    conforms(document)
    assert [m["path"] for m in document["modules"]] == ["ok.py"]
    assert {e["name"] for e in document["externals"]} == {"real"}


def test_a_file_over_the_size_cap_is_counted_and_skipped(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(fs, "MAX_FILE_BYTES", 64)
    document = graph(tmp_path, {"small.py": "import a\n", "big.py": "import b\n" + "# x\n" * 100})
    assert [m["path"] for m in document["modules"]] == ["small.py"]
    assert document["stats"]["files_skipped_size"] == 1


def test_too_many_files_fail_the_extraction_instead_of_truncating(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(fs, "MAX_FILES", 3)
    build(tmp_path, {f"f{i}.py": "" for i in range(5)})
    with pytest.raises(fs.LimitExceeded):
        extract_graph(str(tmp_path))


def test_syntax_errors_and_binary_content_make_files_partial_not_fatal(tmp_path: Path) -> None:
    ws = build(tmp_path, {"good.py": "import a\n", "bad.py": "def f(:\n  import b\n"})
    (ws / "binary.py").write_bytes(bytes(range(256)) * 10)
    (ws / "latin1.py").write_bytes("# caf\xe9\nimport c\n".encode("latin-1"))
    document = extract_graph(str(ws))
    conforms(document)
    parse = {m["path"]: m["parse"] for m in document["modules"]}
    assert parse["good.py"] == "completa" and parse["bad.py"] == "parziale"
    assert document["stats"]["files_partial"] >= 1 and len(parse) == 4


def test_a_file_name_with_control_characters_is_skipped_and_counted(tmp_path: Path) -> None:
    ws = build(tmp_path, {"ok.py": ""})
    (ws / "a\nb.py").write_text("import x\n")
    (ws / "c d.py").write_text("import y\n")
    document = extract_graph(str(ws))
    conforms(document)  # un nome con a capo romperebbe l'intero grafo: si salta e si conta
    assert {m["path"] for m in document["modules"]} == {"ok.py", "c d.py"}
    assert document["stats"]["files_skipped_name"] == 1


def test_the_extractor_never_executes_anything_from_the_workspace(tmp_path: Path) -> None:
    marker = tmp_path / "executed"
    ws = build(
        tmp_path / "ws",
        {
            "setup.py": f"open({str(marker)!r}, 'w').write('x')\n",
            "conftest.py": f"open({str(marker)!r}, 'w').write('x')\n",
            "package.json": '{"name": "p", "scripts": {"postinstall": "touch executed"}}',
            "eslint.config.js": f"require('fs').writeFileSync({str(marker)!r}, 'x');\n",
        },
    )
    extract_graph(str(ws))
    assert not marker.exists()


# --- fixture F-01: archi e metriche attesi, scritti dal progetto e non dall'estrattore ------------


def expected_graph(fixture: str) -> dict:
    import yaml

    return yaml.safe_load((REPOS / fixture / "expected-graph.yaml").read_text(encoding="utf-8"))


@pytest.mark.parametrize("fixture", ["graph-python", "graph-js-ts"])
def test_f01_internal_edges_match_the_designed_expectations(fixture: str) -> None:
    expected = expected_graph(fixture)
    document = extract_graph(str(REPOS / fixture))
    conforms(document)
    tests = {m["path"] for m in document["modules"] if m["test"]}
    assert sorted(tests) == sorted(expected["test_modules"])
    got = sorted(
        [e["source"], e["target"]]
        for e in document["edges"]
        if not e["external"] and e["source"] not in tests
    )
    assert got == expected["internal_edges"]
    assert document["externals"] == [] and document["stats"]["unresolved"]["missing"] == 0
    assert {e["confidence"] for e in document["edges"]} <= {"dichiarato", "dedotto"}


@pytest.mark.parametrize("fixture", ["graph-python", "graph-js-ts"])
def test_f01_extractor_then_metrics_gives_the_designed_numbers(fixture: str) -> None:
    from ca_graph.deps import with_metrics

    expected = expected_graph(fixture)
    result = with_metrics(Graph.model_validate(extract_graph(str(REPOS / fixture))))
    modules = {m.path: m.metrics for m in result.modules}
    for path, want in expected["metrics"]["modules"].items():
        assert modules[path] is not None
        assert (modules[path].fan_in, modules[path].fan_out) == (want["ca"], want["ce"]), path
    packages = {p.path: p.metrics for p in result.packages}
    assert set(packages) == set(expected["metrics"]["packages"])
    for path, want in expected["metrics"]["packages"].items():
        assert (packages[path].fan_in, packages[path].fan_out) == (want["ca"], want["ce"]), path
        assert packages[path].instability == pytest.approx(want["instability"], abs=1e-4), path
    assert all(modules[t] is None for t in expected["test_modules"])  # il test non conta


def test_every_read_module_has_its_physical_lines(tmp_path: Path) -> None:
    """ADR-0023: le righe servono alla densità di violazioni (K-09)."""
    document = graph(
        tmp_path,
        {"a.py": "x = 1\ny = 2\n", "b.py": "x = 1\ny = 2", "c.py": "", "d.ts": "\n\n\n"},
    )
    found = {path: m["lines"] for path, m in modules(document).items()}
    assert found == {"a.py": 2, "b.py": 2, "c.py": 0, "d.ts": 3}
