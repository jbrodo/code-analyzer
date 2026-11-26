"""G-12: estrazione degli entrypoint (ADR-0022) da metadati e convenzioni, letti come dati."""

from pathlib import Path
from typing import Any

import pytest
from graph_builders import extract, graph

from ca_core.models.graph import Graph
from ca_core.scoring.reach import ReachState
from ca_graph.reachability import GraphReachability
from ca_graph.treesitter import entrypoints as ep


def entries(document: dict[str, Any]) -> set[tuple[str, str, str]]:
    return {(e["path"], e["kind"], e["confidence"]) for e in document["entrypoints"]}


def run(tmp_path: Path, files: dict[str, str]) -> dict[str, Any]:
    return graph(tmp_path, files)


def test_pyproject_scripts_gui_scripts_and_entry_points_are_declared(tmp_path: Path) -> None:
    document = run(
        tmp_path,
        {
            "pyproject.toml": (
                '[project]\nname = "x"\n[project.scripts]\ncli = "app.cli:main"\n'
                '[project.gui-scripts]\ngui = "app.gui:run"\n'
                '[project.entry-points."x.plugins"]\np = "app.plug:Plugin"\n'
            ),
            "app/__init__.py": "",
            "app/cli.py": "def main(): ...\n",
            "app/gui.py": "def run(): ...\n",
            "app/plug.py": "class Plugin: ...\n",
        },
    )
    assert entries(document) == {
        ("app/cli.py", "package-metadata", "dichiarato"),
        ("app/gui.py", "package-metadata", "dichiarato"),
        ("app/plug.py", "package-metadata", "dichiarato"),
    }
    assert document["stats"]["unresolved"]["entrypoint_missing"] == 0


def test_poetry_scripts_and_src_layout(tmp_path: Path) -> None:
    document = run(
        tmp_path,
        {
            "pyproject.toml": '[tool.poetry.scripts]\ncli = "pkg.cli:main"\n',
            "src/pkg/__init__.py": "",
            "src/pkg/cli.py": "",
        },
    )
    assert entries(document) == {("src/pkg/cli.py", "package-metadata", "dichiarato")}


def test_a_package_entrypoint_resolves_to_its_init(tmp_path: Path) -> None:
    document = run(
        tmp_path,
        {"pyproject.toml": '[project.scripts]\nc = "pkg:main"\n', "pkg/__init__.py": ""},
    )
    assert entries(document) == {("pkg/__init__.py", "package-metadata", "dichiarato")}


def test_setup_cfg_entry_points(tmp_path: Path) -> None:
    document = run(
        tmp_path,
        {
            "setup.cfg": "[options.entry_points]\nconsole_scripts =\n    a = pkg.a:main\n    b = pkg.b:main\n",
            "pkg/__init__.py": "",
            "pkg/a.py": "",
            "pkg/b.py": "",
        },
    )
    assert {e[0] for e in entries(document)} == {"pkg/a.py", "pkg/b.py"}


def test_a_declared_entrypoint_to_a_missing_file_is_counted_not_invented(tmp_path: Path) -> None:
    document = run(
        tmp_path, {"pyproject.toml": '[project.scripts]\nc = "gone.mod:main"\n', "a.py": ""}
    )
    assert document["entrypoints"] == []
    assert document["stats"]["unresolved"]["entrypoint_missing"] == 1


def test_a_broken_metadata_file_is_counted_as_missing(tmp_path: Path) -> None:
    document = run(tmp_path, {"pyproject.toml": "[project\n", "a.py": ""})
    assert document["stats"]["unresolved"]["entrypoint_missing"] == 1


def test_setup_py_is_code_and_is_never_read(tmp_path: Path) -> None:
    document = run(
        tmp_path,
        {"setup.py": 'entry_points={"console_scripts": ["c = pkg.cli:main"]}\n', "pkg/cli.py": ""},
    )
    assert document["entrypoints"] == []


def test_python_conventions_and_the_main_block(tmp_path: Path) -> None:
    document = run(
        tmp_path,
        {
            "pkg/__main__.py": "",
            "run.py": 'import sys\nif __name__ == "__main__":\n    sys.exit(0)\n',
            "nested.py": 'def f():\n    if __name__ == "__main__":\n        pass\n',
            "manage.py": "",
            "site/wsgi.py": "",
            "site/asgi.py": "",
            "plain.py": "x = 1\n",
        },
    )
    assert entries(document) == {
        ("pkg/__main__.py", "main-module", "dedotto"),
        ("run.py", "main-module", "dedotto"),
        ("manage.py", "convention", "dedotto"),
        ("site/wsgi.py", "convention", "dedotto"),
        ("site/asgi.py", "convention", "dedotto"),
    }


def test_a_main_block_in_a_test_file_is_not_an_entrypoint(tmp_path: Path) -> None:
    document = run(
        tmp_path,
        {
            "tests/test_a.py": 'if __name__ == "__main__":\n    pass\n',
            "conftest.py": 'if __name__ == "__main__":\n    pass\n',
        },
    )
    assert document["entrypoints"] == []


def test_web_application_needs_the_framework_import_and_the_call(tmp_path: Path) -> None:
    document = run(
        tmp_path,
        {
            "web.py": "from flask import Flask\napp = Flask(__name__)\n",
            "api.py": "import fastapi\nserver: object = fastapi.FastAPI()\n",
            "fake.py": "app = Flask(__name__)\n",  # nessun import di flask
            "mention.py": "from flask import Flask\n# Flask( non è una chiamata\nx = 1\n",
            "dj.py": "from django.core.wsgi import get_wsgi_application\napplication = get_wsgi_application()\n",
        },
    )
    assert {e[0] for e in entries(document) if e[1] == "web-application"} == {
        "web.py",
        "api.py",
        "dj.py",
    }


def test_package_json_main_module_bin_and_exports(tmp_path: Path) -> None:
    document = run(
        tmp_path,
        {
            "package.json": (
                '{"name":"x","main":"./lib/index.js","module":"./src/esm.js",'
                '"bin":{"x":"./bin/cli.js"},"exports":{".":{"import":"./src/ex.mjs"}},'
                '"scripts":{"start":"node ./src/never.js"}}'
            ),
            "src/index.ts": "",
            "src/esm.js": "",
            "bin/cli.js": "",
            "src/ex.mjs": "",
            "src/never.js": "",
        },
    )
    declared = {e[0] for e in entries(document) if e[2] == "dichiarato"}
    assert declared == {"src/index.ts", "src/esm.js", "bin/cli.js", "src/ex.mjs"}
    assert "src/never.js" not in {e[0] for e in entries(document)}  # `scripts` non si interpreta


def test_a_build_product_is_looked_up_under_src_and_otherwise_counted(tmp_path: Path) -> None:
    found = run(tmp_path / "a", {"package.json": '{"main":"dist/cli.js"}', "src/cli.ts": ""})
    assert entries(found) == {("src/cli.ts", "package-metadata", "dichiarato")}
    missing = run(tmp_path / "b", {"package.json": '{"main":"dist/cli.js"}', "src/other.ts": ""})
    assert missing["stats"]["unresolved"]["entrypoint_missing"] == 1
    assert not [e for e in entries(missing) if e[1] == "package-metadata"]


def test_package_json_pointing_outside_or_with_wildcards_is_not_followed(tmp_path: Path) -> None:
    document = run(
        tmp_path,
        {
            "package.json": '{"main":"../x.js","exports":{"./*":"./src/*.js"}}',
            "src/a.js": "",
        },
    )
    assert not [e for e in entries(document) if e[1] == "package-metadata"]


def test_js_conventions_and_html_entry(tmp_path: Path) -> None:
    document = run(
        tmp_path,
        {
            "package.json": "{}",
            "index.html": '<script type="module" src="/src/app.ts"></script>'
            '<script src="/src/classic.js"></script>'
            '<script type="module" src="https://cdn.example/x.js"></script>',
            "src/app.ts": "",
            "src/classic.js": "",
            "src/main.tsx": "",
            "src/index.ts": "",
            "src/other.ts": "",
        },
    )
    assert entries(document) == {
        ("src/app.ts", "html-entry", "dedotto"),
        ("src/main.tsx", "convention", "dedotto"),
        ("src/index.ts", "convention", "dedotto"),
    }


def test_an_html_outside_a_package_root_is_ignored(tmp_path: Path) -> None:
    document = run(
        tmp_path,
        {
            "package.json": "{}",
            "docs/index.html": '<script type="module" src="../src/a.ts"></script>',
            "src/a.ts": "",
        },
    )
    assert document["entrypoints"] == []


def test_js_server_frameworks_need_the_import_and_the_call(tmp_path: Path) -> None:
    document = run(
        tmp_path,
        {
            "server.js": "const express = require('express');\nconst app = express();\n",
            "app.ts": "import Fastify from 'fastify';\nconst s = fastify();\n",
            "nest.ts": "import { NestFactory } from '@nestjs/core';\nawait NestFactory.create(M);\n",
            "no-import.js": "const app = express();\n",
            "http.js": "import http from 'node:http';\nhttp.createServer(h);\n",
        },
    )
    assert {e[0] for e in entries(document)} == {"server.js", "app.ts", "nest.ts", "http.js"}


def test_entrypoint_output_is_sorted_unique_and_deterministic(tmp_path: Path) -> None:
    files = {
        "b.py": 'if __name__ == "__main__":\n    pass\n',
        "a.py": 'if __name__ == "__main__":\n    pass\n',
    }
    first = run(tmp_path / "x", files)
    second = run(tmp_path / "y", files)
    assert first["entrypoints"] == second["entrypoints"]
    assert [e["path"] for e in first["entrypoints"]] == ["a.py", "b.py"]
    Graph.model_validate(first)  # rispetta il contratto: ordine e unicità


def test_too_many_entrypoints_fail_instead_of_truncating(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(ep, "MAX_ENTRYPOINTS", 1)
    declared = ep.Declared()
    with pytest.raises(ep.EntrypointLimit):
        ep.to_documents(
            declared, {("a.py", "main-module"): "dedotto", ("b.py", "main-module"): "dedotto"}
        )


def test_declared_confidence_wins_over_inferred_for_the_same_kind() -> None:
    declared = ep.Declared()
    declared.add("a.py", "package-metadata", "dichiarato")
    merged = ep.to_documents(declared, {("a.py", "package-metadata"): "dedotto"})
    assert merged == [{"path": "a.py", "kind": "package-metadata", "confidence": "dichiarato"}]


# --- sul grafo vero e sulle fixture ---------------------------------------------------------


def test_a_real_extraction_feeds_the_reachability(tmp_path: Path) -> None:
    document = run(
        tmp_path,
        {
            "app/__main__.py": "from app import core\n",
            "app/__init__.py": "",
            "app/core.py": "import requests\nfrom app import util\n",
            "app/util.py": "",
            "app/dead.py": "import yaml\n",
        },
    )
    reach = GraphReachability(Graph.model_validate(document))
    assert reach.module("app/util.py").state is ReachState.REACHABLE  # type: ignore[union-attr]
    assert reach.module("app/dead.py").state is ReachState.NOT_REACHABLE  # type: ignore[union-attr]
    assert reach.dependency("pypi", "requests").state is ReachState.REACHABLE
    assert reach.dependency("pypi", "PyYAML").state is ReachState.NOT_REACHABLE


@pytest.mark.parametrize("name", ["graph-python", "graph-js-ts"])
def test_the_f01_fixtures_have_a_consistent_reachability(name: str) -> None:
    root = Path(__file__).resolve().parents[2] / "fixtures/repos" / name
    document = Graph.model_validate(extract(root))
    reach = GraphReachability(document)
    for entrypoint in document.entrypoints:
        assert reach.module(entrypoint.path).state is ReachState.REACHABLE  # type: ignore[union-attr]
    for module in document.modules:
        if module.test:
            assert reach.module(module.path).state is ReachState.TEST_ONLY  # type: ignore[union-attr]
