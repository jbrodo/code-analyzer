"""G-02: estrattore Python, con i casi di V-07 (pacchetti impliciti, import calcolati)."""

from pathlib import Path

import pytest
from graph_builders import edges, graph, modules

pytest.importorskip("tree_sitter")

from ca_graph.treesitter import python as py  # noqa: E402
from ca_graph.treesitter.refs import ImportRef  # noqa: E402


def refs(source: str) -> list[ImportRef]:
    return py.extract_imports(source.encode()).refs


# --- estrazione --------------------------------------------------------------------------------


def test_import_forms() -> None:
    found = refs(
        "import a.b\nimport c as d, e\nfrom f import g, h as i\nfrom . import j\n"
        "from ..k.l import m\nfrom n import *\n"
    )
    assert [(r.spec, r.names) for r in found] == [
        ("a.b", ()),
        ("c", ()),
        ("e", ()),
        ("f", ("g", "h")),
        (".", ("j",)),
        ("..k.l", ("m",)),
        ("n", ()),  # `*` non è un nome: resta l'arco verso il modulo
    ]


def test_type_checking_block_marks_only_its_own_imports() -> None:
    found = refs(
        "import a\nif TYPE_CHECKING:\n    import b\n    from c import d\nelse:\n    import e\n"
        "import typing\nif typing.TYPE_CHECKING:\n    import f\n"
    )
    assert {r.spec: r.type_only for r in found} == {
        "a": False, "b": True, "c": True, "e": False, "typing": False, "f": True,
    }  # fmt: skip


def test_imports_inside_functions_and_classes_are_found() -> None:
    found = refs(
        "def f():\n    import inner\nclass C:\n    def m(self):\n        from x import y\n"
    )
    assert [r.spec for r in found] == ["inner", "x"]


def test_dynamic_imports_literal_become_dynamic_and_computed_are_counted() -> None:
    result = py.extract_imports(
        b'importlib.import_module("m")\nimport_module("n")\n__import__("o")\n'
        b'importlib.import_module(name)\nimportlib.import_module(f"p{x}")\n'
        b'importlib.import_module("a" + b)\nimportlib.import_module(b"c")\n'
    )
    assert [(r.spec, r.dynamic) for r in result.refs] == [("m", True), ("n", True), ("o", True)]
    assert result.computed == 4


def test_syntax_error_keeps_the_imports_found_and_marks_the_file_partial() -> None:
    result = py.extract_imports(b"import good\ndef broken(:\n    pass\nimport also_good\n")
    assert result.partial and "good" in {r.spec for r in result.refs}


def test_very_deep_nesting_does_not_crash_the_extractor() -> None:
    """S2-M2: visita iterativa, nessun `RecursionError`."""
    source = "x = " + "(" * 20_000 + "1" + ")" * 20_000 + "\nimport after\n"
    result = py.extract_imports(source.encode())
    assert isinstance(result.partial, bool)
    deep_if = (
        "\n".join(" " * i + "if x:" for i in range(0, 300)) + "\n" + " " * 300 + "import deep\n"
    )
    assert "deep" in {r.spec for r in py.extract_imports(deep_if.encode()).refs}


def test_depth_limit_marks_the_file_partial(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(py, "MAX_DEPTH", 5)
    assert py.extract_imports(b"x = ((((((((((1))))))))))\n").partial


# --- risoluzione sul workspace ------------------------------------------------------------------


def test_absolute_relative_and_package_imports(tmp_path: Path) -> None:
    doc = graph(
        tmp_path,
        {
            "app/__init__.py": "",
            "app/main.py": (
                "from . import util\nfrom .sub import deep\nimport app.models\n"
                "from app import models as m2\n"
            ),
            "app/util.py": "",
            "app/models.py": "",
            "app/sub/__init__.py": "",
            "app/sub/deep.py": "from .. import util\n",
        },
    )
    e = edges(doc)
    assert e[("app/main.py", "app/util.py")]["confidence"] == "dichiarato"
    assert ("app/main.py", "app/sub/deep.py") in e
    assert e[("app/main.py", "app/models.py")]["imports"] == 2  # due import, un arco
    assert ("app/sub/deep.py", "app/util.py") in e
    assert not any(external for _, external, _ in [(0, x["external"], 0) for x in doc["edges"]])


def test_from_package_import_module_points_at_the_submodule_when_it_exists(tmp_path: Path) -> None:
    doc = graph(
        tmp_path,
        {
            "pkg/__init__.py": "",
            "pkg/mod.py": "",
            "use.py": "from pkg import mod, Cls\nfrom pkg import Cls as c\n",
        },
    )
    e = edges(doc)
    assert ("use.py", "pkg/mod.py") in e and ("use.py", "pkg/__init__.py") in e


def test_directories_without_init_are_packages_with_inferred_confidence(tmp_path: Path) -> None:
    """V-07: 4 e 10 cartelle senza `__init__.py` sui pilota."""
    doc = graph(
        tmp_path,
        {
            "implicit/mod.py": "",
            "implicit/sub/leaf.py": "",
            "use.py": "from implicit import mod\nimport implicit.sub.leaf\n",
        },
    )
    e = edges(doc)
    assert e[("use.py", "implicit/mod.py")]["confidence"] == "dedotto"
    assert e[("use.py", "implicit/sub/leaf.py")]["confidence"] == "dedotto"


def test_a_namespace_package_import_alone_gives_no_edge_and_no_external(tmp_path: Path) -> None:
    doc = graph(tmp_path, {"ns/mod.py": "", "use.py": "import ns\n"})
    assert doc["edges"] == [] and doc["externals"] == []


def test_src_layout_and_project_roots_are_source_roots(tmp_path: Path) -> None:
    doc = graph(
        tmp_path,
        {
            "src/lib/__init__.py": "",
            "src/lib/core.py": "",
            "tools/app/pyproject.toml": "",
            "tools/app/pkg/__init__.py": "",
            "tools/app/pkg/mod.py": "",
            "run.py": "import lib.core\n",
            "tools/app/main.py": "import pkg.mod\n",
        },
    )
    e = edges(doc)
    assert e[("run.py", "src/lib/core.py")]["confidence"] == "dedotto"
    assert e[("tools/app/main.py", "tools/app/pkg/mod.py")]["confidence"] == "dedotto"


def test_nearest_source_root_wins_with_several_matches(tmp_path: Path) -> None:
    doc = graph(
        tmp_path,
        {
            "common/__init__.py": "",
            "common/x.py": "",
            "svc/pyproject.toml": "",
            "svc/common/__init__.py": "",
            "svc/common/x.py": "",
            "svc/main.py": "import common.x\n",
        },
    )
    assert ("svc/main.py", "svc/common/x.py") in edges(doc)
    assert ("svc/main.py", "common/x.py") not in edges(doc)


def test_stdlib_is_not_a_node_and_third_party_packages_are_external_by_top_level_name(
    tmp_path: Path,
) -> None:
    doc = graph(
        tmp_path,
        {"a.py": "import os, json.decoder\nimport requests.adapters\nfrom yaml import safe_load\n"},
    )
    assert doc["externals"] == [
        {"name": "requests", "ecosystem": "pypi"},
        {"name": "yaml", "ecosystem": "pypi"},
    ]
    assert {e["target"] for e in doc["edges"]} == {"requests", "yaml"} and all(
        e["external"] for e in doc["edges"]
    )


def test_relative_import_that_leaves_the_workspace_is_missing_and_never_invented(
    tmp_path: Path,
) -> None:
    doc = graph(tmp_path, {"a.py": "from .. import x\nfrom .nothing import y\n"})
    assert doc["edges"] == [] and doc["stats"]["unresolved"]["missing"] == 2


def test_self_import_and_type_only_dynamic_flags(tmp_path: Path) -> None:
    doc = graph(
        tmp_path,
        {
            "a.py": (
                "import a\nif TYPE_CHECKING:\n    import b\n"
                "importlib.import_module('c')\nimport b\n"
            ),
            "b.py": "",
            "c.py": "",
        },
    )
    e = edges(doc)
    assert ("a.py", "a.py") not in e
    assert e[("a.py", "b.py")]["type_only"] is False and e[("a.py", "b.py")]["imports"] == 2
    assert (
        e[("a.py", "c.py")]["dynamic"] is True and e[("a.py", "c.py")]["confidence"] == "dichiarato"
    )


def test_computed_imports_are_counted_in_the_stats(tmp_path: Path) -> None:
    doc = graph(
        tmp_path, {"a.py": "importlib.import_module(name)\nimportlib.import_module(f'x{y}')\n"}
    )
    assert doc["stats"]["unresolved"]["computed"] == 2 and doc["edges"] == []


def test_test_files_are_flagged(tmp_path: Path) -> None:
    doc = graph(
        tmp_path, {"app/a.py": "", "tests/test_a.py": "", "app/a_test.py": "", "conftest.py": ""}
    )
    flags = {p: m["test"] for p, m in modules(doc).items()}
    assert flags == {
        "app/a.py": False,
        "tests/test_a.py": True,
        "app/a_test.py": True,
        "conftest.py": True,
    }
