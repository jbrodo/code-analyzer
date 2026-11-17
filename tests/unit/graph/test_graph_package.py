"""G-01: il pacchetto è nel workspace e importabile senza il parser (ADR-0020)."""

import importlib
import sys

import ca_graph


def test_package_imports_without_tree_sitter() -> None:
    assert "tree_sitter" not in sys.modules
    for name in ("deps", "pagerank", "smells"):
        importlib.import_module(f"ca_graph.{name}")
    assert ca_graph.__doc__
