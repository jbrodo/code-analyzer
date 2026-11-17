"""G-01: il pacchetto è nel workspace e importabile senza il parser (ADR-0020)."""

import subprocess
import sys


def test_package_imports_without_tree_sitter() -> None:
    """In un processo a parte: altri test importano `tree_sitter` nella stessa sessione."""
    code = (
        "import sys, importlib, ca_graph\n"
        "[importlib.import_module(f'ca_graph.{n}') for n in ('deps', 'pagerank', 'smells')]\n"
        "assert 'tree_sitter' not in sys.modules and 'ca_graph.treesitter' not in sys.modules\n"
        "assert ca_graph.__doc__\n"
    )
    done = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, check=False)
    assert done.returncode == 0, done.stderr
