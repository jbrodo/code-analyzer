"""Aiuti per i test dell'estrattore: workspace in cartelle temporanee e lettura del grafo."""

from pathlib import Path
from typing import Any

from ca_graph.treesitter.extract import extract_graph


def build(root: Path, files: dict[str, str]) -> Path:
    for rel, text in files.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    return root


def graph(root: Path, files: dict[str, str]) -> dict[str, Any]:
    return extract_graph(str(build(root, files)))


def edges(document: dict[str, Any]) -> dict[tuple[str, str], dict[str, Any]]:
    """Archi per (origine, destinazione)."""
    return {(e["source"], e["target"]): e for e in document["edges"]}


def modules(document: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {m["path"]: m for m in document["modules"]}


def extract(root: Path) -> dict[str, Any]:
    """Grafo di un repository già scritto su disco (le fixture)."""
    return extract_graph(str(root))
