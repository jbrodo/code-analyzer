"""Ogni server di prova in container ha l'immagine fissata per digest (`container_images`).

Una prova che avvia un container con un tag mobile cambia comportamento senza un commit. La regola
è la stessa dei manifest dei plugin e del compose: niente immagine senza `@sha256:`.
"""

import ast
import importlib.util
import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
TESTS = ROOT / "tests"
PINNED = re.compile(r"^[a-z0-9./_-]+:[A-Za-z0-9._-]+@sha256:[0-9a-f]{64}$")


def _registry() -> dict[str, str]:
    spec = importlib.util.spec_from_file_location(
        "container_images", TESTS / "integration/container_images.py"
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return {k: v for k, v in vars(module).items() if k.isupper() and isinstance(v, str)}


REGISTRY = _registry()


@pytest.mark.parametrize("name", sorted(n for n in REGISTRY if n != "ROOT"))
def test_every_registered_image_is_pinned_by_digest(name: str) -> None:
    assert PINNED.fullmatch(REGISTRY[name]), f"{name}: {REGISTRY[name]}"


def _container_calls() -> list[tuple[str, int, ast.expr]]:
    found = []
    for path in TESTS.rglob("*.py"):
        tree = ast.parse(path.read_text(), filename=str(path))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call) or not node.args:
                continue
            func = node.func
            name = func.id if isinstance(func, ast.Name) else getattr(func, "attr", "")
            if name.endswith("Container") and name[0].isupper():
                found.append((str(path.relative_to(ROOT)), node.lineno, node.args[0]))
    return found


def test_containers_take_their_image_from_the_registry_or_a_pinned_literal() -> None:
    calls = _container_calls()
    assert calls, "nessun container trovato: la guardia non guarda più nulla"
    for where, line, image in calls:
        if isinstance(image, ast.Constant) and isinstance(image.value, str):
            assert PINNED.fullmatch(image.value), f"{where}:{line}: {image.value}"
        else:
            assert isinstance(image, ast.Name) and image.id in REGISTRY, (
                f"{where}:{line}: l'immagine viene da `container_images`"
            )
