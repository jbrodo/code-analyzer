from importlib import import_module

import pytest


@pytest.mark.parametrize("name", ["ca_core", "ca_plugins", "ca_cli"])
def test_package_is_importable(name: str) -> None:
    assert import_module(name).__name__ == name
