"""U-02: i token di `doc/ux/tokens.json` rispettano i contrasti dichiarati in `accessibilita.md`."""

import importlib.util
from pathlib import Path

CHECK = Path(__file__).resolve().parents[2] / "doc/ux/check_tokens.py"


def test_every_token_pair_meets_its_contrast_threshold() -> None:
    spec = importlib.util.spec_from_file_location("check_tokens", CHECK)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    assert module.main() == 0
    assert module.contrast("#000000", "#ffffff") == 21.0
