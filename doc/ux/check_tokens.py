"""Verifica i contrasti di `tokens.json` (U-02, criteri G5 e G6 di `accessibilita.md`).

Uso: python doc/ux/check_tokens.py. Esce con 1 se una coppia è sotto la soglia.
"""

import json
import sys
from pathlib import Path

TEXT, NON_TEXT = 4.5, 3.0
BACKGROUNDS = ("bg", "bg-subtle", "bg-row-selected")
# (primo piano, sfondo, soglia)
PAIRS = (
    [(fg, bg, TEXT) for fg in ("text", "text-muted", "accent", "danger", "status-ok-text")
     for bg in BACKGROUNDS]
    + [("accent-text", "accent", TEXT), ("status-warn-text", "status-warn-bg", TEXT)]
    + [(f"level-{level}-text", f"level-{level}-bg", TEXT)
       for level in ("critico", "alto", "medio", "basso")]
    + [(fg, bg, NON_TEXT) for fg in ("focus", "border-control") for bg in BACKGROUNDS]
)  # fmt: skip


def luminance(color: str) -> float:
    channels = [int(color[i : i + 2], 16) / 255 for i in (1, 3, 5)]
    linear = [c / 12.92 if c <= 0.04045 else ((c + 0.055) / 1.055) ** 2.4 for c in channels]
    return 0.2126 * linear[0] + 0.7152 * linear[1] + 0.0722 * linear[2]


def contrast(first: str, second: str) -> float:
    high, low = sorted((luminance(first), luminance(second)), reverse=True)
    return (high + 0.05) / (low + 0.05)


def main() -> int:
    tokens = json.loads(Path(__file__).with_name("tokens.json").read_text())["color"]
    failed = 0
    for theme, colors in tokens.items():
        for fg, bg, minimum in PAIRS:
            ratio = contrast(colors[fg]["$value"], colors[bg]["$value"])
            if ratio < minimum:
                failed += 1
                print(f"{theme}: {fg} su {bg} = {ratio:.2f}, minimo {minimum}")
    print(f"{len(PAIRS) * len(tokens)} coppie, {failed} sotto soglia")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
