"""Raccoglie i file di licenza delle dipendenze Python installate in /licenses/deps (I-03).

Uno script a parte e non un documento in linea nel Dockerfile: hadolint non legge le heredoc.
"""

import pathlib
import shutil

OWN = {"pip", "ca_core", "ca_api"}  # il progetto ha la sua licenza in /licenses/code-analyzer
site = pathlib.Path("/usr/local/lib/python3.14/site-packages")
for info in sorted(site.glob("*.dist-info")):
    name = info.name.split("-")[0]
    if name in OWN:
        continue
    found = [
        p
        for p in info.rglob("*")
        if p.is_file() and p.name.upper().startswith(("LICENSE", "LICENCE", "COPYING", "NOTICE"))
    ]
    for path in found:
        target = pathlib.Path("/licenses/deps", name)
        target.mkdir(parents=True, exist_ok=True)
        shutil.copy(path, target / path.name)
