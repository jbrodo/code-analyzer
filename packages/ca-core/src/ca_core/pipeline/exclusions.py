"""Filtro `paths.exclude` (K-08, ADR-0014): autorevole, applicato ai finding normalizzati.

Glob relativi POSIX, sensibili alle maiuscole: `*` e `?` dentro un segmento, `**` per più
segmenti; non esistono classi `[...]` (limite noto). Un glob vale per un percorso se ne
corrisponde il percorso intero o uno dei suoi antenati: `dist` esclude anche `dist/a.js`.
I finding senza percorso (dipendenze, `health`) non si escludono mai.

Predefiniti e deroghe sono dati: l'esclusione di `.git` non si applica a gitleaks, che legge la
storia.
"""

import re
from collections.abc import Mapping, Sequence
from functools import lru_cache

from ca_core.models.finding import Finding

DEFAULT_EXCLUDES: tuple[str, ...] = (
    "**/node_modules",
    "**/.venv",
    "**/dist",
    "**/.git",
    "**/code-analyzer.report.json",  # artefatti di output di `scan` (ADR-0010)
    "**/code-analyzer.sarif",
)
# Predefiniti che non valgono per un tool; i glob di `paths.exclude` valgono sempre.
TOOL_EXEMPTIONS: Mapping[str, tuple[str, ...]] = {"gitleaks": ("**/.git",)}


@lru_cache(maxsize=256)
def _compile(pattern: str) -> re.Pattern[str]:
    segments = pattern.rstrip("/").split("/")
    parts: list[str] = []
    for i, segment in enumerate(segments):
        last = i == len(segments) - 1
        if segment == "**":
            parts.append(".*" if last else "(?:[^/]+/)*")
            continue
        body = "".join(
            "[^/]*" if c == "*" else "[^/]" if c == "?" else re.escape(c) for c in segment
        )
        parts.append(body if last else body + "/")
    return re.compile("".join(parts))


def is_excluded(path: str, patterns: Sequence[str]) -> bool:
    ancestors = path.split("/")
    candidates = ["/".join(ancestors[: i + 1]) for i in range(len(ancestors))]
    return any(_compile(p).fullmatch(c) for p in patterns for c in candidates)


def effective_exclusions(user_patterns: Sequence[str]) -> list[str]:
    """Glob effettivi per il report: predefiniti, poi `paths.exclude`, senza duplicati."""
    return list(dict.fromkeys([*DEFAULT_EXCLUDES, *user_patterns]))


def coverage_exclusions(user_patterns: Sequence[str]) -> list[str]:
    """Esclusioni per il controllo di copertura del workspace (ADR-0004, A-02).

    Predefiniti senza quelli esentati per almeno un tool (`.git`: gitleaks legge la storia e
    ciò che non può leggere conta), poi `paths.exclude`.
    """
    exempt = {p for patterns in TOOL_EXEMPTIONS.values() for p in patterns}
    return list(dict.fromkeys([*(p for p in DEFAULT_EXCLUDES if p not in exempt), *user_patterns]))


def _patterns_for(tools: Sequence[str], user_patterns: Sequence[str]) -> list[str]:
    # conservativo: se un tool del finding è esentato, il predefinito non si applica
    exempt = {p for t in tools for p in TOOL_EXEMPTIONS.get(t, ())}
    return [p for p in DEFAULT_EXCLUDES if p not in exempt] + list(user_patterns)


def apply_exclusions(findings: Sequence[Finding], user_patterns: Sequence[str]) -> list[Finding]:
    """Finding che restano; l'ordine non cambia."""
    return [
        f
        for f in findings
        if f.location.path is None
        or not is_excluded(f.location.path, _patterns_for(f.tools, user_patterns))
    ]
