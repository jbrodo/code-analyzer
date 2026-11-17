"""Entrypoint del workspace (G-12, ADR-0022). Solo la libreria standard, nessuna esecuzione.

Dichiarati dai metadati del pacchetto, letti **come dati**: `pyproject.toml`, `setup.cfg`,
`package.json` (`main`, `module`, `bin`, `exports`). `setup.py` è codice e non si legge; il campo
`scripts` di `package.json` contiene comandi di shell e non si interpreta. Dedotti da convenzioni:
`__main__.py`, il blocco `if __name__ == "__main__"`, `manage.py`, `wsgi.py`, `asgi.py`, moduli che
costruiscono l'applicazione di un framework web noto, `src/main.*` e `src/index.*`, il modulo
caricato da un `index.html`. Un file di test non è un entrypoint.

Un entrypoint dichiarato che punta a un file assente (per esempio un prodotto della build) si cerca
sotto `src/` con lo stesso nome; se non si trova si **conta** (`entrypoint_missing`) e non produce
un entrypoint: il grafo risulta incompleto, e la raggiungibilità resta `ignota`. Lo stesso vale per
un file di metadati che non si legge. L'elenco dei framework è un dato di questa immagine,
versionato con essa (`FRAMEWORKS_VERSION`).
"""

import configparser
import json
import posixpath
import re
import tomllib
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from html.parser import HTMLParser
from typing import Any

from ca_graph.treesitter import files as fs
from ca_graph.treesitter.refs import FileImports

FRAMEWORKS_VERSION = 1
MAX_ENTRYPOINTS = (
    10_000  # come `graph`: oltre, si fallisce (togliere entrypoint alzerebbe i falsi non raggiunti)
)
DECLARED, INFERRED = "dichiarato", "dedotto"
PACKAGE_METADATA, MAIN_MODULE, WEB_APP, HTML_ENTRY, CONVENTION = (
    "package-metadata",
    "main-module",
    "web-application",
    "html-entry",
    "convention",
)
PY_CONVENTION_NAMES = frozenset({"manage.py", "wsgi.py", "asgi.py"})
JS_SOURCE_SUFFIXES = (".ts", ".tsx", ".mts", ".cts", ".js", ".jsx", ".mjs", ".cjs")
BUILD_DIRS = frozenset({"dist", "build", "lib", "out"})

_MAIN_BLOCK = re.compile(rb"^if[ \t]+__name__[ \t]*==[ \t]*['\"]__main__['\"][ \t]*:", re.MULTILINE)
# chiamata che costruisce l'applicazione -> modulo che deve essere importato dal file
PY_APP_CALLS: dict[str, str] = {
    "Flask": "flask",
    "FastAPI": "fastapi",
    "Starlette": "starlette",
    "Quart": "quart",
    "Sanic": "sanic",
    "Bottle": "bottle",
    "get_wsgi_application": "django",
    "get_asgi_application": "django",
}
_PY_APP = re.compile(
    rb"^[ \t]*(?:[\w.]+[ \t]*(?::[^=\n]{1,100})?=[ \t]*)?(?:[\w.]+\.)?("
    + b"|".join(n.encode() for n in PY_APP_CALLS)
    + rb")[ \t]*\(",
    re.MULTILINE,
)
_PY_AIOHTTP = re.compile(rb"\bweb\.Application[ \t]*\(")
JS_APP_PATTERNS: tuple[tuple[re.Pattern[bytes], tuple[str, ...]], ...] = (
    (re.compile(rb"\bexpress[ \t]*\("), ("express",)),
    (re.compile(rb"\bfastify[ \t]*\("), ("fastify",)),
    (re.compile(rb"\bnew[ \t]+Koa[ \t]*\("), ("koa",)),
    (re.compile(rb"\bNestFactory[ \t]*\.[ \t]*create[ \t]*\("), ("@nestjs/core",)),
    (re.compile(rb"\bcreateServer[ \t]*\("), ("http", "https", "node:http", "node:https")),
)


class EntrypointLimit(ValueError):
    """Troppi entrypoint: l'estrazione fallisce, non si tronca."""


def _imports_any(imports: FileImports, modules: Iterable[str]) -> bool:
    wanted = tuple(modules)
    for ref in imports.refs:
        spec = ref.spec.lstrip(".")
        if any(spec == m or spec.startswith(m + ".") or spec.startswith(m + "/") for m in wanted):
            return True
    return False


def inspect_source(
    path: str, language: str, data: bytes | None, imports: FileImports
) -> list[tuple[str, str]]:
    """Entrypoint dedotti da un file sorgente: lista di (kind, confidence). Mai per i test."""
    if data is None or fs.is_test_path(path):
        return []
    name = posixpath.basename(path)
    found: list[tuple[str, str]] = []
    if language == "python":
        if name == "__main__.py" or _MAIN_BLOCK.search(data):
            found.append((MAIN_MODULE, INFERRED))
        if name in PY_CONVENTION_NAMES:
            found.append((CONVENTION, INFERRED))
        for match in _PY_APP.finditer(data):
            if _imports_any(imports, [PY_APP_CALLS[match.group(1).decode()]]):
                found.append((WEB_APP, INFERRED))
                break
        else:
            if _PY_AIOHTTP.search(data) and _imports_any(imports, ["aiohttp"]):
                found.append((WEB_APP, INFERRED))
        return found
    for pattern, modules in JS_APP_PATTERNS:
        if pattern.search(data) and _imports_any(imports, modules):
            found.append((WEB_APP, INFERRED))
            break
    return found


# --- metadati dichiarati -------------------------------------------------------------------


@dataclass
class Declared:
    entries: dict[tuple[str, str], str] = field(default_factory=dict)  # (path, kind) -> confidence
    missing: int = 0

    def add(self, path: str, kind: str, confidence: str) -> None:
        key = (path, kind)
        if self.entries.get(key) != DECLARED:
            self.entries[key] = confidence


def _join(base: str, rel: str) -> str:
    return posixpath.normpath(posixpath.join(base, rel)) if base else posixpath.normpath(rel)


def _python_module(base: str, dotted: str, sources: frozenset[str]) -> str | None:
    parts = dotted.strip().split(".")
    if not all(p.isidentifier() for p in parts):
        return None
    stem = "/".join(parts)
    for root in (base, _join(base, "src")):
        for candidate in (f"{stem}.py", f"{stem}/__init__.py"):
            path = _join(root, candidate)
            if path in sources:
                return path
    return None


def _python_target(value: object) -> str | None:
    """`pkg.mod:func [extras]` -> `pkg.mod`."""
    if not isinstance(value, str) or ":" not in value:
        return None
    return value.partition(":")[0].strip() or None


def _from_pyproject(base: str, data: bytes, sources: frozenset[str], out: Declared) -> None:
    try:
        document = tomllib.loads(data.decode("utf-8"))
    except (ValueError, UnicodeDecodeError, RecursionError):
        out.missing += 1
        return
    values: list[object] = []
    project = document.get("project")
    if isinstance(project, dict):
        for key in ("scripts", "gui-scripts"):
            table = project.get(key)
            if isinstance(table, dict):
                values += list(table.values())
        groups = project.get("entry-points")
        if isinstance(groups, dict):
            for table in groups.values():
                if isinstance(table, dict):
                    values += list(table.values())
    poetry = (
        document.get("tool", {}).get("poetry") if isinstance(document.get("tool"), dict) else None
    )
    if isinstance(poetry, dict) and isinstance(poetry.get("scripts"), dict):
        values += list(poetry["scripts"].values())
    for value in values:
        module = _python_target(value)
        path = _python_module(base, module, sources) if module else None
        if path is None:
            out.missing += 1
        else:
            out.add(path, PACKAGE_METADATA, DECLARED)


def _from_setup_cfg(base: str, data: bytes, sources: frozenset[str], out: Declared) -> None:
    parser = configparser.ConfigParser(interpolation=None, strict=False)
    try:
        parser.read_string(data.decode("utf-8"))
    except (configparser.Error, UnicodeDecodeError):
        out.missing += 1
        return
    if not parser.has_section("options.entry_points"):
        return
    for _, block in parser.items("options.entry_points"):
        for line in block.splitlines():
            _, _, value = line.partition("=")
            if not value.strip():
                continue
            module = _python_target(value.strip())
            path = _python_module(base, module, sources) if module else None
            if path is None:
                out.missing += 1
            else:
                out.add(path, PACKAGE_METADATA, DECLARED)


def _strings(node: Any, depth: int = 0) -> list[str]:
    if depth > 8:
        return []
    if isinstance(node, str):
        return [node]
    if isinstance(node, dict):
        return [s for v in node.values() for s in _strings(v, depth + 1)]
    if isinstance(node, list):
        return [s for v in node for s in _strings(v, depth + 1)]
    return []


def _js_target(base: str, value: str, sources: frozenset[str]) -> str | None:
    """Il file sorgente cui punta un campo di `package.json`; cerca sotto `src/` se è un prodotto
    della build."""
    if "*" in value or value.startswith(("http:", "https:", "#")):
        return None
    rel = posixpath.normpath(value.removeprefix("./"))
    if rel.startswith(("..", "/")):
        return None
    stem, suffix = posixpath.splitext(rel)
    first, _, rest = rel.partition("/")
    options: list[str] = [rel] if suffix in JS_SOURCE_SUFFIXES else []
    stems = [stem] if suffix else [rel]
    if first in BUILD_DIRS and rest:
        stems.append("src/" + posixpath.splitext(rest)[0])
    stems.append("src/" + stem)
    for s in stems:
        options += [s + ext for ext in JS_SOURCE_SUFFIXES]
        if not suffix:
            options += [f"{s}/index{ext}" for ext in JS_SOURCE_SUFFIXES]
    for option in options:
        path = _join(base, option)
        if path in sources:
            return path
    return None


def _from_package_json(base: str, data: bytes, sources: frozenset[str], out: Declared) -> None:
    try:
        document = json.loads(data.decode("utf-8"))
    except (ValueError, UnicodeDecodeError, RecursionError):
        out.missing += 1
        return
    if not isinstance(document, dict):
        out.missing += 1
        return
    values: list[str] = []
    for key in ("main", "module"):
        if isinstance(document.get(key), str):
            values.append(document[key])
    values += _strings(document.get("bin"))
    values += [s for s in _strings(document.get("exports")) if s.startswith("./")]
    for value in dict.fromkeys(values):
        path = _js_target(base, value, sources)
        if path is None:
            out.missing += 1
        else:
            out.add(path, PACKAGE_METADATA, DECLARED)


class _ModuleScripts(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=False)
        self.sources: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag != "script":
            return
        values = dict(attrs)
        if values.get("type") == "module" and values.get("src"):
            self.sources.append(values["src"] or "")


def _from_html(base: str, data: bytes, sources: frozenset[str], out: Declared) -> None:
    parser = _ModuleScripts()
    try:
        parser.feed(data.decode("utf-8", errors="replace"))
        parser.close()
    except (ValueError, RecursionError):
        return
    for src in parser.sources[:50]:
        src = src.split("?", 1)[0].split("#", 1)[0]
        if "://" in src or src.startswith("//"):
            continue
        path = _join(base, src.removeprefix("/"))
        if path in sources and not fs.is_test_path(path):
            out.add(path, HTML_ENTRY, INFERRED)


def declared_entrypoints(
    configs: list[str],
    sources: frozenset[str],
    read: Callable[[str], bytes | None],
) -> Declared:
    """Entrypoint dichiarati dai metadati e dedotti da `src/main.*`, `src/index.*`, `index.html`."""
    out = Declared()
    roots: list[str] = []
    for config in configs:
        base, name = posixpath.split(config)
        if name not in ("pyproject.toml", "setup.cfg", "package.json"):
            continue  # `index.html` si legge sotto, solo se sta nella radice di un pacchetto
        data = read(config)
        if data is None:
            out.missing += 1
            continue
        if name == "pyproject.toml":
            _from_pyproject(base, data, sources, out)
        elif name == "setup.cfg":
            _from_setup_cfg(base, data, sources, out)
        else:
            roots.append(base)
            _from_package_json(base, data, sources, out)
    for root in roots:
        for stem in ("main", "index"):
            for ext in JS_SOURCE_SUFFIXES:
                path = _join(root, f"src/{stem}{ext}")
                if path in sources and not fs.is_test_path(path):
                    out.add(path, CONVENTION, INFERRED)
    for config in configs:
        base, name = posixpath.split(config)
        if name == "index.html" and base in roots:
            data = read(config)
            if data is not None:
                _from_html(base, data, sources, out)
    return out


def to_documents(declared: Declared, inferred: dict[tuple[str, str], str]) -> list[dict[str, str]]:
    merged = dict(inferred)
    for key, confidence in declared.entries.items():
        if merged.get(key) != DECLARED:
            merged[key] = confidence
    if len(merged) > MAX_ENTRYPOINTS:
        raise EntrypointLimit("troppi entrypoint")
    return [
        {"path": path, "kind": kind, "confidence": confidence}
        for (path, kind), confidence in sorted(merged.items())
    ]
