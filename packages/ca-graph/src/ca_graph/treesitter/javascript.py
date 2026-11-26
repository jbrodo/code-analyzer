"""Estrattore JS, TS e TSX (G-03, ADR-0020): import, `export … from`, `require`, `import()`.

Mai inventare: `require` e `import()` con argomento non letterale non producono archi e si
contano. Gli alias di `tsconfig.json` (`paths`, `baseUrl`, `extends`) e i nomi dei `package.json`
del workspace si leggono come **dati non fidati** (V-07: senza gli alias più della metà degli
import interni di un pilota risulta esterna): limiti di dimensione, `extends` solo verso file
dentro il workspace e per un numero limitato di passi, nessun alias che esca dal workspace.
"""

import json
import posixpath
import re
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from typing import Any

import tree_sitter as ts
import tree_sitter_javascript as tsj
import tree_sitter_typescript as tst

from ca_graph.treesitter.refs import FileImports, ImportRef

LANGUAGES = {
    "javascript": ts.Language(tsj.language()),
    "typescript": ts.Language(tst.language_typescript()),
    "tsx": ts.Language(tst.language_tsx()),
}
MAX_DEPTH = 5_000
MAX_EXTENDS = 8
EXTENSIONS = (".ts", ".tsx", ".mts", ".cts", ".js", ".jsx", ".mjs", ".cjs")
# `./a.js` in un file TypeScript indica `./a.ts`: la convenzione di TypeScript per ESM.
SWAP = {
    ".js": (".ts", ".tsx"),
    ".jsx": (".tsx",),
    ".mjs": (".mts",),
    ".cjs": (".cts",),
}
_BUILTIN_NAMES = (
    "assert async_hooks buffer child_process cluster console constants crypto dgram "
    "diagnostics_channel dns domain events fs http http2 https inspector module net os path "
    "perf_hooks process punycode querystring readline repl stream string_decoder sys timers tls "
    "trace_events tty url util v8 vm wasi worker_threads zlib"
)
BUILTINS = frozenset(_BUILTIN_NAMES.split())
NPM_NAME = re.compile(r"^(?:@[A-Za-z0-9._~-]+/)?[A-Za-z0-9_][A-Za-z0-9._~-]*$")
DECLARED, INFERRED = "dichiarato", "dedotto"


def _text(node: ts.Node) -> str:
    return (node.text or b"").decode("utf-8", "replace")


def _literal(node: ts.Node | None) -> str | None:
    """Testo di una stringa o di un template senza sostituzioni; `None` altrimenti."""
    if node is None:
        return None
    if node.type == "string":
        kinds = {c.type for c in node.children}
        if kinds - {'"', "'", "string_fragment"}:
            return None
        return "".join(_text(c) for c in node.children if c.type == "string_fragment")
    if node.type == "template_string":
        if any(c.type == "template_substitution" for c in node.children):
            return None
        return "".join(_text(c) for c in node.children if c.type == "string_fragment")
    return None


def _first_argument(node: ts.Node) -> ts.Node | None:
    arguments = node.child_by_field_name("arguments")
    if arguments is None:
        return None
    return next((c for c in arguments.named_children if c.type != "comment"), None)


def extract_imports(source: bytes, language: str) -> FileImports:
    parser = ts.Parser(LANGUAGES[language])
    tree = parser.parse(source)
    result = FileImports(refs=[], partial=tree.root_node.has_error)
    stack: list[tuple[ts.Node, int]] = [(tree.root_node, 0)]
    while stack:
        node, depth = stack.pop()
        if depth > MAX_DEPTH:
            result.partial = True
            continue
        kind = node.type
        if kind in ("import_statement", "export_statement"):
            type_only = any(c.type == "type" for c in node.children)
            spec = _literal(node.child_by_field_name("source"))
            if spec is None:
                clause = next((c for c in node.children if c.type == "import_require_clause"), None)
                spec = _literal(
                    next(
                        (c for c in (clause.children if clause else []) if c.type == "string"), None
                    )
                )
            if spec is not None:
                result.refs.append(ImportRef(spec=spec, type_only=type_only))
                continue
            if kind == "import_statement":
                continue  # nessuna sorgente leggibile: l'errore è già in `partial`
        elif kind == "call_expression":
            function = node.child_by_field_name("function")
            if function is not None and (
                function.type == "import"
                or (function.type == "identifier" and _text(function) == "require")
            ):
                spec = _literal(_first_argument(node))
                if spec is None:
                    result.computed += 1
                else:
                    result.refs.append(ImportRef(spec=spec, dynamic=function.type == "import"))
        stack.extend((child, depth + 1) for child in reversed(node.children))
    return result


# --- configurazioni (dati non fidati) ------------------------------------------------------------


def parse_json_lenient(raw: bytes) -> Any:
    """JSON con commenti e virgole finali, come `tsconfig.json`. `None` se non si legge."""
    try:
        text = raw.decode("utf-8-sig")
    except UnicodeDecodeError:
        return None
    out: list[str] = []
    i, n, in_string = 0, len(text), False
    while i < n:
        c = text[i]
        if in_string:
            out.append(c)
            if c == "\\" and i + 1 < n:
                out.append(text[i + 1])
                i += 1
            elif c == '"':
                in_string = False
        elif c == '"':
            in_string = True
            out.append(c)
        elif text.startswith("//", i):
            i = text.find("\n", i)
            if i == -1:
                break
            continue
        elif text.startswith("/*", i):
            end = text.find("*/", i + 2)
            if end == -1:
                return None
            i = end + 2
            continue
        else:
            out.append(c)
        i += 1
    cleaned = re.sub(r",(\s*[}\]])", r"\1", "".join(out))
    try:
        return json.loads(cleaned)
    except (ValueError, RecursionError):
        return None


@dataclass
class TsConfig:
    base_url: str | None = None  # cartella del workspace, già normalizzata
    paths: dict[str, list[str]] = field(default_factory=dict)
    paths_dir: str = ""  # cartella a cui i `paths` sono relativi se manca `baseUrl`


@dataclass
class Outcome:
    kind: str  # files | external | builtin | missing | outside
    files: list[tuple[str, str]] = field(default_factory=list)
    name: str = ""


def _inside(path: str) -> bool:
    return not (path == ".." or path.startswith("../") or posixpath.isabs(path))


def _join(base: str, relative: str) -> str:
    return (
        posixpath.normpath(posixpath.join(base, relative)) if base else posixpath.normpath(relative)
    )


class Resolver:
    """Risolve gli import di JS e TS sul workspace, con alias e pacchetti del workspace."""

    def __init__(
        self,
        files: Iterable[str],
        configs: Iterable[str],
        read_config: Callable[[str], bytes | None],
    ) -> None:
        self.files = set(files)
        self.configs = set(configs)
        self._read = read_config
        self._tsconfigs: dict[str, TsConfig] = {}
        self.config_extends = 0  # `extends` verso un pacchetto o non seguibile: contato
        self.packages = self._workspace_packages()

    # --- tsconfig ---------------------------------------------------------------------------

    def _load(self, path: str, chain: tuple[str, ...]) -> TsConfig:
        if path in self._tsconfigs:
            return self._tsconfigs[path]
        document = parse_json_lenient(self._read(path) or b"")
        config = TsConfig()
        directory = posixpath.dirname(path)
        if isinstance(document, dict):
            parent = self._parent(document.get("extends"), directory, chain + (path,))
            if parent is not None:
                config = TsConfig(parent.base_url, dict(parent.paths), parent.paths_dir)
            options = document.get("compilerOptions")
            if isinstance(options, dict):
                base = options.get("baseUrl")
                if isinstance(base, str):
                    resolved = _join(directory, base)
                    config.base_url = resolved if _inside(resolved) else None
                paths = options.get("paths")
                if isinstance(paths, dict):
                    config.paths = {
                        k: [t for t in v if isinstance(t, str)]
                        for k, v in paths.items()
                        if isinstance(k, str) and isinstance(v, list)
                    }
                    config.paths_dir = directory
        self._tsconfigs[path] = config
        return config

    def _parent(self, extends: Any, directory: str, chain: tuple[str, ...]) -> TsConfig | None:
        if extends is None:
            return None
        targets = extends if isinstance(extends, list) else [extends]
        found: TsConfig | None = None
        for target in targets:
            if not isinstance(target, str) or not target.startswith("."):
                self.config_extends += 1  # pacchetto: non si segue
                continue
            resolved = _join(directory, target)
            candidates = [resolved, resolved + ".json"]
            path = next(
                (c for c in candidates if c in self.configs or self._exists_config(c)), None
            )
            if path is None or not _inside(path) or path in chain or len(chain) >= MAX_EXTENDS:
                self.config_extends += 1
                continue
            found = self._load(path, chain)
        return found

    def _exists_config(self, path: str) -> bool:
        return self._read(path) is not None

    def tsconfig_for(self, importer: str) -> TsConfig | None:
        directory = posixpath.dirname(importer)
        while True:
            for name in ("tsconfig.json", "jsconfig.json"):
                path = posixpath.join(directory, name) if directory else name
                if path in self.configs:
                    return self._load(path, ())
            if not directory:
                return None
            directory = posixpath.dirname(directory)

    # --- pacchetti del workspace -------------------------------------------------------------

    def _workspace_packages(self) -> dict[str, tuple[str, dict[str, Any]]]:
        packages: dict[str, tuple[str, dict[str, Any]]] = {}
        for path in sorted(c for c in self.configs if c.endswith("package.json")):
            document = self._read(path)
            try:
                data = json.loads(document) if document else None
            except (ValueError, RecursionError):
                data = None
            if not isinstance(data, dict):
                continue
            name = data.get("name")
            if isinstance(name, str) and NPM_NAME.fullmatch(name) and name not in packages:
                packages[name] = (posixpath.dirname(path), data)
        return packages

    def _package_entry(self, directory: str, data: dict[str, Any]) -> str | None:
        candidates: list[str] = []
        exports = data.get("exports")
        if isinstance(exports, dict) and "." in exports:
            exports = exports["."]
        if isinstance(exports, str):
            candidates.append(exports)
        elif isinstance(exports, dict):
            candidates += [
                exports[k]
                for k in ("import", "default", "require")
                if isinstance(exports.get(k), str)
            ]
        candidates += [
            data[k] for k in ("source", "module", "main") if isinstance(data.get(k), str)
        ]
        candidates += ["src/index", "index"]
        for candidate in candidates:
            found = self._file(_join(directory, candidate))
            if found:
                return found
        return None

    # --- risoluzione di un file ------------------------------------------------------------

    def _file(self, path: str) -> str | None:
        if not _inside(path):
            return None
        if path in self.files:
            return path
        stem, dot, ext = path.rpartition(".")
        if dot and f".{ext}" in SWAP:
            for swapped in SWAP[f".{ext}"]:
                if stem + swapped in self.files:
                    return stem + swapped
        for extension in EXTENSIONS:
            if path + extension in self.files:
                return path + extension
        for extension in EXTENSIONS:
            index = posixpath.join(path, "index" + extension) if path else "index" + extension
            if index in self.files:
                return index
        return None

    def resolve(self, importer: str, ref: ImportRef) -> Outcome:
        spec = ref.spec
        if not spec:
            return Outcome("missing")
        if spec.startswith("."):
            found = self._file(_join(posixpath.dirname(importer), spec))
            return Outcome("files", [(found, DECLARED)]) if found else Outcome("missing")
        if spec.startswith("/"):
            return Outcome("outside")
        if spec.startswith("node:"):
            return Outcome("builtin")
        if re.match(r"^[A-Za-z][A-Za-z0-9+.-]*:", spec):
            return Outcome("missing")  # `http:`, `data:`, `file:`
        aliased = self._alias(importer, spec)
        if aliased is not None:
            return aliased
        return self._bare(spec)

    def _alias(self, importer: str, spec: str) -> Outcome | None:
        config = self.tsconfig_for(importer)
        if config is None:
            return None
        base = config.base_url if config.base_url is not None else config.paths_dir
        best: tuple[int, str, str] | None = None
        for pattern in config.paths:
            star = pattern.find("*")
            if star == -1:
                matched = spec == pattern
                captured = ""
                weight = len(pattern)
            else:
                prefix, suffix = pattern[:star], pattern[star + 1 :]
                matched = (
                    spec.startswith(prefix)
                    and spec.endswith(suffix)
                    and len(spec) >= len(prefix + suffix)
                )
                captured = spec[len(prefix) : len(spec) - len(suffix)] if matched else ""
                weight = len(prefix)
            if matched and (best is None or weight > best[0]):
                best = (weight, pattern, captured)
        if best is not None:
            _, pattern, captured = best
            for target in config.paths[pattern]:
                found = self._file(_join(base, target.replace("*", captured)))
                if found:
                    return Outcome("files", [(found, INFERRED)])
            return Outcome("missing")  # l'alias c'è ma il file no: non è un pacchetto esterno
        if config.base_url is not None:
            found = self._file(_join(config.base_url, spec))
            if found:
                return Outcome("files", [(found, INFERRED)])
        return None

    def _bare(self, spec: str) -> Outcome:
        parts = spec.split("/")
        name = "/".join(parts[:2]) if spec.startswith("@") else parts[0]
        subpath = parts[len(name.split("/")) :]
        if name in self.packages:
            directory, data = self.packages[name]
            found = (
                self._file(_join(directory, "/".join(subpath)))
                or self._file(_join(directory, posixpath.join("src", *subpath)))
                if subpath
                else self._package_entry(directory, data)
            )
            return Outcome("files", [(found, INFERRED)]) if found else Outcome("missing")
        if name in BUILTINS:
            return Outcome("builtin")
        if not NPM_NAME.fullmatch(name):
            return Outcome("missing")
        return Outcome("external", name=name)
