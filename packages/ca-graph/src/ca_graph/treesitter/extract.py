"""Estrazione del grafo dei moduli di un workspace (G-02, G-03, ADR-0020).

Produce un dizionario nel formato del contratto `graph` (C-02) senza importare `ca_core`: lo
valida il test di contratto. Nodi, archi ed elenchi sono ordinati, così lo stesso workspace dà lo
stesso file. Entrypoint, churn, metriche e pacchetti non sono qui: gli entrypoint e il churn
arrivano con G-11 e G-12, metriche e pacchetti li ricava l'host (ADR-0020).
"""

import json
from dataclasses import dataclass, field
from typing import Any

from ca_graph.treesitter import files as fs
from ca_graph.treesitter import javascript as js
from ca_graph.treesitter import python as py
from ca_graph.treesitter.refs import FileImports

PYTHON, JS_FAMILY = "python", ("javascript", "typescript", "tsx")
RANK = {"dichiarato": 0, "dedotto": 1, "osservato": 2}  # il più debole vince nell'unione
MAX_ARGUMENT = 214


@dataclass
class _Edge:
    imports: int = 0
    dynamic: bool = True
    type_only: bool = True
    confidence: str = "dichiarato"

    def add(self, *, dynamic: bool, type_only: bool, confidence: str) -> None:
        self.imports += 1
        self.dynamic &= dynamic
        self.type_only &= type_only
        if RANK[confidence] > RANK[self.confidence]:
            self.confidence = confidence


@dataclass
class _State:
    edges: dict[tuple[str, bool, str], _Edge] = field(default_factory=dict)
    externals: set[tuple[str, str]] = field(default_factory=set)
    computed: int = 0
    missing: int = 0
    outside: int = 0

    def edge(self, source: str, target: str, external: bool, **kw: Any) -> None:
        if not external and source == target:
            return
        self.edges.setdefault((source, external, target), _Edge()).add(**kw)


def _record_python(state: _State, resolver: py.Resolver, source: str, imports: FileImports) -> None:
    for ref in imports.refs:
        outcome = resolver.resolve(source, ref)
        if outcome is None:
            state.missing += 1
        elif outcome == "stdlib":
            continue
        elif isinstance(outcome, str):
            name = outcome.removeprefix("ext:")
            state.externals.add(("pypi", name))
            state.edge(
                source,
                name,
                True,
                dynamic=ref.dynamic,
                type_only=ref.type_only,
                confidence="dichiarato",
            )
        else:
            for target, confidence in outcome:
                state.edge(
                    source,
                    target,
                    False,
                    dynamic=ref.dynamic,
                    type_only=ref.type_only,
                    confidence=confidence,
                )


def _record_js(state: _State, resolver: js.Resolver, source: str, imports: FileImports) -> None:
    for ref in imports.refs:
        outcome = resolver.resolve(source, ref)
        if outcome.kind == "files":
            for target, confidence in outcome.files:
                state.edge(
                    source,
                    target,
                    False,
                    dynamic=ref.dynamic,
                    type_only=ref.type_only,
                    confidence=confidence,
                )
        elif outcome.kind == "external":
            state.externals.add(("npm", outcome.name))
            state.edge(
                source,
                outcome.name,
                True,
                dynamic=ref.dynamic,
                type_only=ref.type_only,
                confidence="dichiarato",
            )
        elif outcome.kind == "outside":
            state.outside += 1
        elif outcome.kind == "missing":
            state.missing += 1


def extract_graph(workspace: str, *, window_days: int = 90) -> dict[str, Any]:
    """Grafo del workspace nel formato di C-02. `LimitExceeded` se supera i limiti globali."""
    listing = fs.list_sources(workspace)
    sources = listing.files
    configs = fs.list_configs(workspace)

    def read_config(path: str) -> bytes | None:
        return fs.read_file(workspace, path, fs.MAX_CONFIG_BYTES)

    py_resolver = py.Resolver(sources, configs)
    js_resolver = js.Resolver(
        (f for f in sources if fs.language_of(f) in JS_FAMILY), configs, read_config
    )

    state = _State()
    modules: list[dict[str, Any]] = []
    parsed = partial = 0
    for path in sources:
        language = fs.language_of(path)
        assert language is not None
        data = fs.read_file(workspace, path)
        if data is None:
            imports = FileImports(refs=[], partial=True)
        elif language == PYTHON:
            imports = py.extract_imports(data)
        else:
            imports = js.extract_imports(data, language)
        parsed += 1
        partial += imports.partial
        state.computed += imports.computed
        if language == PYTHON:
            _record_python(state, py_resolver, path, imports)
        else:
            _record_js(state, js_resolver, path, imports)
        modules.append(
            {
                "path": path,
                "language": language,
                "parse": "parziale" if imports.partial else "completa",
                "test": fs.is_test_path(path),
            }
        )
    edges = [
        {
            "source": source,
            "target": target,
            "external": external,
            "imports": edge.imports,
            "dynamic": edge.dynamic,
            "type_only": edge.type_only,
            "confidence": edge.confidence,
        }
        for (source, external, target), edge in sorted(state.edges.items())
    ]
    return {
        "version": 1,
        "modules": modules,
        "externals": [{"name": n, "ecosystem": e} for e, n in sorted(state.externals)],
        "edges": edges,
        "entrypoints": [],
        "packages": [],
        "stats": {
            "files_parsed": parsed,
            "files_partial": partial,
            "files_skipped_size": listing.skipped_size,
            "files_skipped_name": listing.skipped_name,
            "unresolved": {
                "computed": state.computed,
                "missing": state.missing,
                "outside_workspace": state.outside,
                "config_extends": js_resolver.config_extends,
                "entrypoint_missing": 0,
            },
        },
        "history": {"status": "assente", "window_days": window_days},
    }


def to_json(graph: dict[str, Any]) -> bytes:
    """Serializzazione canonica: lo stesso grafo dà gli stessi byte."""
    return (
        json.dumps(graph, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n"
    ).encode()


__all__ = ["extract_graph", "to_json"]
