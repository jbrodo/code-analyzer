"""`graph`: contratto del grafo dei moduli emesso da `ca-graph` (C-02, ADR-0020, ADR-0022)."""

import pytest
from conftest import Json, errors_of, make_validator, mutated

VALIDATOR = make_validator("graph")

STATS: Json = {"files_parsed": 0}
HISTORY: Json = {"status": "assente", "window_days": 90}
MINIMAL: Json = {"version": 1, "stats": STATS, "history": HISTORY}

A: Json = {"path": "app/a.py", "language": "python", "parse": "completa", "churn": 4}
B: Json = {"path": "app/b.py", "language": "python", "parse": "parziale", "churn": 0}
T: Json = {"path": "tests/test_a.py", "language": "python", "parse": "completa", "test": True}
METRICS: Json = {"fan_in": 1, "fan_out": 1, "instability": 0.5, "pagerank": 0.25}
FULL: Json = {
    "version": 1,
    "modules": [{**A, "metrics": METRICS}, B, {**T, "churn": 1}],
    "externals": [{"name": "requests", "ecosystem": "pypi"}],
    "edges": [
        {"source": "app/a.py", "target": "app/b.py", "imports": 2, "confidence": "dichiarato"},
        {
            "source": "app/a.py",
            "target": "requests",
            "external": True,
            "imports": 1,
            "confidence": "dichiarato",
        },
        {
            "source": "app/b.py",
            "target": "app/a.py",
            "imports": 1,
            "dynamic": True,
            "type_only": True,
            "confidence": "dedotto",
        },
    ],
    "entrypoints": [
        {"path": "app/a.py", "kind": "main-module", "confidence": "dedotto"},
        {"path": "app/a.py", "kind": "package-metadata", "confidence": "dichiarato"},
    ],
    "packages": [
        {"path": "app", "modules": 2, "metrics": {"fan_in": 0, "fan_out": 0, "instability": 0.0}}
    ],
    "stats": {
        "files_parsed": 3,
        "files_partial": 1,
        "files_skipped_size": 0,
        "unresolved": {"computed": 2, "missing": 1, "outside_workspace": 0, "config_extends": 1},
    },
    "history": {
        "status": "completa",
        "window_days": 90,
        "head_time": "2026-11-13T10:00:00+00:00",
        "commits_read": 12,
    },
}
JS: Json = {"path": "src/view.tsx", "language": "tsx", "parse": "completa"}


def _with(**kv: object):
    return lambda i: i.update(kv)


def _module(**kv: object) -> Json:
    return mutated(MINIMAL, _with(modules=[{**JS, **kv}]))


def _edge(**kv: object) -> Json:
    edge = {"source": "app/a.py", "target": "app/b.py", "imports": 1, "confidence": "dichiarato"}
    modules = [{k: v for k, v in m.items() if k != "churn"} for m in (A, B)]
    return mutated(MINIMAL, _with(modules=modules, edges=[{**edge, **kv}]))


def _history(**kv: object) -> Json:
    return mutated(MINIMAL, _with(history={**HISTORY, **kv}))


VALID = {
    "minimal": MINIMAL,
    "full": FULL,
    "module-js": _module(),
    "stats-skipped-name": mutated(
        MINIMAL, _with(stats={"files_parsed": 1, "files_skipped_name": 2})
    ),
    "module-root-file": _module(path="setup.py", language="python"),
    "external-scoped-npm": mutated(
        MINIMAL, _with(externals=[{"name": "@scope/pkg.name", "ecosystem": "npm"}])
    ),
    "edge-observed": _edge(confidence="osservato"),
    "module-lines-and-adi": _module(lines=0, metrics={**METRICS, "adi": 1.25}),
    "history-shallow": _history(status="superficiale", commits_read=1),
    "package-root": mutated(
        MINIMAL,
        _with(
            modules=[{**JS, "path": "main.py", "language": "python"}],
            packages=[
                {
                    "path": ".",
                    "modules": 1,
                    "metrics": {"fan_in": 0, "fan_out": 0, "instability": 0},
                }
            ],
        ),
    ),
}

UNSAFE_PATHS = {
    "absolute": "/etc/passwd",
    "traversal": "a/../../b.py",
    "traversal-leading": "../b.py",
    "empty": "",
    "windows-drive": "C:/x.py",
    "backslash-absolute": "\\x.py",
    "too-long": "a/" * 2100 + "x.py",
    "newline": "a/b\n::error::x.py",
    "nul": "a\x00b.py",
    "carriage-return": "a\rb.py",
    "escape": "a\x1b[31m.py",
    "delete": "a\x7fb.py",
}

INVALID = {
    "missing-version": {"stats": STATS, "history": HISTORY},
    "version-2": mutated(MINIMAL, _with(version=2)),
    "version-true": mutated(MINIMAL, _with(version=True)),
    "missing-stats": {"version": 1, "history": HISTORY},
    "missing-history": {"version": 1, "stats": STATS},
    "unknown-top-level": mutated(MINIMAL, _with(nodes=[])),
    "module-unknown-language": _module(language="java"),
    "module-unknown-parse": _module(parse="fallita"),
    "module-unknown-key": _module(source="import os"),
    "module-negative-churn": _module(churn=-1),
    "module-negative-lines": _module(lines=-1),
    "module-fractional-lines": _module(lines=1.5),
    "metrics-negative-adi": _module(metrics={**METRICS, "adi": -0.1}),
    "metrics-string-adi": _module(metrics={**METRICS, "adi": "1"}),
    "module-test-not-bool": _module(test="yes"),
    "metrics-instability-above-one": _module(metrics={**METRICS, "instability": 1.5}),
    "metrics-missing-fan-in": _module(metrics={"fan_out": 1, "instability": 0.5}),
    "external-with-path-separator": mutated(
        MINIMAL, _with(externals=[{"name": "a/b/c", "ecosystem": "npm"}])
    ),
    "external-with-space": mutated(
        MINIMAL, _with(externals=[{"name": "a b", "ecosystem": "pypi"}])
    ),
    "external-unknown-ecosystem": mutated(
        MINIMAL, _with(externals=[{"name": "a", "ecosystem": "maven"}])
    ),
    "edge-zero-imports": _edge(imports=0),
    "edge-unknown-confidence": _edge(confidence="certo"),
    "edge-missing-confidence": mutated(
        MINIMAL,
        _with(modules=[A, B], edges=[{"source": "app/a.py", "target": "app/b.py", "imports": 1}]),
    ),
    "edge-unknown-key": _edge(line=3),
    "entrypoint-unknown-kind": mutated(
        MINIMAL,
        _with(
            modules=[A], entrypoints=[{"path": "app/a.py", "kind": "x", "confidence": "dedotto"}]
        ),
    ),
    "package-zero-modules": mutated(
        MINIMAL,
        _with(
            packages=[
                {
                    "path": "app",
                    "modules": 0,
                    "metrics": {"fan_in": 0, "fan_out": 0, "instability": 0},
                }
            ]
        ),
    ),
    "stats-negative": mutated(MINIMAL, _with(stats={"files_parsed": -1})),
    "stats-skipped-name-negative": mutated(
        MINIMAL, _with(stats={"files_parsed": 0, "files_skipped_name": -1})
    ),
    "stats-unknown-reason": mutated(
        MINIMAL, _with(stats={"files_parsed": 0, "unresolved": {"other": 1}})
    ),
    "history-unknown-status": _history(status="parziale"),
    "history-window-zero": _history(window_days=0),
}
for _name, _value in UNSAFE_PATHS.items():
    INVALID[f"module-path-{_name}"] = _module(path=_value)
    INVALID[f"edge-source-{_name}"] = _edge(source=_value)


@pytest.mark.parametrize("instance", VALID.values(), ids=VALID.keys())
def test_valid_graph_is_accepted(instance: Json) -> None:
    assert errors_of(VALIDATOR, instance) == []


@pytest.mark.parametrize("instance", INVALID.values(), ids=INVALID.keys())
def test_invalid_graph_is_rejected(instance: Json) -> None:
    assert errors_of(VALIDATOR, instance) != []


@pytest.mark.parametrize(
    ("section", "limit"),
    [("modules", 200_000), ("externals", 50_000), ("edges", 2_000_000), ("entrypoints", 10_000)],
)
def test_lists_have_a_size_cap(section: str, limit: int) -> None:
    """Il tetto è nello schema: un documento oltre il limite è rifiutato, non troncato."""
    schema = VALIDATOR.schema
    assert schema["properties"][section]["maxItems"] == limit
