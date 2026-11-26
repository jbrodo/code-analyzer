"""K-06: la procedura del benchmark aggrega come dice ADR-0023 (dati finti, nessuna rete)."""

import importlib.util
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from ca_core.scoring import exposure
from ca_core.scoring.benchmark import load_benchmark

SOURCE = Path(__file__).resolve().parents[2] / "scripts/benchmark/benchmark.py"
spec = importlib.util.spec_from_file_location("benchmark_tools", SOURCE)
assert spec is not None and spec.loader is not None
bt = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bt)

NOW = datetime(2026, 11, 26, 10, 0, tzinfo=UTC)


def code(tool: str, rule: str, value: int, path: str = "src/a.py") -> dict[str, Any]:
    return {
        "tool": tool, "rule_id": rule, "category": "quality", "location": {"path": path},
        "evidence": {tool: {"tool_severity": "medium", "metric": {"value": value, "threshold": 0}}},
    }  # fmt: skip


def smell(rule: str, scope: str = "module", path: str = "pkg/a.py", **evidence: Any):
    return {
        "tool": "ca-graph", "rule_id": rule, "category": "architecture",
        "location": {"path": path}, "evidence": {"ca-graph": {"scope": scope, **evidence}},
    }  # fmt: skip


def report(*findings: dict[str, Any], ruff: str = "1.0.0") -> dict[str, Any]:
    return {
        "findings": list(findings),
        "plugins": [
            {"name": "ruff", "version": ruff, "outcome": "ok"},
            {"name": "ca-graph", "version": "1.0.0", "outcome": "ok"},
        ],
    }


CYCLE = "ca.arch.cyclic-dependency"
HUB = "ca.arch.hub-like-dependency"


@pytest.mark.parametrize(
    "path",
    ["src/a.py", "tests/a.py", "pkg/test_a.py", "conftest.py", "web/a.spec.ts", "a_test.go",
     "src/__tests__/x.js", "Testing/a.py", "src/testing.py", "latest/a.py"],
)  # fmt: skip
def test_test_paths_follow_the_rules_of_the_core(path: str) -> None:
    assert bt.is_test_path(path) == exposure.is_test_path(path)


def test_observations_skip_tests_and_findings_without_a_metric() -> None:
    no_metric = code("ruff", "F401", 1)
    no_metric["evidence"]["ruff"].pop("metric")
    found_code, found_sizes = bt.observations(
        report(
            code("ruff", "C901", 3),
            code("ruff", "C901", 7, path="tests/test_a.py"),
            code("eslint", "complexity", 4, path="src/a.ts"),
            no_metric,
            code("bandit", "B101", 1),
            smell(CYCLE, size=3),
            smell(HUB, fan_in=4, fan_out=6, size=1),
            smell(CYCLE, scope="package", size=2, path="tests/x.py"),
        )
    )
    assert found_code == {("ruff", "C901"): [3.0], ("eslint", "complexity"): [4.0]}
    assert found_sizes == {(CYCLE, "module"): [3.0], (HUB, "module"): [10.0]}


PERCENT = range(0, 10001, 100)  # ogni 1%, in centesimi


def test_one_repository_gives_its_own_quantiles() -> None:
    values = [float(i) for i in range(101)]
    assert bt.mixture_quantiles([values], PERCENT) == values


def test_the_default_grid_is_dense_in_the_tail() -> None:
    assert bt.LEVELS[0] == 0 and bt.LEVELS[-1] == 100 and list(bt.LEVELS) == sorted(set(bt.LEVELS))
    assert bt.LEVELS[89:92] == (89.0, 90.0, 90.1) and bt.LEVELS[-2:] == (99.99, 100.0)
    assert 99.5 in bt.LEVELS and 99.95 in bt.LEVELS and len(bt.LEVELS) == 281
    values = [float(i) for i in range(1000)]
    q = bt.mixture_quantiles([values])
    assert len(q) == len(bt.LEVELS)
    assert q[bt.LEVELS.index(99.5)] == pytest.approx(994, abs=1)


def test_every_repository_weighs_the_same_whatever_its_size() -> None:
    big, small = [1.0] * 1000, [10.0] * 10
    q = bt.mixture_quantiles([big, small], PERCENT)
    assert q[0] == 1.0 and q[50] == 1.0 and q[51] == 10.0 and q[100] == 10.0


def test_a_repository_without_observations_does_not_count() -> None:
    assert bt.mixture_quantiles([[], [2.0, 4.0]]) == bt.mixture_quantiles([[2.0, 4.0]])
    with pytest.raises(ValueError):
        bt.mixture_quantiles([[], []])


CORPUS = [
    {"url": "https://github.com/a/one", "commit": "a" * 40, "tag": "1.0"},
    {"url": "https://github.com/b/two", "commit": "b" * 40, "tag": None},
]


def test_build_writes_a_benchmark_the_core_accepts() -> None:
    reports = {
        CORPUS[0]["url"]: report(
            *(code("ruff", "C901", v) for v in range(1, 40)), smell(CYCLE, size=2)
        ),
        CORPUS[1]["url"]: report(code("ruff", "C901", 5), code("ruff", "PLR0913", 2)),
    }  # fmt: skip
    document = bt.build(reports, CORPUS, bt.engines_of(reports.values()), version=1, created_at=NOW)
    loaded = load_benchmark(json.dumps(document).encode())
    c901 = loaded.code_metric("ruff", "C901")
    assert c901 is not None and (c901.repositories, c901.observations) == (2, 40)
    # metà della quota da `one` (5 valori su 39) e metà da `two` (il solo valore 5)
    assert loaded.cdf(c901, 5) == pytest.approx(0.55, abs=0.02)
    plr = loaded.code_metric("ruff", "PLR0913")
    assert plr is not None and plr.repositories == 1
    assert loaded.smell_size(CYCLE, "module") is not None
    assert document["engines"] == {"ca-graph": "1.0.0", "ruff": "1.0.0"}


def test_build_needs_a_report_for_every_repository() -> None:
    with pytest.raises(ValueError, match="report mancanti"):
        bt.build({CORPUS[0]["url"]: report()}, CORPUS, {}, version=1, created_at=NOW)


def test_engines_must_match_across_reports() -> None:
    with pytest.raises(ValueError, match="versioni diverse"):
        bt.engines_of([report(ruff="1.0.0"), report(ruff="1.1.0")])


def test_the_corpus_is_the_one_approved_in_adr_0023() -> None:
    corpus = bt.load_corpus()
    names = {bt.slug(r["url"]) for r in corpus}
    assert names == {
        "saleor__saleor", "fastapi__full-stack-fastapi-template", "excalidraw__excalidraw",
        "pallets__flask", "encode__httpx", "scrapy__scrapy", "django__django",
        "expressjs__express", "vuejs__core", "vitejs__vite",
    }  # fmt: skip
    assert all(len(r["commit"]) == 40 and r["tag"] for r in corpus)
    assert sum(r["pilot"] for r in corpus) == 3


def test_collect_refuses_a_work_directory_inside_the_repository() -> None:
    assert bt.collect(bt.ROOT / "tmp-benchmark", "python", []) == 2


def test_a_partial_scan_is_usable_when_the_benchmark_plugins_succeeded() -> None:
    ok = report()
    assert bt.usable(ok) is None
    skipped = {**ok, "plugins": [*ok["plugins"], {"name": "eslint", "outcome": "skipped"}]}
    assert bt.usable(skipped) is None
    graph_failed = {**ok, "plugins": [{"name": "ruff", "outcome": "ok"},
                                      {"name": "ca-graph", "outcome": "failed"}]}  # fmt: skip
    assert bt.usable(graph_failed) is not None
    eslint_failed = {**ok, "plugins": [*ok["plugins"], {"name": "eslint", "outcome": "failed"}]}
    assert bt.usable(eslint_failed) is not None
