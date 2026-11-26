"""K-07..K-10: Variante B su qualità e architettura (ADR-0023), con i casi di F-05.

I valori attesi della tabella sono ricavati a mano dall'ADR su un benchmark e un grafo minimi
(`variant_b` in `tests/fixtures/scoring/cases.json`), non dal codice.
"""

import json
from pathlib import Path
from typing import Any

import pytest
from builders import finding

from ca_core.models.finding import Category, Finding, Level
from ca_core.models.graph import Graph
from ca_core.models.scoring_config import ScoringConfig
from ca_core.scoring.base import ScoringContext, impact
from ca_core.scoring.benchmark import LoadedBenchmark, load_benchmark
from ca_core.scoring.churn import ChurnIndex
from ca_core.scoring.config import default_bytes, load_default
from ca_core.scoring.levels import level_from_score
from ca_core.scoring.models import MODELS, VariantAModel
from ca_core.scoring.variant_b import arch_smell, change, code_smell, criticality
from ca_core.scoring.variant_b.graph_index import GraphIndex

CASES: dict[str, Any] = json.loads(
    (Path(__file__).resolve().parents[1] / "fixtures/scoring/cases.json").read_text()
)["variant_b"]
CONFIG = load_default()


def benchmark_of(spec: dict[str, Any], engines: dict[str, str] | None = None) -> LoadedBenchmark:
    def dist(d: dict[str, Any]) -> dict[str, Any]:
        keys = {k: v for k, v in d.items() if k != "quantiles"}
        n = len(d["quantiles"])
        return {**keys, "repositories": 1, "observations": n, "quantiles": d["quantiles"]}

    document = {
        "version": 1,
        "created_at": "2026-11-26T10:00:00Z",
        "levels": spec["levels"],
        "corpus": [{"url": "https://github.com/pallets/flask", "commit": "a" * 40}],
        "engines": engines or {"ruff": "1.0.0", "ca-graph": "1.0.0"},
        "code_metrics": [dist(d) for d in spec["code_metrics"]],
        "smell_sizes": [dist(d) for d in spec["smell_sizes"]],
    }
    return load_benchmark(json.dumps(document).encode())


BENCHMARK = benchmark_of(CASES["benchmark"])


def graph_of(spec: dict[str, Any], history: str = "completa") -> Graph:
    modules = []
    for m in spec["modules"]:
        module: dict[str, Any] = {
            "path": m["path"],
            "language": "python",
            "parse": "completa",
            "test": m.get("test", False),
            "lines": m["lines"],
        }
        if history == "completa":
            module["churn"] = m["churn"]
        if "pagerank" in m:
            module["metrics"] = {
                "fan_in": 0, "fan_out": 0, "instability": 0.0, "pagerank": m["pagerank"]
            }  # fmt: skip
        modules.append(module)
    return Graph.model_validate(
        {
            "version": 1,
            "modules": modules,
            "stats": {"files_parsed": len(modules)},
            "history": {"status": history, "window_days": 90},
        }
    )


def quality_findings(spec: dict[str, Any]) -> list[Finding]:
    return [
        finding(f"{path}-{i}", category=Category.QUALITY, tool="ruff", path=path)
        for path, count in spec["quality_findings"].items()
        for i in range(count)
    ]


def context(
    *,
    history: str = "completa",
    config: ScoringConfig = CONFIG,
    benchmark: LoadedBenchmark | None = BENCHMARK,
    graph: bool = True,
    **kv: Any,
) -> ScoringContext:
    g = graph_of(CASES["graph"], history)
    return ScoringContext(
        config=config,
        benchmark=benchmark,
        churn=ChurnIndex(g) if graph else None,
        graph=GraphIndex(g, quality_findings(CASES["graph"])) if graph else None,
        **kv,
    )


CTX = context()


def code_finding(case: dict[str, Any], path: str = "a.py") -> Finding:
    evidence: dict[str, Any] = {}
    if "metric" in case:
        evidence["metric"] = case["metric"]
    if "tool_severity" in case:
        evidence["tool_severity"] = case["tool_severity"]
    f = finding("q", category=Category.QUALITY, tool="ruff", path=path, evidence=evidence)
    return f.model_copy(update={"rule_id": case["rule_id"]})


def arch_finding(rule_id: str, evidence: dict[str, Any], path: str = "a.py") -> Finding:
    f = finding("s", category=Category.ARCHITECTURE, tool="ca-graph", path=path, evidence=evidence)
    return f.model_copy(update={"rule_id": rule_id})


def members_finding(members: list[str]) -> Finding:
    return arch_finding(arch_smell.CYCLIC, {"scope": "module", "size": 2, "members": members})


def check(factor: Any, case: dict[str, Any]) -> None:
    assert factor.value == pytest.approx(case["expected"], abs=1e-9)
    if "fallback" in case:
        assert factor.evidence["fallback"] == case["fallback"]
    else:
        assert "fallback" not in factor.evidence


# --- tabella F-05 -------------------------------------------------------------------------------


@pytest.mark.parametrize("case", CASES["g_code"], ids=[c["name"] for c in CASES["g_code"]])
def test_code_smell_g_matches_the_hand_derived_table(case: dict[str, Any]) -> None:
    check(code_smell.factor_g(code_finding(case), CTX), case)


@pytest.mark.parametrize("case", CASES["g_arch"], ids=[c["name"] for c in CASES["g_arch"]])
def test_architecture_g_matches_the_hand_derived_table(case: dict[str, Any]) -> None:
    check(arch_smell.factor_g(arch_finding(case["rule_id"], case["evidence"]), CTX), case)


@pytest.mark.parametrize("case", CASES["p"], ids=[c["name"] for c in CASES["p"]])
def test_p_matches_the_hand_derived_table(case: dict[str, Any]) -> None:
    ctx = context(history=case.get("history", "completa"))
    check(change.factor_p(members_finding(case["members"]), ctx), case)


@pytest.mark.parametrize("case", CASES["c"], ids=[c["name"] for c in CASES["c"]])
def test_c_matches_the_hand_derived_table(case: dict[str, Any]) -> None:
    check(criticality.factor_c(members_finding(case["members"]), CTX), case)


@pytest.mark.parametrize("case", CASES["scores"], ids=[c["name"] for c in CASES["scores"]])
def test_variant_b_scores_match_the_hand_derived_table(case: dict[str, Any]) -> None:
    if case["category"] == "quality":
        f = code_finding(case, path=case["path"])
    else:
        f = arch_finding(case["rule_id"], case["evidence"], path=case["path"])
    factors = MODELS["B"].factors(f, CTX)
    assert factors.variant == "B"
    got = (factors.g, factors.p, factors.e, factors.c)
    assert got == pytest.approx((case["g"], case["p"], case["e"], case["c"]), abs=1e-9)
    score = impact(factors.g, factors.p, factors.e, factors.c)
    assert score == case["score"]
    assert level_from_score(score, CONFIG.levels.thresholds) is Level(case["level"])


# --- evidenza e ripieghi -----------------------------------------------------------------------


def test_the_code_smell_evidence_has_the_numbers_that_produce_g() -> None:
    factor = code_smell.factor_g(code_finding(CASES["g_code"][0]), CTX)
    assert factor.evidence["benchmark"] == BENCHMARK.version
    (metric,) = factor.evidence["metrics"]
    assert metric == {
        "engine": "ruff", "value": 20.0, "threshold": 10.0,
        "f_value": 0.95, "f_threshold": 0.9, "intensity": 0.5,
    }  # fmt: skip
    assert "warning" not in factor.evidence


def test_a_different_engine_version_is_declared_not_refused() -> None:
    ctx = context(plugin_versions={"ruff": "1.1.0", "ca-graph": "1.0.0"})
    factor = code_smell.factor_g(code_finding(CASES["g_code"][0]), ctx)
    assert factor.value == 0.5 and factor.evidence["warning"] == "benchmark-motore-diverso"
    same = code_smell.factor_g(
        code_finding(CASES["g_code"][0]), context(plugin_versions={"ruff": "1.0.0"})
    )
    assert "warning" not in same.evidence
    arch = arch_smell.factor_g(
        arch_finding(arch_smell.CYCLIC, {"scope": "module", "size": 4}),
        context(plugin_versions={"ca-graph": "2.0.0"}),
    )
    assert arch.evidence["warning"] == "benchmark-motore-diverso"


def test_without_a_benchmark_g_is_the_one_of_a_and_says_why() -> None:
    ctx = context(benchmark=None)
    code = code_smell.factor_g(code_finding(CASES["g_code"][0] | {"tool_severity": "low"}), ctx)
    assert (code.value, code.evidence["fallback"]) == (0.25, "benchmark-assente")
    assert code.evidence["from_variant"] == "A"
    arch = arch_smell.factor_g(arch_finding(arch_smell.CYCLIC, {"scope": "module", "size": 4}), ctx)
    assert arch.evidence["fallback"] == "benchmark-assente"


@pytest.mark.parametrize(
    "evidence",
    [{"scope": "module"}, {"scope": "module", "size": True}, {"size": 4},
     {"scope": "module", "size": 1, "fan_in": 3}],
)  # fmt: skip
def test_a_smell_without_a_usable_dimension_falls_back(evidence: dict[str, Any]) -> None:
    rule = arch_smell.HUB_LIKE if "fan_in" in evidence else arch_smell.CYCLIC
    factor = arch_smell.factor_g(arch_finding(rule, evidence), CTX)
    assert factor.evidence["fallback"] == "dimensione-assente"


def test_a_metric_that_is_not_a_number_is_not_a_metric() -> None:
    case = {"rule_id": "C901", "metric": {"value": "20", "threshold": 10}, "tool_severity": "low"}
    factor = code_smell.factor_g(code_finding(case), CTX)
    assert factor.evidence["fallback"] == "metrica-assente"


def test_two_engines_with_a_metric_average_their_intensities() -> None:
    f = code_finding({"rule_id": "C901", "metric": {"value": 20, "threshold": 10}})
    f = f.model_copy(
        update={
            "tools": ["eslint", "ruff"],
            "evidence": {**f.evidence, "eslint": {"metric": {"value": 40, "threshold": 10}}},
        }
    )
    ruff_only = benchmark_of(CASES["benchmark"])
    two = CASES["benchmark"] | {
        "code_metrics": [
            *CASES["benchmark"]["code_metrics"],
            {"engine": "eslint", "rule_id": "C901", "quantiles": [1.0, 4.0, 10.0, 30.0]},
        ]
    }  # fmt: skip
    assert code_smell.factor_g(f, context(benchmark=ruff_only)).value == 0.5
    assert code_smell.factor_g(f, context(benchmark=benchmark_of(two))).value == 0.75


def test_without_a_graph_c_is_the_tier_of_a_and_p_uses_the_unknown_values() -> None:
    ctx = context(graph=False)
    c = criticality.factor_c(members_finding(["a.py"]), ctx)
    assert (c.value, c.evidence["fallback"]) == (0.7, "grafo-assente")
    p = change.factor_p(members_finding(["a.py"]), ctx)
    assert (p.value, p.evidence["fallback"]) == (0.3, "churn-ignoto,densita-ignota")


def test_p_evidence_shows_the_percentiles_the_weights_and_the_density() -> None:
    p = change.factor_p(members_finding(["a.py"]), CTX)
    assert p.evidence == {
        "rule": "churn-density", "churn_percentile": 0.5, "density_percentile": 0.5,
        "w_churn": 0.5, "w_density": 0.5, "violations": 2, "density_per_kloc": 20.0,
    }  # fmt: skip


def test_c_evidence_shows_the_raw_pagerank_and_the_rank() -> None:
    c = criticality.factor_c(members_finding(["a.py", "d.py"]), CTX)
    assert c.evidence == {"rule": "pagerank-rank", "rank": 0.75, "pagerank": 0.5, "module": "d.py"}


def test_c_has_a_floor() -> None:
    spec = {
        "modules": [{"path": f"m{i:02}.py", "lines": 10, "churn": 0, "pagerank": (i + 1) / 20}
                    for i in range(20)],
        "quality_findings": {},
    }  # fmt: skip
    g = graph_of(spec)
    ctx = ScoringContext(config=CONFIG, benchmark=BENCHMARK, graph=GraphIndex(g, []))
    assert criticality.factor_c(members_finding(["m00.py"]), ctx).value == 0.1  # 1/20 < 0,1
    assert criticality.factor_c(members_finding(["m02.py"]), ctx).value == 0.15


# --- modello ------------------------------------------------------------------------------------


def test_outside_quality_and_architecture_b_is_a() -> None:
    secret = finding("k", category=Category.SECRET, tool="gitleaks")
    a, b = VariantAModel().factors(secret, CTX), MODELS["B"].factors(secret, CTX)
    assert (a.g, a.p, a.e, a.c) == (b.g, b.p, b.e, b.c) and b.variant == "B"
    assert "fallbacks" not in b.evidence


def test_on_quality_b_differs_from_a_and_has_no_global_fallback() -> None:
    f = code_finding(CASES["g_code"][0] | {"tool_severity": "high"})
    a, b = VariantAModel().factors(f, CTX), MODELS["B"].factors(f, CTX)
    assert (a.g, b.g) == (0.75, 0.5)
    assert b.c == 0.25 and a.c == 0.7
    assert "variante-b-non-configurata" not in b.evidence.get("fallbacks", [])


def test_without_the_block_b_is_a_and_says_so() -> None:
    data = json.loads(default_bytes())
    data.pop("variant_b")
    config = ScoringConfig.model_validate(data)
    f = code_finding(CASES["g_code"][0] | {"tool_severity": "high"})
    b = MODELS["B"].factors(f, context(config=config))
    assert b.g == 0.75 and "variante-b-non-configurata" in b.evidence["fallbacks"]


def test_the_weights_of_p_must_add_up_to_one() -> None:
    data = json.loads(default_bytes())
    data["variant_b"]["p"]["w_churn"] = 0.6
    with pytest.raises(ValueError, match="w_churn"):
        ScoringConfig.model_validate(data)


def test_no_value_of_b_is_in_the_code() -> None:
    """Regola 3: cambiando la configurazione cambiano G, P e C di B."""
    data = json.loads(default_bytes())
    data["variant_b"] = {
        "g": {"floor": 0.2, "architecture": {"cyclic_dependency": 0.5,
                                             "hub_like_dependency": 0.5,
                                             "unstable_dependency": 0.5}},
        "p": {"w_churn": 1.0, "w_density": 0.0, "floor": 0.05, "density_unknown": 0.9},
        "c": {"floor": 0.3},
    }  # fmt: skip
    ctx = context(config=ScoringConfig.model_validate(data))
    assert code_smell.factor_g(code_finding(CASES["g_code"][1]), ctx).value == 0.2
    cycle = arch_finding(arch_smell.CYCLIC, {"scope": "module", "size": 4})
    assert arch_smell.factor_g(cycle, ctx).value == 0.35
    assert change.factor_p(members_finding(["a.py"]), ctx).value == 0.5
    assert criticality.factor_c(members_finding(["a.py"]), ctx).value == 0.3


def test_graph_index_counts_only_quality_findings() -> None:
    g = graph_of(CASES["graph"])
    other = finding("x", category=Category.SAST, tool="bandit", path="b.py")
    index = GraphIndex(g, [*quality_findings(CASES["graph"]), other])
    assert index.violations("b.py") == 0 and index.density("b.py") == 0.0
    assert index.modules_of(["."]) == ["a.py", "b.py", "c.py", "d.py"]
    assert index.modules_of(["tests"]) == ["tests/test_a.py"]
    assert index.modules_of(["nowhere", "a.py"]) == ["a.py"]


def test_a_module_without_lines_has_no_density_and_an_empty_file_has_zero() -> None:
    spec = {
        "modules": [
            {"path": "a.py", "lines": 0, "churn": 0},
            {"path": "b.py", "lines": 10, "churn": 0},
        ],
        "quality_findings": {},
    }  # fmt: skip
    g = graph_of(spec)
    g = g.model_copy(
        update={"modules": [g.modules[0], g.modules[1].model_copy(update={"lines": None})]}
    )
    index = GraphIndex(g, [])
    assert index.density("a.py") == 0.0 and index.density("b.py") is None
    assert index.density_percentile("b.py") is None


def test_scoring_is_deterministic() -> None:
    f = code_finding(CASES["g_code"][0])
    first = MODELS["B"].factors(f, CTX)
    assert all(MODELS["B"].factors(f, context()) == first for _ in range(3))
