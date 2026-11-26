"""K-06: lettura della distribuzione di benchmark e funzione di ripartizione (ADR-0023)."""

import json
from typing import Any

import pytest

from ca_core.models.scoring_benchmark import Distribution
from ca_core.scoring.benchmark import BenchmarkError, cdf, load_benchmark, parse_benchmark

PERCENT = [float(i) for i in range(101)]


def dist(quantiles: list[float]) -> Distribution:
    return Distribution(repositories=1, observations=len(quantiles), quantiles=quantiles)


LINEAR = dist([float(i) for i in range(101)])  # quantile p = p
STEPS = dist([float(min(i // 25, 3)) for i in range(101)])  # 0 fino a 24, 1 fino a 49, ...


@pytest.mark.parametrize(
    ("x", "expected"),
    [(-1, 0.0), (0, 0.0), (50, 0.5), (12.5, 0.125), (100, 1.0), (1000, 1.0)],
)
def test_cdf_on_a_linear_distribution(x: float, expected: float) -> None:
    assert cdf(LINEAR, PERCENT, x) == pytest.approx(expected)


@pytest.mark.parametrize(
    ("x", "expected"),
    [(0, 0.24), (1, 0.49), (2, 0.74), (3, 1.0), (0.5, 0.245)],
)
def test_cdf_takes_the_top_of_a_step(x: float, expected: float) -> None:
    """Valori interi ripetuti: il valore del gradino ha la quota di chi sta sotto o uguale."""
    assert cdf(STEPS, PERCENT, x) == pytest.approx(expected)


def test_cdf_is_monotonic() -> None:
    values = [cdf(STEPS, PERCENT, x / 10) for x in range(-10, 50)]
    assert values == sorted(values)


def benchmark_doc(**changes: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "version": 3,
        "created_at": "2026-11-26T10:00:00Z",
        "levels": PERCENT,
        "corpus": [
            {"url": "https://github.com/pallets/flask", "commit": "a" * 40},
            {"url": "https://github.com/encode/httpx", "commit": "b" * 40},
        ],
        "engines": {"ruff": "0.17.5"},
        "code_metrics": [
            {
                "engine": "ruff",
                "rule_id": "C901",
                "repositories": 2,
                "observations": 10,
                "quantiles": [float(i) for i in range(101)],
            },
        ],
        "smell_sizes": [],
    }
    base.update(changes)
    return base


def raw(doc: dict[str, Any]) -> bytes:
    return json.dumps(doc).encode()


def test_load_finds_distributions_and_records_the_version() -> None:
    loaded = load_benchmark(raw(benchmark_doc()))
    assert loaded.version.startswith("3+") and len(loaded.version) == 2 + 12
    assert loaded.code_metric("ruff", "C901") is not None
    assert loaded.code_metric("eslint", "C901") is None
    assert loaded.smell_size("ca.arch.cyclic-dependency", "module") is None


@pytest.mark.parametrize(
    "doc",
    [
        benchmark_doc(
            code_metrics=[
                {
                    "engine": "ruff",
                    "rule_id": "C901",
                    "repositories": 1,
                    "observations": 5,
                    "quantiles": [float(100 - i) for i in range(101)],
                }
            ]
        ),
        benchmark_doc(
            code_metrics=[
                {
                    "engine": "ruff",
                    "rule_id": "C901",
                    "repositories": 2,
                    "observations": 1,
                    "quantiles": [0.0] * 101,
                }
            ]
        ),
        benchmark_doc(
            code_metrics=[
                {
                    "engine": "ruff",
                    "rule_id": "C901",
                    "repositories": 3,
                    "observations": 9,
                    "quantiles": [0.0] * 101,
                }
            ]
        ),
        benchmark_doc(code_metrics=[benchmark_doc()["code_metrics"][0]] * 2),
        benchmark_doc(
            corpus=[{"url": "https://github.com/a/b", "commit": "a" * 40}] * 2,
            code_metrics=[],
        ),
        benchmark_doc(levels=PERCENT[:-1]),
        benchmark_doc(levels=[*PERCENT[:-1], 99.0]),
        benchmark_doc(levels=[1.0, *PERCENT[1:]]),
    ],
    ids=[
        "unordered",
        "fewer-observations",
        "more-repositories",
        "repeated",
        "repeated-commit",
        "length-mismatch",
        "levels-not-increasing",
        "levels-not-from-0",
    ],  # fmt: skip
)
def test_parse_rejects_what_the_schema_cannot_see(doc: dict[str, Any]) -> None:
    with pytest.raises(BenchmarkError):
        parse_benchmark(raw(doc))


def test_parse_rejects_an_invalid_file_without_quoting_it() -> None:
    with pytest.raises(BenchmarkError) as error:
        parse_benchmark(b'{"version": "segreto"}')
    assert "segreto" not in str(error.value)
