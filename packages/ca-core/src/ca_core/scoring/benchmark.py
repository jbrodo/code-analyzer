"""Lettura della distribuzione di benchmark della Variante B (ADR-0023, K-06). Nessun I/O oltre
alla lettura del dato del pacchetto.

`cdf` è la funzione di ripartizione ricostruita dai quantili ai livelli del file: la quota di
osservazioni con valore minore o uguale a `x`, interpolata linearmente tra due quantili diversi.
Con valori interi molti quantili coincidono: un valore pari a un gradino prende il punto più alto
del gradino, come la funzione di ripartizione empirica (continua a destra).
"""

import hashlib
from bisect import bisect_right
from collections.abc import Sequence
from dataclasses import dataclass
from importlib import resources

from pydantic import ValidationError

from ca_core.models.scoring_benchmark import Distribution, ScoringBenchmark

BENCHMARK_FILE = "benchmark.json"
MAX_BYTES = 1024 * 1024


class BenchmarkError(ValueError):
    """Il file non è una distribuzione di benchmark valida; il messaggio non cita il contenuto."""


def cdf(distribution: Distribution, levels: Sequence[float], x: float) -> float:
    """Quota stimata di osservazioni `<= x`, in [0, 1]. `levels` in percentuale, come nel file."""
    q = distribution.quantiles
    if x < q[0]:
        return 0.0
    if x >= q[-1]:
        return 1.0
    i = bisect_right(q, x) - 1  # ultimo quantile <= x; q[i] <= x < q[i + 1]
    low, high = q[i], q[i + 1]
    share = levels[i] + (levels[i + 1] - levels[i]) * (x - low) / (high - low)
    return share / 100.0


def _check(benchmark: ScoringBenchmark) -> None:
    levels = benchmark.levels
    rising = all(a < b for a, b in zip(levels, levels[1:], strict=False))
    if levels[0] != 0 or levels[-1] != 100 or not rising:
        raise BenchmarkError("livelli non crescenti da 0 a 100")
    distributions: list[Distribution] = [*benchmark.code_metrics, *benchmark.smell_sizes]
    for d in distributions:
        if len(d.quantiles) != len(levels):
            raise BenchmarkError("quantili e livelli di lunghezza diversa")
        if any(a > b for a, b in zip(d.quantiles, d.quantiles[1:], strict=False)):
            raise BenchmarkError("quantili non ordinati")
        if d.observations < d.repositories:
            raise BenchmarkError("meno osservazioni che repository")
        if d.repositories > len(benchmark.corpus):
            raise BenchmarkError("più repository del corpus")
    metrics = [(m.engine, m.rule_id) for m in benchmark.code_metrics]
    sizes = [(s.rule_id, s.scope) for s in benchmark.smell_sizes]
    if len(set(metrics)) != len(metrics) or len(set(sizes)) != len(sizes):
        raise BenchmarkError("distribuzione ripetuta")
    commits = [r.commit for r in benchmark.corpus]
    if len(set(commits)) != len(commits):
        raise BenchmarkError("repository ripetuto nel corpus")


def parse_benchmark(raw: bytes) -> ScoringBenchmark:
    if len(raw) > MAX_BYTES:
        raise BenchmarkError("distribuzione di benchmark troppo grande")
    try:
        benchmark = ScoringBenchmark.model_validate_json(raw)
    except ValidationError as exc:
        raise BenchmarkError(
            f"distribuzione di benchmark non valida ({exc.error_count()} errori)"
        ) from exc
    _check(benchmark)
    return benchmark


@dataclass(frozen=True)
class LoadedBenchmark:
    benchmark: ScoringBenchmark
    version: str  # "<version>+<primi 12 caratteri dello SHA-256>", come `config_version`

    def cdf(self, distribution: Distribution, x: float) -> float:
        return cdf(distribution, self.benchmark.levels, x)

    def code_metric(self, engine: str, rule_id: str) -> Distribution | None:
        return next(
            (m for m in self.benchmark.code_metrics if (m.engine, m.rule_id) == (engine, rule_id)),
            None,
        )

    def smell_size(self, rule_id: str, scope: str) -> Distribution | None:
        return next(
            (s for s in self.benchmark.smell_sizes if (s.rule_id, s.scope) == (rule_id, scope)),
            None,
        )


def load_benchmark(raw: bytes) -> LoadedBenchmark:
    benchmark = parse_benchmark(raw)
    digest = hashlib.sha256(raw).hexdigest()[:12]
    return LoadedBenchmark(benchmark, f"{benchmark.version}+{digest}")


def packaged_bytes() -> bytes | None:
    """Il dato del pacchetto, o `None` finché K-06 non l'ha prodotto."""
    path = resources.files("ca_core.scoring").joinpath(BENCHMARK_FILE)
    return path.read_bytes() if path.is_file() else None
