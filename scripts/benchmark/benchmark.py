"""Procedura del benchmark della Variante B (ADR-0023, K-06, D2-11). Solo libreria standard.

Tre comandi:

  collect    clona ogni repository di `corpus.json` al commit fissato e lo scansiona con ruff ed
             eslint in modalità benchmark e con ca-graph; i report vanno in `--work`, FUORI dal
             repository. Va lanciato con il Python della CLI impacchettata da
             `deploy/docker/package-cli.sh` (manifest con i digest veri, immagini firmate sul
             registry locale), che esegue `scan_child.py`. È l'unico passo con la rete (git clone).
  aggregate  dai report scrive `ca_core/scoring/benchmark.json`: per ogni regola con metrica e per
             ogni tipo e ambito di architectural smell, i quantili della miscela a pesi uguali per
             repository ai livelli di `LEVELS`. Nessuna rete, nessun dato oltre ai numeri.
  check      rilegge un `benchmark.json` con il lettore del nucleo.

Ricalcolo solo esplicito: nessuna scansione lo fa da sé (D2-11). I file di test si scartano con
le regole fisse di ADR-0022 (`ca_core.scoring.exposure.is_test_path`, copiate qui perché lo
script non deve importare il nucleo durante `aggregate`; un test le confronta).
"""

import argparse
import json
import subprocess
import sys
from collections import defaultdict
from collections.abc import Iterable, Mapping, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
CORPUS = HERE / "corpus.json"
OUTPUT = ROOT / "packages/ca-core/src/ca_core/scoring/benchmark.json"
REPORT = "code-analyzer.report.json"
# Livelli dei quantili, in centesimi di punto percentuale per evitare errori di arrotondamento:
# ogni 1% fino al 90%, ogni 0,1% fino al 99%, poi ogni 0,01%. Le soglie delle regole stanno tra il
# 94° e il 99,8° percentile, e l'indice di intensità usa solo la coda sopra la soglia (ADR-0023).
LEVELS_HUNDREDTHS = (*range(0, 9000, 100), *range(9000, 9900, 10), *range(9900, 10001))
LEVELS = tuple(t / 100 for t in LEVELS_HUNDREDTHS)
CODE_ENGINES = ("ruff", "eslint")
GRAPH = "ca-graph"
HUB_LIKE = "ca.arch.hub-like-dependency"

# Stesse regole di `ca_core.scoring.exposure.is_test_path` (ADR-0022).
_TEST_DIRS = frozenset({"test", "tests", "testing", "__tests__", "__mocks__"})


def is_test_path(path: str) -> bool:
    *dirs, name = path.casefold().split("/")
    stem = name.rsplit(".", 1)[0]
    return (
        not _TEST_DIRS.isdisjoint(dirs)
        or name == "conftest.py"
        or name.startswith("test_")
        or stem.endswith(("_test", ".test", ".spec"))
    )


# --- osservazioni da un report ------------------------------------------------------------------

CodeKey = tuple[str, str]  # (motore, regola)
SizeKey = tuple[str, str]  # (regola, ambito)


def smell_size(rule_id: str, evidence: Mapping[str, Any]) -> int | None:
    """Dimensione di ADR-0023: per Hub-Like fan-in più fan-out, per gli altri `size`."""
    if rule_id == HUB_LIKE:
        fan_in, fan_out = evidence.get("fan_in"), evidence.get("fan_out")
        if isinstance(fan_in, int) and isinstance(fan_out, int):
            return fan_in + fan_out
        return None
    size = evidence.get("size")
    return size if isinstance(size, int) and not isinstance(size, bool) else None


def observations(
    report: Mapping[str, Any],
) -> tuple[dict[CodeKey, list[float]], dict[SizeKey, list[float]]]:
    """Valori delle metriche e dimensioni degli smell, senza i file di test."""
    code: dict[CodeKey, list[float]] = defaultdict(list)
    sizes: dict[SizeKey, list[float]] = defaultdict(list)
    for finding in report.get("findings", []):
        path = finding.get("location", {}).get("path", "")
        if not isinstance(path, str) or is_test_path(path):
            continue
        tool, rule = finding.get("tool"), finding.get("rule_id")
        evidence = finding.get("evidence", {}).get(tool, {})
        if tool in CODE_ENGINES:
            metric = evidence.get("metric")
            if isinstance(metric, dict) and isinstance(metric.get("value"), int):
                code[(tool, rule)].append(float(metric["value"]))
        elif tool == GRAPH and finding.get("category") == "architecture":
            size = smell_size(rule, evidence)
            scope = evidence.get("scope")
            if size is not None and scope in ("module", "package"):
                sizes[(rule, scope)].append(float(size))
    return dict(code), dict(sizes)


# --- miscela a pesi uguali -----------------------------------------------------------------------


def mixture_quantiles(
    per_repository: Sequence[Sequence[float]], levels: Sequence[int] = LEVELS_HUNDREDTHS
) -> list[float]:
    """Quantili della miscela ai livelli dati (in centesimi di percento): ogni repository pesa
    uguale, dentro ciascuno ogni osservazione pesa `1 / n`. Il quantile al livello p è il più
    piccolo valore con quota cumulata >= p (livello 0: il minimo).
    """
    groups = [sorted(values) for values in per_repository if values]
    if not groups:
        raise ValueError("nessuna osservazione")
    weighted = sorted(
        (value, 1.0 / (len(group) * len(groups))) for group in groups for value in group
    )
    result: list[float] = []
    cumulative, i = 0.0, 0
    for p in levels:
        target = p / 10000
        if p == 0:
            result.append(weighted[0][0])
            continue
        while i < len(weighted) and cumulative + weighted[i][1] < target - 1e-12:
            cumulative += weighted[i][1]
            i += 1
        result.append(weighted[min(i, len(weighted) - 1)][0])
    return result


def _distribution(groups: Sequence[Sequence[float]]) -> dict[str, Any]:
    present = [g for g in groups if g]
    return {
        "repositories": len(present),
        "observations": sum(len(g) for g in present),
        "quantiles": mixture_quantiles(present),
    }


def build(
    reports: Mapping[str, Mapping[str, Any]],
    corpus: Sequence[Mapping[str, Any]],
    engines: Mapping[str, str],
    *,
    version: int,
    created_at: datetime,
) -> dict[str, Any]:
    """Il documento `scoring-benchmark` dai report, uno per URL del corpus."""
    missing = [r["url"] for r in corpus if r["url"] not in reports]
    if missing:
        raise ValueError(f"report mancanti: {', '.join(missing)}")
    code: dict[CodeKey, list[list[float]]] = defaultdict(list)
    sizes: dict[SizeKey, list[list[float]]] = defaultdict(list)
    for entry in corpus:
        report_code, report_sizes = observations(reports[entry["url"]])
        for key, values in report_code.items():
            code[key].append(values)
        for key, values in report_sizes.items():
            sizes[key].append(values)
    return {
        "version": version,
        "created_at": created_at.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "levels": list(LEVELS),
        "corpus": [{"url": r["url"], "commit": r["commit"], "tag": r.get("tag")} for r in corpus],
        "engines": dict(sorted(engines.items())),
        "code_metrics": [
            {"engine": engine, "rule_id": rule, **_distribution(groups)}
            for (engine, rule), groups in sorted(code.items())
        ],
        "smell_sizes": [
            {"rule_id": rule, "scope": scope, **_distribution(groups)}
            for (rule, scope), groups in sorted(sizes.items())
        ],
    }


def engines_of(reports: Iterable[Mapping[str, Any]]) -> dict[str, str]:
    """Versione dei plugin che hanno misurato, uguale in tutti i report o errore."""
    found: dict[str, set[str]] = defaultdict(set)
    for report in reports:
        for run in report.get("plugins", []):
            if run.get("name") in (*CODE_ENGINES, GRAPH) and run.get("outcome") == "ok":
                found[run["name"]].add(str(run.get("version")))
    mixed = {name: v for name, v in found.items() if len(v) != 1}
    if mixed:
        raise ValueError(f"versioni diverse tra i report: {sorted(mixed)}")
    return {name: next(iter(v)) for name, v in found.items()}


# --- comandi -------------------------------------------------------------------------------------


def load_corpus(path: Path = CORPUS) -> list[dict[str, Any]]:
    repositories: list[dict[str, Any]] = json.loads(path.read_text())["repositories"]
    return repositories


def slug(url: str) -> str:
    return url.removeprefix("https://github.com/").replace("/", "__")


def _git(*args: str, cwd: Path | None = None) -> str:
    done = subprocess.run(["git", *args], cwd=cwd, capture_output=True, text=True, check=True)
    return done.stdout.strip()


def usable(report: Mapping[str, Any]) -> str | None:
    """`None` se il report vale per il benchmark, altrimenti il motivo.

    Conta l'esito dei plugin, non lo stato della scansione: un collegamento simbolico non seguito
    rende la scansione `partial` (saleor ne ha due) senza togliere nulla alle misure degli altri.
    """
    runs = {r.get("name"): r.get("outcome") for r in report.get("plugins", [])}
    if runs.get(GRAPH) != "ok" or not any(runs.get(e) == "ok" for e in CODE_ENGINES):
        return f"plugin del benchmark non riusciti: {sorted(runs.items())}"
    failed = [name for name, outcome in runs.items() if outcome not in ("ok", "skipped")]
    return f"plugin falliti: {failed}" if failed else None


def collect(work: Path, python: str, only: Sequence[str]) -> int:
    work = work.resolve()
    if work == ROOT or ROOT in work.parents:
        print("errore: --work deve stare fuori dal repository", file=sys.stderr)
        return 2
    for entry in load_corpus():
        name = slug(entry["url"])
        if only and name not in only:
            continue
        source, out = work / "src" / name, work / "out" / name
        if (out / REPORT).is_file() and usable(json.loads((out / REPORT).read_text())) is None:
            print(f"{name}: già misurato", file=sys.stderr)
            continue
        if not source.exists():
            _git("clone", "-q", "--depth", "1", "--branch", entry["tag"], entry["url"], str(source))
        head = _git("rev-parse", "HEAD", cwd=source)
        if head != entry["commit"]:
            print(f"errore: {name} è a {head}, atteso {entry['commit']}", file=sys.stderr)
            return 2
        out.mkdir(parents=True, exist_ok=True)
        started = datetime.now(UTC)
        done = subprocess.run(
            [python, str(HERE / "scan_child.py"), str(source), str(out)],
            stdout=subprocess.DEVNULL,
            check=False,
        )
        seconds = (datetime.now(UTC) - started).total_seconds()
        print(f"{name}: uscita {done.returncode}, {seconds:.0f} s", file=sys.stderr)
        if done.returncode != 0:
            return done.returncode
        report = json.loads((out / REPORT).read_text())
        problem = usable(report)
        if problem:
            print(f"errore: {name}: {problem}", file=sys.stderr)
            return 2
        warnings = sorted({w["code"] for w in report.get("warnings", [])})
        print(f"{name}: {report['status']}, avvisi {warnings}", file=sys.stderr)
    return 0


def aggregate(work: Path, version: int, output: Path) -> int:
    corpus = load_corpus()
    reports = {
        e["url"]: json.loads((work / "out" / slug(e["url"]) / REPORT).read_text()) for e in corpus
    }
    document = build(
        reports, corpus, engines_of(reports.values()), version=version,
        created_at=datetime.now(UTC),
    )  # fmt: skip
    output.write_text(json.dumps(document, indent=1) + "\n")
    for metric in document["code_metrics"]:
        q = metric["quantiles"]
        print(f"{metric['engine']} {metric['rule_id']}: {metric['observations']} osservazioni, "
              f"mediana {q[LEVELS.index(50)]}, 99% {q[LEVELS.index(99)]}, max {q[-1]}",
              file=sys.stderr)  # fmt: skip
    for size in document["smell_sizes"]:
        q = size["quantiles"]
        print(f"{size['rule_id']} {size['scope']}: {size['observations']} smell, "
              f"mediana {q[LEVELS.index(50)]}, max {q[-1]}", file=sys.stderr)  # fmt: skip
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    sub = parser.add_subparsers(dest="command", required=True)
    c = sub.add_parser("collect")
    c.add_argument("--work", type=Path, required=True, help="cartella fuori dal repository")
    c.add_argument("--python", required=True, help="Python della CLI impacchettata")
    c.add_argument("--only", nargs="*", default=[], help="solo questi repository (owner__nome)")
    a = sub.add_parser("aggregate")
    a.add_argument("--work", type=Path, required=True)
    a.add_argument("--version", type=int, required=True, help="nuova versione del benchmark")
    a.add_argument("--output", type=Path, default=OUTPUT)
    k = sub.add_parser("check")
    k.add_argument("file", type=Path, nargs="?", default=OUTPUT)
    args = parser.parse_args(argv)
    if args.command == "collect":
        return collect(args.work, args.python, args.only)
    if args.command == "aggregate":
        return aggregate(args.work, args.version, args.output)
    from ca_core.scoring.benchmark import load_benchmark  # solo qui: serve il nucleo

    print(load_benchmark(args.file.read_bytes()).version)
    return 0


if __name__ == "__main__":
    sys.exit(main())
