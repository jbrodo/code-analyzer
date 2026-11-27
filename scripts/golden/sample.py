"""Estrae un insieme del golden set dai report delle scansioni del corpus (G3-02, ADR-0034).

    uv run python scripts/golden/sample.py --reports CARTELLA [--reports ALTRA] \\
        --set pilota --size 30 --seed pilota-1 [--exclude golden-set/ALTRO.sample.json]

Ogni `CARTELLA/*/code-analyzer.report.json` è un report; deve essere di un commit di
`golden-set/corpus.json`. Il risultato dipende solo da report, filtri (`golden-set/sampling.json`),
seme ed esclusioni: a parità di ingressi il file è identico byte per byte.

Nel campione entrano solo riferimenti. I messaggi dei tool, che possono citare il codice, vanno nel
materiale locale (`--materials`), fuori dal repository: servono a chi annota.
"""

import argparse
import hashlib
import json
import re
import sys
from collections import Counter
from collections.abc import Iterable
from pathlib import Path
from typing import Any

from ca_core.models.golden_set import GoldenSample
from ca_core.scoring.exposure import is_test_path

ROOT = Path(__file__).resolve().parents[2]
GOLDEN = ROOT / "golden-set"
REPORT = "code-analyzer.report.json"


def _key(seed: str, repository: str, fingerprint: str) -> str:
    return hashlib.sha256(f"{seed}\0{repository}\0{fingerprint}".encode()).hexdigest()


def candidates(
    reports: Iterable[dict[str, Any]], corpus: dict[str, str], config: dict[str, Any]
) -> tuple[list[dict[str, Any]], list[str]]:
    """I finding SAST di Python che si possono giudicare. `corpus` va da commit a indirizzo."""
    excluded = set(config["excluded_rules"])
    third_party = re.compile(config["third_party_path"], re.I)
    found, warnings = [], []
    for report in reports:
        commit = report["repository"]["commit"]
        if commit not in corpus:
            raise ValueError(f"il report del commit {commit} non è di un repository del corpus")
        url = corpus[commit]
        for plugin in report["plugins"]:
            if plugin["name"] in ("bandit", "semgrep") and plugin["outcome"] != "ok":
                warnings.append(f"{url}: {plugin['name']} non riuscito, conteggio incompleto")
        for finding in report["findings"]:
            location = finding["location"]
            path = location.get("path") or ""
            if (
                finding["category"] != "sast"
                or not path.endswith(".py")
                or finding["rule_id"] in excluded
                or is_test_path(path)
                or third_party.search(path)
                or not location.get("start_line")
            ):
                continue
            found.append(
                {
                    "repository": url,
                    "commit": commit,
                    "tool": finding["tool"],
                    "rule_id": finding["rule_id"],
                    "path": path,
                    "start_line": location["start_line"],
                    "end_line": location.get("end_line") or location["start_line"],
                    "fingerprint": finding["fingerprint"],
                    "message": finding["message"],
                }
            )
    return found, warnings


def _point(item: dict[str, Any]) -> tuple[str, str, int]:
    return item["repository"], item["path"], item["start_line"]


def pool(found: list[dict[str, Any]], seed: str, cap: int) -> list[dict[str, Any]]:
    """Un finding per punto di codice (più regole sulla stessa riga contano una volta), poi al più
    `cap` per repository e regola. Chi resta lo decide il seme, non l'ordine dei report."""
    ordered = sorted(found, key=lambda i: _key(seed, i["repository"], i["fingerprint"]))
    points: set[tuple[str, str, int]] = set()
    taken: Counter[tuple[str, str]] = Counter()
    kept = []
    for item in ordered:
        if _point(item) in points:
            continue
        points.add(_point(item))
        group = item["repository"], item["rule_id"]
        if taken[group] < cap:
            taken[group] += 1
            kept.append(item)
    return kept


def draw(
    found: list[dict[str, Any]],
    config: dict[str, Any],
    *,
    name: str,
    size: int,
    seed: str,
    used: Iterable[dict[str, Any]] = (),
) -> tuple[GoldenSample, dict[str, str]]:
    """Estrazione uniforme dal bacino, escluso ciò che è in altri insiemi (stesso punto di codice
    compreso). Restituisce il campione e i messaggi, da tenere fuori dal repository."""
    cap = config["cap_per_repository_and_rule"]
    used = list(used)
    seen = {_point(i) for i in used}
    available = [i for i in pool(found, seed, cap) if _point(i) not in seen]
    if len(available) < size:
        raise ValueError(f"nel bacino ci sono {len(available)} punti, ne servono {size}")
    chosen = available[:size]
    sample = GoldenSample.model_validate(
        {
            "version": 1,
            "set": name,
            "language": "python",
            "sampling": {
                "seed": seed,
                "cap_per_repository_and_rule": cap,
                "excluded_rules": config["excluded_rules"],
                "pool_size": len(available),
            },
            "items": [{k: v for k, v in i.items() if k != "message"} for i in chosen],
        }
    )
    return sample, {f"{i['repository']} {i['fingerprint']}": i["message"] for i in chosen}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--reports", type=Path, action="append", required=True)
    parser.add_argument("--set", dest="name", required=True)
    parser.add_argument("--size", type=int, required=True)
    parser.add_argument("--seed", required=True)
    parser.add_argument("--exclude", type=Path, action="append", default=[])
    parser.add_argument("--materials", type=Path, default=Path.home() / "golden-material")
    args = parser.parse_args(argv)
    materials = args.materials.resolve()
    if materials.is_relative_to(ROOT):
        print("errore: il materiale sta fuori dal repository", file=sys.stderr)
        return 2
    target = GOLDEN / f"{args.name}.sample.json"
    if target.exists():
        print(f"errore: {target.name} esiste già: un insieme non si ridisegna", file=sys.stderr)
        return 2
    corpus = json.loads((GOLDEN / "corpus.json").read_text(encoding="utf-8"))["repositories"]
    config = json.loads((GOLDEN / "sampling.json").read_text(encoding="utf-8"))
    paths = sorted(p for folder in args.reports for p in folder.glob(f"*/{REPORT}"))
    try:
        found, warnings = candidates(
            (json.loads(p.read_text(encoding="utf-8")) for p in paths),
            {r["commit"]: r["url"] for r in corpus},
            config,
        )
        used = [
            item
            for path in args.exclude
            for item in json.loads(path.read_text(encoding="utf-8"))["items"]
        ]
        sample, messages = draw(
            found, config, name=args.name, size=args.size, seed=args.seed, used=used
        )
    except ValueError as error:
        print(f"errore: {error}", file=sys.stderr)
        return 2
    for warning in warnings:
        print(f"avviso: {warning}", file=sys.stderr)
    if len(paths) != len(corpus):
        print(f"avviso: {len(paths)} report per {len(corpus)} repository", file=sys.stderr)
    materials.mkdir(parents=True, exist_ok=True)
    (materials / f"messaggi-{args.name}.json").write_text(
        json.dumps(messages, indent=1), encoding="utf-8"
    )
    target.write_text(sample.model_dump_json(indent=1) + "\n", encoding="utf-8")
    repositories = Counter(i.repository.rsplit("/", 1)[1] for i in sample.items)
    print(f"{target.name}: {len(sample.items)} voci da un bacino di {sample.sampling.pool_size}")
    print("per repository:", dict(repositories.most_common()))
    return 0


if __name__ == "__main__":
    sys.exit(main())
