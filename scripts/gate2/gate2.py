"""Strumenti del Gate 2 (X-02, X-03, X-04; protocollo in `doc/verifiche/gate-2.md`).

Tre comandi, solo libreria standard, su report `code-analyzer.report.json` che restano **fuori dal
repository** (i repository del gate sono riservati):

  stats   conteggi per X-02: G2.a, livelli provvisori, di A e di B, quanti cambiano
  sample  il campione stratificato e il materiale alla cieca (senza punteggi né variante)
  score   tau-b di Kendall e sovrapposizione sui primi 10, utente contro varianti

Mai stampare o scrivere nel repository percorsi, messaggi o regole di un repository riservato: i
comandi scrivono dove dice `--out`, fuori dal repository, e `stats` stampa solo conteggi.
"""

import argparse
import csv
import json
import math
import random
import sys
from collections import Counter, defaultdict
from collections.abc import Sequence
from pathlib import Path
from typing import Any

LEVELS = ("critico", "alto", "medio", "basso")
RANK = {name: i for i, name in enumerate(LEVELS)}
SAMPLE_SIZE = 30
TOP = 10
TAU_MIN, OVERLAP_MIN = 0.5, 6


def load(path: str | Path) -> dict[str, Any]:
    return json.loads(Path(path).read_text())  # type: ignore[no-any-return]


def variant(finding: dict[str, Any], name: str) -> dict[str, Any] | None:
    return next((v for v in finding.get("variant_scores") or [] if v["variant"] == name), None)


def provisional_level(finding: dict[str, Any]) -> str | None:
    """Il livello provvisorio di ADR-0009: con `levels.source: provisional` è `level`."""
    return finding.get("level")  # type: ignore[no-any-return]


# --- stats (X-02) --------------------------------------------------------------------------------


def stats(report: dict[str, Any]) -> dict[str, Any]:
    findings = report["findings"]
    both = [f for f in findings if variant(f, "A") and variant(f, "B")]
    out: dict[str, Any] = {
        "status": report["status"],
        "findings": len(findings),
        "g2a_with_both_variants": len(both),
        "g2a_percent": round(100 * len(both) / len(findings), 2) if findings else None,
        "scoring": report.get("scoring"),
        "provisional": Counter(provisional_level(f) or "senza" for f in findings),
        "A": Counter((variant(f, "A") or {}).get("level", "senza") for f in findings),
        "B": Counter((variant(f, "B") or {}).get("level", "senza") for f in findings),
    }
    changes: dict[str, Any] = {}
    for label, pairs in (
        (
            "provisional_to_A",
            [(provisional_level(f), (variant(f, "A") or {}).get("level")) for f in both],
        ),
        (
            "provisional_to_B",
            [(provisional_level(f), (variant(f, "B") or {}).get("level")) for f in both],
        ),
        (
            "A_to_B",
            [((variant(f, "A") or {})["level"], (variant(f, "B") or {})["level"]) for f in both],
        ),
    ):
        moved = [(a, b) for a, b in pairs if a != b]
        changes[label] = {
            "changed": len(moved),
            "percent": round(100 * len(moved) / len(pairs), 2) if pairs else None,
            "matrix": {f"{a}->{b}": n for (a, b), n in sorted(Counter(moved).items(), key=str)},
        }
    out["changes"] = changes
    fallbacks = sum(
        1
        for f in both
        if any(
            c in json.dumps(variant(f, "B"))
            for c in ("variante-b-non-definita", "variante-b-non-configurata")
        )
    )
    out["B_fallback_to_A"] = fallbacks
    out["by_category"] = {
        cat: dict(
            Counter(f"{provisional_level(f)}/{(variant(f, 'A') or {}).get('level')}" for f in group)
        )
        for cat, group in _by(findings, lambda f: f["category"]).items()
    }
    return out


def _by(items: Sequence[dict[str, Any]], key: Any) -> dict[str, list[dict[str, Any]]]:
    groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for item in items:
        groups[key(item)].append(item)
    return dict(groups)


# --- sample (X-03) -------------------------------------------------------------------------------


def eligible(report: dict[str, Any]) -> list[dict[str, Any]]:
    excepted = {e["fingerprint"] for e in report.get("exceptions") or []}
    seen: set[str] = set()
    out = []
    for f in sorted(report["findings"], key=lambda f: f["fingerprint"]):
        if f["fingerprint"] in seen or f["fingerprint"] in excepted or f["category"] == "health":
            continue
        if f.get("status", "aperto") != "aperto":
            continue
        seen.add(f["fingerprint"])
        out.append(f)
    return out


def stratified(
    findings: Sequence[dict[str, Any]], size: int, rng: random.Random
) -> list[dict[str, Any]]:
    """Quote proporzionali per (categoria, livello provvisorio), almeno uno per strato non vuoto."""
    if len(findings) <= size:
        return list(findings)
    strata = _by(findings, lambda f: f"{f['category']}|{provisional_level(f)}")
    quota = {k: max(1, round(size * len(v) / len(findings))) for k, v in strata.items()}
    while sum(quota.values()) > size:  # tolti dagli strati più grandi, mai sotto uno
        biggest = max((k for k in quota if quota[k] > 1), key=lambda k: (quota[k], k))
        quota[biggest] -= 1
    while sum(quota.values()) < size:  # aggiunti dove c'è ancora da prendere
        room = [k for k in strata if quota[k] < len(strata[k])]
        quota[max(room, key=lambda k: (len(strata[k]) - quota[k], k))] += 1
    chosen: list[dict[str, Any]] = []
    for key in sorted(strata):
        chosen += rng.sample(strata[key], min(quota[key], len(strata[key])))
    return chosen


def make_sample(report: dict[str, Any], seed: int, size: int = SAMPLE_SIZE) -> dict[str, Any]:
    pool = eligible(report)
    rng = random.Random(seed)  # noqa: S311 - un seme registrato, non un segreto
    chosen = stratified(pool, size, rng)
    order = chosen[:]
    rng.shuffle(order)  # ordine casuale di presentazione
    return {
        "seed": seed,
        "eligible": len(pool),
        "size": len(order),
        "strata": dict(Counter(f"{f['category']}|{provisional_level(f)}" for f in order)),
        "items": [{"n": i + 1, "fingerprint": f["fingerprint"]} for i, f in enumerate(order)],
        "findings": order,
    }


def write_sample(sample: dict[str, Any], out: Path, name: str) -> None:
    """`valutazione-<name>.md` (senza punteggi, livelli né variante), `chiave-<name>.json` e il
    modello `ordinamento-<name>.csv` da riempire. Fuori dal repository."""
    out.mkdir(parents=True, exist_ok=True)
    lines = [
        f"# Valutazione alla cieca — {name}",
        "",
        "Ordina i finding dal più urgente da correggere (1) al meno urgente. Pari merito ammessi:",
        "stesso numero. Compila `ordinamento-"
        + name
        + ".csv` (colonna `rank`) **prima** di vedere qualunque punteggio e non",
        "modificarlo dopo. Qui non ci sono livelli, severità, punteggi né varianti.",
        "",
    ]
    for item, f in zip(sample["items"], sample["findings"], strict=True):
        loc = f["location"]
        where = (loc.get("path") or loc.get("purl") or "—") + (
            f":{loc['start_line']}" if loc.get("start_line") else ""
        )
        lines += [
            f"## {item['n']}. {f['title']}",
            f"- Categoria: {f['category']}",
            f"- Regola: {f['rule_id']}",
            f"- Posizione: {where}",
            f"- Messaggio: {f['message'][:500]}",
            "",
        ]
    (out / f"valutazione-{name}.md").write_text("\n".join(lines))
    key = {k: sample[k] for k in ("seed", "eligible", "size", "strata", "items")}
    (out / f"chiave-{name}.json").write_text(json.dumps(key, indent=1))
    with (out / f"ordinamento-{name}.csv").open("w", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(["n", "rank"])
        writer.writerows([[item["n"], ""] for item in sample["items"]])


# --- score (X-04) --------------------------------------------------------------------------------


def kendall_tau_b(x: Sequence[float], y: Sequence[float]) -> float | None:
    """tau-b di Kendall, con i pari merito su entrambi i lati. `None` se uno è tutto pari."""
    concordant = discordant = tied_x = tied_y = 0
    n = len(x)
    for i in range(n):
        for j in range(i + 1, n):
            dx, dy = x[i] - x[j], y[i] - y[j]
            if dx == 0 and dy == 0:
                continue
            if dx == 0:
                tied_x += 1
            elif dy == 0:
                tied_y += 1
            elif (dx > 0) == (dy > 0):
                concordant += 1
            else:
                discordant += 1
    denominator = math.sqrt((concordant + discordant + tied_x) * (concordant + discordant + tied_y))
    return None if denominator == 0 else (concordant - discordant) / denominator


def top_overlap(user: dict[str, float], other: dict[str, float], k: int) -> int:
    """Quanti dei primi `k` dell'utente sono nei primi `k` dell'altro: pari al confine risolti
    con l'ordine del fingerprint, su entrambi i lati. Un rango più piccolo è più urgente."""

    def top(ranks: dict[str, float]) -> set[str]:
        return set(sorted(ranks, key=lambda fp: (ranks[fp], fp))[:k])

    return len(top(user) & top(other))


def evaluate(
    report: dict[str, Any], key: dict[str, Any], ranking: dict[int, float]
) -> dict[str, Any]:
    by_fp = {f["fingerprint"]: f for f in report["findings"]}
    fps = [item["fingerprint"] for item in key["items"] if item["n"] in ranking]
    user = {
        fp: ranking[item["n"]]
        for item in key["items"]
        for fp in [item["fingerprint"]]
        if item["n"] in ranking
    }
    size = len(fps)
    k = TOP if size >= SAMPLE_SIZE else math.ceil(size / 3)
    need = OVERLAP_MIN if size >= SAMPLE_SIZE else math.ceil(k * 0.6)
    scores = {
        "A": {fp: -(variant(by_fp[fp], "A") or {}).get("score", 0.0) for fp in fps},
        "B": {fp: -(variant(by_fp[fp], "B") or {}).get("score", 0.0) for fp in fps},
        "provvisorio": {
            fp: float(RANK.get(provisional_level(by_fp[fp]) or "basso", 3)) for fp in fps
        },
    }
    out: dict[str, Any] = {"size": size, "top": k, "overlap_needed": need}
    for name, ranks in scores.items():
        tau = kendall_tau_b([user[fp] for fp in fps], [ranks[fp] for fp in fps])
        overlap = top_overlap(user, ranks, k)
        out[name] = {"tau_b": None if tau is None else round(tau, 3), "overlap": overlap}
    best = max(
        ("A", "B"),
        key=lambda v: (out[v]["tau_b"] if out[v]["tau_b"] is not None else -2, out[v]["overlap"]),
    )
    tau_best = out[best]["tau_b"]
    out["best_variant"] = best
    out["passes"] = tau_best is not None and tau_best >= TAU_MIN and out[best]["overlap"] >= need
    return out


def read_ranking(path: str | Path) -> dict[int, float]:
    ranks: dict[int, float] = {}
    with Path(path).open(newline="") as handle:
        for row in csv.DictReader(handle):
            if row["rank"].strip() != "":
                ranks[int(row["n"])] = float(row["rank"])
    return ranks


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    commands = parser.add_subparsers(dest="command", required=True)
    s = commands.add_parser("stats")
    s.add_argument("report", nargs="+")
    m = commands.add_parser("sample")
    m.add_argument("--report", required=True)
    m.add_argument("--name", required=True)
    m.add_argument("--seed", type=int, required=True)
    m.add_argument("--size", type=int, default=SAMPLE_SIZE)
    m.add_argument("--out", required=True, help="cartella FUORI dal repository")
    c = commands.add_parser("score")
    c.add_argument("--report", required=True)
    c.add_argument("--key", required=True)
    c.add_argument("--ranking", required=True)
    args = parser.parse_args(argv)
    if args.command == "stats":
        for path in args.report:
            print(
                json.dumps(
                    {"report": Path(path).parent.name, **stats(load(path))},
                    ensure_ascii=False,
                    indent=1,
                    default=dict,
                )
            )
        return 0
    if args.command == "sample":
        out = Path(args.out).resolve()
        if (
            Path(__file__).resolve().parents[2] in out.parents
            or out == Path(__file__).resolve().parents[2]
        ):
            print("errore: la cartella di uscita sta dentro il repository", file=sys.stderr)
            return 2
        sample = make_sample(load(args.report), args.seed, args.size)
        write_sample(sample, out, args.name)
        print(json.dumps({k: sample[k] for k in ("seed", "eligible", "size", "strata")}, indent=1))
        return 0
    key = json.loads(Path(args.key).read_text())
    print(json.dumps(evaluate(load(args.report), key, read_ranking(args.ranking)), indent=1))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
