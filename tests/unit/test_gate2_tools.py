"""X-02, X-03, X-04: gli strumenti del Gate 2 fanno ciò che dice il protocollo (dati finti)."""

import importlib.util
import json
import random
from pathlib import Path

import pytest

SOURCE = Path(__file__).resolve().parents[2] / "scripts/gate2/gate2.py"
spec = importlib.util.spec_from_file_location("gate2", SOURCE)
assert spec is not None and spec.loader is not None
gate2 = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate2)


def finding(
    n: int, category: str = "sast", level: str = "alto", a: float = 10, b: float = 10, **kv
):
    return {
        "fingerprint": f"sha256:{n:064x}", "category": category, "level": level, "status": "aperto",
        "title": f"t{n}", "rule_id": f"r{n}", "message": f"m{n}",
        "location": {"path": f"f{n}.py", "start_line": n},
        "variant_scores": [
            {"variant": "A", "score": a, "level": level},
            {"variant": "B", "score": b, "level": level},
        ],
        **kv,
    }  # fmt: skip


def report(findings, **kv):
    return {"status": "complete", "findings": findings, "exceptions": [], **kv}


# --- tau-b: valori calcolati a mano --------------------------------------------------------------


def test_tau_b_of_identical_reversed_and_unrelated_orders() -> None:
    assert gate2.kendall_tau_b([1, 2, 3, 4], [1, 2, 3, 4]) == 1.0
    assert gate2.kendall_tau_b([1, 2, 3, 4], [4, 3, 2, 1]) == -1.0
    # 4 elementi, una sola coppia scambiata: 5 concordanti, 1 discordante → (5-1)/6
    assert gate2.kendall_tau_b([1, 2, 3, 4], [1, 2, 4, 3]) == pytest.approx(4 / 6)


def test_tau_b_accounts_for_ties_on_both_sides() -> None:
    # x = 1,1,2,3  y = 1,2,2,3: coppie: (0,1) x pari; (0,2) conc; (0,3) conc; (1,2) y pari;
    # (1,3) conc; (2,3) conc → C=4, D=0, Tx=1, Ty=1 → 4/sqrt(5*5)=0.8
    assert gate2.kendall_tau_b([1, 1, 2, 3], [1, 2, 2, 3]) == pytest.approx(0.8)
    assert gate2.kendall_tau_b([1, 1, 1], [1, 2, 3]) is None  # tutto pari da un lato: indefinito


# --- sovrapposizione sui primi k -----------------------------------------------------------------


def test_top_overlap_resolves_ties_at_the_border_by_fingerprint_on_both_sides() -> None:
    user = {"a": 1, "b": 2, "c": 3, "d": 3, "e": 5}  # c e d pari al confine del top 3
    other = {"a": 1, "b": 2, "c": 3, "d": 3, "e": 5}
    assert gate2.top_overlap(user, other, 3) == 3  # stesso criterio: c prima di d da entrambi
    other_reversed = {"a": 1, "b": 2, "d": 2.5, "c": 3, "e": 5}  # qui d precede c davvero
    assert gate2.top_overlap(user, other_reversed, 3) == 2
    assert gate2.top_overlap({"a": 1, "b": 2, "c": 3}, {"x": 1, "y": 2, "z": 3}, 3) == 0


# --- campione ----------------------------------------------------------------------------------


def test_the_sample_excludes_health_excepted_duplicates_and_non_open() -> None:
    items = [finding(i) for i in range(1, 6)]
    items += [finding(6, category="health"), finding(7, status="risolto"), finding(1)]  # duplicato
    rep = report(items, exceptions=[{"fingerprint": finding(2)["fingerprint"]}])
    pool = gate2.eligible(rep)
    assert [f["title"] for f in pool] == ["t1", "t3", "t4", "t5"]


def test_the_sample_is_stratified_proportional_with_at_least_one_per_stratum_and_reproducible() -> (
    None
):
    items = [finding(i, "sast", "alto") for i in range(1, 61)]
    items += [finding(100 + i, "dependency", "critico") for i in range(1, 31)]
    items += [finding(200, "license", "basso")]  # uno strato piccolo ma non vuoto
    sample = gate2.make_sample(report(items), seed=42, size=30)
    assert sample["size"] == 30 and sample["eligible"] == 91
    strata = sample["strata"]
    assert strata["license|basso"] == 1 and strata["sast|alto"] > strata["dependency|critico"] > 1
    assert gate2.make_sample(report(items), seed=42)["items"] == sample["items"]  # stesso seme
    assert gate2.make_sample(report(items), seed=43)["items"] != sample["items"]


def test_with_fewer_than_thirty_all_are_taken() -> None:
    sample = gate2.make_sample(report([finding(i) for i in range(1, 12)]), seed=1)
    assert sample["size"] == 11 and sample["eligible"] == 11


def test_the_material_shows_no_score_level_severity_or_variant(tmp_path: Path) -> None:
    sample = gate2.make_sample(
        report([finding(i, level="critico", a=99.5, b=77.7) for i in range(1, 6)]), seed=1
    )
    gate2.write_sample(sample, tmp_path, "r1")
    text = (
        (tmp_path / "valutazione-r1.md").read_text().split("\n## ", 1)[1]
    )  # i finding, non le istruzioni
    for forbidden in ("critico", "99.5", "77.7", "score", "variant", "livello", "severit"):
        assert forbidden not in text.lower().replace("severità", ""), forbidden
    assert "Posizione: f" in text and "Categoria: sast" in text
    assert (tmp_path / "chiave-r1.json").exists() and (
        tmp_path / "ordinamento-r1.csv"
    ).read_text().startswith("n,rank")


def test_the_sample_refuses_to_write_inside_the_repository() -> None:
    inside = Path(__file__).resolve().parents[2] / "materiale"
    assert (
        gate2.main(["sample", "--report", "x", "--name", "n", "--seed", "1", "--out", str(inside)])
        == 2
    )


# --- valutazione ---------------------------------------------------------------------------------


def test_the_evaluation_compares_the_user_with_a_b_and_the_provisional_levels(
    tmp_path: Path,
) -> None:
    rows = [("critico", 90, 10), ("alto", 70, 20), ("medio", 40, 70), ("basso", 5, 90)]
    findings = [finding(i, level=lvl, a=a, b=b) for i, (lvl, a, b) in enumerate(rows, start=1)]
    rep = report(findings)
    key = {"items": [{"n": n, "fingerprint": f["fingerprint"]} for n, f in enumerate(findings, 1)]}
    user_like_a = {1: 1, 2: 2, 3: 3, 4: 4}
    result = gate2.evaluate(rep, key, user_like_a)
    assert (
        result["A"]["tau_b"] == 1.0
        and result["B"]["tau_b"] < 0
        and result["provvisorio"]["tau_b"] == 1.0
    )
    assert result["best_variant"] == "A" and result["top"] == 2 and result["overlap_needed"] == 2
    assert result["A"]["overlap"] == 2 and result["passes"] is True
    opposed = gate2.evaluate(rep, key, {1: 4, 2: 3, 3: 2, 4: 1})
    assert opposed["B"]["tau_b"] > 0 and opposed["best_variant"] == "B"


def test_the_threshold_needs_tau_and_overlap_on_a_full_sample() -> None:
    rng = random.Random(3)
    findings = [finding(i, a=float(i), b=float(100 - i)) for i in range(1, 31)]
    key = {"items": [{"n": n, "fingerprint": f["fingerprint"]} for n, f in enumerate(findings, 1)]}
    perfect = {
        n: 31 - n for n in range(1, 31)
    }  # il più urgente è quello con il punteggio più alto di A
    result = gate2.evaluate(report(findings), key, perfect)
    assert result["top"] == 10 and result["overlap_needed"] == 6 and result["passes"] is True
    noise = {n: rng.random() for n in range(1, 31)}
    assert gate2.evaluate(report(findings), key, noise)["passes"] is False


def test_stats_counts_g2a_and_the_level_changes() -> None:
    findings = [finding(1, level="alto"), finding(2, level="alto"), finding(3, level="medio")]
    findings[1]["variant_scores"][0]["level"] = "medio"  # A abbassa uno
    findings[2]["variant_scores"] = [findings[2]["variant_scores"][0]]  # senza B
    out = gate2.stats(report(findings))
    assert out["g2a_with_both_variants"] == 2 and out["g2a_percent"] == pytest.approx(66.67)
    assert out["changes"]["provisional_to_A"]["changed"] == 1
    assert out["changes"]["provisional_to_A"]["matrix"] == {"alto->medio": 1}
    json.dumps(out, default=dict)  # serializzabile
