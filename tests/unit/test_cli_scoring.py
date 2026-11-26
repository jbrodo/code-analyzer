"""K-15, E-06, L-02: punteggi in ombra, contesto del servizio e feed nella `scan` (nessuna rete)."""

import dataclasses
import json
from pathlib import Path
from typing import Any

import pytest
from test_cli_scan_gate import Env, load
from test_enrichment import LIMITS, FakeFetcher, epss_file, kev_file

from ca_cli.main import main
from ca_core.fakes import FakePluginExecutor
from ca_core.scoring.config import default_bytes


@pytest.fixture
def env(tmp_path: Path) -> Env:
    return Env(tmp_path)


def run_scan(env: Env, *flags: str, fetcher: FakeFetcher | None = None) -> int:
    context = env.context(FakePluginExecutor({"bandit": env.ok()}))
    if fetcher is not None:
        context = dataclasses.replace(context, enrichment_fetcher=fetcher, enrichment_limits=LIMITS)
    return env.scan(context, *flags)


def scoring_file(env: Env, **patch: Any) -> Path:
    data = json.loads(default_bytes())
    for key, value in patch.items():
        node = data
        *parents, last = key.split("__")
        for part in parents:
            node = node[part]
        node[last] = value
    path = env.tmp / "scoring.json"
    path.write_text(json.dumps(data))
    return path


def finding_of(env: Env) -> dict[str, Any]:
    (found,) = load(env)["findings"]
    return found


# --- ombra: il livello non cambia -------------------------------------------------------------


def test_by_default_both_variants_are_recorded_and_the_level_is_the_provisional_one(
    env: Env,
) -> None:
    assert run_scan(env) == 0
    report, found = load(env), finding_of(env)
    assert report["scoring"]["active_variant"] == "A" and report["scoring"]["shadow"] is True
    assert report["scoring"]["config_version"].startswith("2+")
    assert [v["variant"] for v in found["variant_scores"]] == ["A", "B"]
    assert found["level"] == "alto" and found["level_source"] == "tool_severity"
    assert found["score"] == found["variant_scores"][0]["score"]
    assert found["impact"]["variant"] == "A"
    assert report["inert_sections"] == []


def test_without_a_graph_or_feeds_the_report_says_which_data_was_missing(env: Env) -> None:
    assert run_scan(env) == 0
    report = load(env)
    codes = [(w["code"], w.get("subject")) for w in report["warnings"]]
    assert ("enrichment-feed-missing", "epss") in codes and (
        "enrichment-feed-missing",
        "kev",
    ) in codes
    assert ("scoring-with-fallbacks", None) not in codes  # un finding SAST non usa i feed
    evidence = finding_of(env)["impact"]["evidence"]
    assert evidence["e"]["reason"] == "grafo-assente" and evidence["e"]["reachability"] == "ignota"
    assert report["enrichment"] == []


def test_the_gate_is_unchanged_by_scoring_in_shadow(
    env: Env, capsys: pytest.CaptureFixture[str]
) -> None:
    assert run_scan(env) == 0
    assert main(["gate", "--report", str(env.out / "code-analyzer.report.json")]) == 1


# --- configurazione di scoring ---------------------------------------------------------------


def test_a_scoring_config_can_make_the_score_decide_the_level(env: Env) -> None:
    config = scoring_file(env, levels__source="score")
    assert run_scan(env, "--scoring-config", str(config)) == 0
    found = finding_of(env)
    assert found["level_source"] in ("score", "override")
    assert found["level"] == found["variant_scores"][0]["level"]


def test_the_env_var_is_read_and_the_flag_wins(env: Env, monkeypatch: pytest.MonkeyPatch) -> None:
    on_score = scoring_file(env, levels__source="score")
    monkeypatch.setenv("CA_SCORING_CONFIG", str(on_score))
    assert run_scan(env) == 0 and finding_of(env)["level_source"] in ("score", "override")
    shadow = env.tmp / "shadow.json"
    shadow.write_bytes(default_bytes())
    assert run_scan(env, "--scoring-config", str(shadow)) == 0
    assert finding_of(env)["level_source"] == "tool_severity"


def test_a_scoring_config_inside_the_repository_is_refused(
    env: Env, capsys: pytest.CaptureFixture[str]
) -> None:
    inside = env.repo / "scoring.json"
    inside.write_bytes(default_bytes())
    assert run_scan(env, "--scoring-config", str(inside)) == 2
    assert "dentro la directory analizzata" in capsys.readouterr().err
    link = env.tmp / "link.json"
    link.symlink_to(inside)  # un link da fuori verso dentro non lo aggira
    assert run_scan(env, "--scoring-config", str(link)) == 2


@pytest.mark.parametrize("content", [b"", b"{", b"[]", b'{"version": 1}'])
def test_an_invalid_scoring_config_is_exit_2_without_echoing_it(
    env: Env, capsys: pytest.CaptureFixture[str], content: bytes
) -> None:
    path = env.tmp / "bad.json"
    path.write_bytes(content)
    assert run_scan(env, "--scoring-config", str(path)) == 2
    assert content.decode() not in capsys.readouterr().err or content in (b"", b"{")


def test_the_repository_cannot_ship_its_own_scoring_through_its_config(env: Env) -> None:
    (env.repo / ".code-analyzer.yml").write_text("version: 1\nscoring:\n  variant: B\n")
    assert run_scan(env) == 0
    assert load(env)["scoring"]["active_variant"] == "B"  # solo la variante, nient'altro
    (env.repo / ".code-analyzer.yml").write_text(
        "version: 1\nscoring:\n  levels: {source: score}\n"
    )
    assert run_scan(env) == 2  # chiavi sconosciute: il repository non ha dove scrivere pesi


# --- variante ---------------------------------------------------------------------------------


def test_variant_precedence_flag_then_repository_config_then_scoring_file(env: Env) -> None:
    file_b = scoring_file(env, variant="B")
    assert run_scan(env, "--scoring-config", str(file_b)) == 0
    assert load(env)["scoring"]["active_variant"] == "B"
    (env.repo / ".code-analyzer.yml").write_text("version: 1\nscoring:\n  variant: A\n")
    assert run_scan(env, "--scoring-config", str(file_b)) == 0
    assert load(env)["scoring"]["active_variant"] == "A"  # il blocco del repository batte il file
    assert run_scan(env, "--scoring-config", str(file_b), "--variant", "B") == 0
    assert load(env)["scoring"]["active_variant"] == "B"  # il flag batte tutto
    assert finding_of(env)["impact"]["variant"] == "B"


# --- contesto del servizio --------------------------------------------------------------------


def test_the_service_context_file_feeds_c_and_is_marked_catalog(env: Env) -> None:
    context = env.tmp / "service.json"
    context.write_text(json.dumps({"version": 1, "tier": 1, "internet_facing": True}))
    assert run_scan(env, "--service-context", str(context)) == 0
    report = load(env)
    assert report["service_context"]["tier"] == {"value": 1, "source": "catalog"}
    assert report["service_context"]["internet_facing"] == {"value": True, "source": "catalog"}
    c = finding_of(env)["impact"]["evidence"]["c"]
    assert c == {"rule": "tier", "tier": 1, "source": "catalog"}
    assert finding_of(env)["impact"]["c"] == 1.0


def test_the_service_block_of_the_repository_is_declared_unverified(env: Env) -> None:
    (env.repo / ".code-analyzer.yml").write_text("version: 1\nservice:\n  tier: 3\n")
    assert run_scan(env) == 0
    report = load(env)
    assert report["service_context"]["tier"] == {"value": 3, "source": "repository"}
    assert any(w["code"] == "service-from-repository" for w in report["warnings"])
    assert finding_of(env)["impact"]["c"] == 0.4


def test_the_file_beats_the_block_and_the_mismatch_is_reported(env: Env) -> None:
    (env.repo / ".code-analyzer.yml").write_text("version: 1\nservice:\n  tier: 3\n")
    context = env.tmp / "service.json"
    context.write_text(json.dumps({"version": 1, "tier": 1}))
    assert run_scan(env, "--service-context", str(context)) == 0
    report = load(env)
    assert report["service_context"]["tier"]["value"] == 1
    assert any(w["code"] == "service-config-ignored" for w in report["warnings"])


def test_a_service_context_inside_the_repository_or_invalid_is_refused(env: Env) -> None:
    inside = env.repo / "service.json"
    inside.write_text(json.dumps({"version": 1, "tier": 1}))
    assert run_scan(env, "--service-context", str(inside)) == 2
    bad = env.tmp / "bad.json"
    bad.write_text(json.dumps({"version": 1, "tier": 9}))
    assert run_scan(env, "--service-context", str(bad)) == 2


# --- feed -------------------------------------------------------------------------------------


def test_feeds_are_synced_recorded_with_their_identity_and_cached(env: Env) -> None:
    fetcher = FakeFetcher(epss_file(), kev_file())
    assert run_scan(env, fetcher=fetcher) == 0
    report = load(env)
    feeds = {e["feed"]: e for e in report["enrichment"]}
    assert set(feeds) == {"epss", "kev"} and feeds["epss"]["origin"] == "public"
    assert feeds["kev"]["content"]["catalog_version"] == "2026.11.13"
    assert not any(w["code"] == "enrichment-feed-missing" for w in report["warnings"])
    assert len(fetcher.calls) == 2
    assert run_scan(env, fetcher=fetcher) == 0  # seconda volta: dalla cache, nessuna rete
    assert len(fetcher.calls) == 2


def test_offline_never_touches_the_network(env: Env) -> None:
    fetcher = FakeFetcher(OSError("non deve"), OSError("non deve"))
    assert run_scan(env, "--offline", fetcher=fetcher) == 0
    assert fetcher.calls == [] and load(env)["enrichment"] == []


def test_a_failed_sync_is_a_warning_never_a_failed_scan(env: Env) -> None:
    from ca_plugins.enrichment import FetchError

    fetcher = FakeFetcher(FetchError("network"), FetchError("network"))
    assert run_scan(env, fetcher=fetcher) == 0
    codes = {w["code"] for w in load(env)["warnings"]}
    assert "enrichment-feed-missing" in codes


def test_a_bad_origin_in_the_environment_is_exit_2(
    env: Env, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("CA_FEEDS_EPSS_URL", "http://plain.example/x")
    assert run_scan(env, fetcher=FakeFetcher(epss_file(), kev_file())) == 2


# --- uscite -----------------------------------------------------------------------------------


def test_sarif_carries_the_scores_and_the_table_the_maximum(
    env: Env, capsys: pytest.CaptureFixture[str]
) -> None:
    assert run_scan(env) == 0
    sarif = json.loads((env.out / "code-analyzer.sarif").read_text())
    props = sarif["runs"][0]["results"][0]["properties"]
    assert props["score"] == finding_of(env)["score"]
    assert [v["variant"] for v in props["variant_scores"]] == ["A", "B"]
    assert set(props["variant_scores"][0]) == {"variant", "score", "level", "g", "p", "e", "c"}
    assert "punteggio (variante A): massimo" in capsys.readouterr().out
