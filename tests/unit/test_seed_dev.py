"""I-05, U-05: lo script dei dati di prova costruisce report validi, senza rete."""

import importlib.util
from datetime import UTC, datetime
from pathlib import Path

from ca_core.models.scan_report import ScanReport

SOURCE = Path(__file__).resolve().parents[2] / "deploy/compose/seed_dev.py"
spec = importlib.util.spec_from_file_location("seed_dev", SOURCE)
assert spec is not None and spec.loader is not None
seed = importlib.util.module_from_spec(spec)
spec.loader.exec_module(seed)
NOW = datetime(2026, 11, 18, 12, 0, tzinfo=UTC)


def test_every_finding_of_the_pool_is_valid_and_distinct() -> None:
    pool = seed.build(NOW)
    assert len({f.fingerprint for f in pool.values()}) == len(pool)
    assert {f.level.value for f in pool.values()} == {"critico", "alto", "medio", "basso"}
    assert any(f.variant_scores for f in pool.values()) and any(
        f.remediation for f in pool.values()
    )


def test_a_report_round_trips_through_the_server_model() -> None:
    pool = seed.build(NOW)
    data = seed.report(list(pool.values()), started=NOW, commit="a" * 40)
    assert len(ScanReport.model_validate_json(data).findings) == len(pool)


def test_the_partial_report_names_its_failed_plugin() -> None:
    pool = seed.build(NOW)
    data = seed.report(
        [pool["sql"]], started=NOW, commit="b" * 40, status="partial", failed=("semgrep",)
    )
    report = ScanReport.model_validate_json(data)
    assert report.status.value == "partial"
    assert [p.name for p in report.plugins if p.outcome.value == "failed"] == ["semgrep"]


def test_the_script_only_talks_to_loopback() -> None:
    import pytest

    assert seed.loopback("http://127.0.0.1:8000/") == "http://127.0.0.1:8000"
    with pytest.raises(SystemExit):
        seed.loopback("https://ca.example.org")
