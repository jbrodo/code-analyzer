"""Controlli iniziali di `scan_local`: rifiuti prima di toccare Docker (nessun servizio esterno)."""

from pathlib import Path

import pytest

from . import e2e_lab, scan_local


@pytest.fixture
def configured(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in ("COSIGN", "SYFT", "OSV_FEEDS", "TRIVY_FEEDS"):
        monkeypatch.setattr(e2e_lab, name, "/x")
    monkeypatch.setattr(scan_local, "container_leftovers", list)


def no_fleet(*args: object, **kwargs: object) -> None:
    raise AssertionError("il laboratorio non deve partire")


def test_missing_settings_are_named(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    for name in ("COSIGN", "SYFT", "OSV_FEEDS", "TRIVY_FEEDS"):
        monkeypatch.setattr(e2e_lab, name, "")
    monkeypatch.setattr(scan_local, "Fleet", no_fleet)
    assert scan_local.main([str(tmp_path)]) == 2
    assert "COSIGN, SYFT, CA_TEST_OSV_FEEDS, CA_TEST_TRIVY_FEEDS" in capsys.readouterr().err


@pytest.mark.usefixtures("configured")
def test_unknown_plugin_and_missing_directory_are_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(scan_local, "Fleet", no_fleet)
    assert scan_local.main([str(tmp_path), "--plugins", "bandit,nope"]) == 2
    assert scan_local.main([str(tmp_path / "assente")]) == 2


@pytest.mark.usefixtures("configured")
def test_refuses_to_start_with_active_project_containers(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(scan_local, "container_leftovers", lambda: ["abc"])
    monkeypatch.setattr(scan_local, "Fleet", no_fleet)
    assert scan_local.main([str(tmp_path)]) == 2
    assert "container del progetto attivi" in capsys.readouterr().err
