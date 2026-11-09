"""Fixture degli E2E: flotta di plugin firmati, cache dei feed congelata, scansioni condivise.

Le scansioni delle tre fixture (python-app, js-ts-app, secrets-history) si fanno UNA volta per
sessione e servono a T-05 (senza CVE) e a T-08 (CVE): T-08 dipende da T-05. Tutto richiede Docker,
cosign, syft e lo snapshot dei feed; senza, i test saltano con il motivo (vedi `e2e_lab.py`).
"""

import sys
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest

from .e2e_lab import (
    REPOS,
    CliResult,
    Fleet,
    copy_fixture,
    make_feeds_cache,
)

sys.path.insert(0, str(REPOS.parents[1] / "fixtures" / "builders"))
import secrets_history  # noqa: E402

ALL_PLUGINS = ["bandit", "gitleaks", "osv-scanner", "scancode", "semgrep", "syft", "trivy"]
DURATIONS: dict[str, float] = {}


def pytest_terminal_summary(terminalreporter: Any) -> None:
    if DURATIONS:
        terminalreporter.section("durate delle scansioni E2E (secondi, processo completo)")
        for name, seconds in DURATIONS.items():
            terminalreporter.write_line(f"{name}: {seconds}")


@pytest.fixture(scope="session")
def fleet(tmp_path_factory: pytest.TempPathFactory) -> Iterator[Fleet]:
    lab = Fleet(work=tmp_path_factory.mktemp("e2e-lab"))
    try:
        yield lab
    finally:
        lab.close()
        DURATIONS.update({f"build+firma {n}": s for n, s in lab.build_seconds.items()})


@pytest.fixture(scope="session")
def feeds_cache(fleet: Fleet, tmp_path_factory: pytest.TempPathFactory) -> Path:
    for plugin in ("osv-scanner", "trivy"):
        fleet.add_builtin(plugin)
    cache = tmp_path_factory.mktemp("e2e-feeds") / "cache"
    make_feeds_cache(cache, fleet.digests)
    return cache


@dataclass
class Scan:
    name: str
    result: CliResult
    path: Path

    @property
    def report(self) -> dict[str, Any]:
        return self.result.report

    @property
    def findings(self) -> list[dict[str, Any]]:
        findings: list[dict[str, Any]] = self.report["findings"]
        return findings


def full_scan(
    fleet: Fleet, feeds_cache: Path, root: Path, name: str, base: Path, **kwargs: Any
) -> Scan:
    for plugin in ALL_PLUGINS:
        fleet.add_builtin(plugin)
    out = base / f"out-{name}"
    result = fleet.scan(
        root, out, "--offline", plugins=ALL_PLUGINS, feeds_cache=feeds_cache, **kwargs
    )
    DURATIONS[f"scansione {name}"] = result.seconds
    return Scan(name, result, root)


@pytest.fixture(scope="session")
def work(tmp_path_factory: pytest.TempPathFactory) -> Path:
    return tmp_path_factory.mktemp("e2e-work")


@pytest.fixture(scope="session")
def python_scan(fleet: Fleet, feeds_cache: Path, work: Path) -> Scan:
    root = copy_fixture("python-app", work, license_policy=True)
    return full_scan(fleet, feeds_cache, root, "python-app", work)


@pytest.fixture(scope="session")
def jsts_scan(fleet: Fleet, feeds_cache: Path, work: Path) -> Scan:
    root = copy_fixture("js-ts-app", work, license_policy=True)
    return full_scan(fleet, feeds_cache, root, "js-ts-app", work)


@pytest.fixture(scope="session")
def secrets_scan(fleet: Fleet, feeds_cache: Path, work: Path) -> Scan:
    history = secrets_history.build_history(work / "secrets-history")
    return full_scan(fleet, feeds_cache, history.path, "secrets-history", work)


@pytest.fixture(scope="session")
def secrets_shallow_scan(fleet: Fleet, feeds_cache: Path, work: Path) -> Scan:
    history = secrets_history.build_history(work / "secrets-history-src")
    shallow = secrets_history.shallow_clone(history.path, work / "secrets-history-shallow")
    return full_scan(fleet, feeds_cache, shallow, "secrets-history-shallow", work)
