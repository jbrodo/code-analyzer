"""Plugin di pytest per la CI (O-02): un salto non previsto fa fallire l'esecuzione.

Gli E2E e le prove di integrazione si saltano se manca Docker, cosign, syft o lo snapshot dei
feed: in locale va bene, in CI darebbe un esito verde senza aver provato nulla. Con questo plugin
sono ammessi solo i salti con un motivo di questo elenco, tutti scelte esplicite.

Uso: `PYTHONPATH=tests/ci pytest -p skip_guard …`. Un file a sé e non un `conftest.py` nella radice
delle prove, che si scontrerebbe con il modulo `conftest` dei test di contratto.
"""

from typing import Any

import pytest

ALLOWED = frozenset(
    {
        "misura lenta: CA_TEST_PERF=1",  # B-08: misura, non una prova di correttezza
        "scarica da internet: CA_TEST_NETWORK=1",  # nessun servizio esterno (AGENTS.md, regola 7)
        # il motore non sta sul runner: le regole si provano con quello dell'immagine
        "semgrep non disponibile",
    }
)
_unexpected: list[str] = []


def _reason(report: Any) -> str:
    longrepr = report.longrepr
    text = longrepr[2] if isinstance(longrepr, tuple) else str(longrepr)
    return text.removeprefix("Skipped: ")


def _record(report: Any) -> None:
    if report.skipped and not hasattr(report, "wasxfail"):
        reason = _reason(report)
        if reason not in ALLOWED:
            _unexpected.append(f"{report.nodeid}: {reason}")


def pytest_runtest_logreport(report: Any) -> None:
    _record(report)


def pytest_collectreport(report: Any) -> None:  # un modulo intero saltato in raccolta
    _record(report)


@pytest.hookimpl(trylast=True)
def pytest_sessionfinish(session: Any) -> None:
    if _unexpected and session.exitstatus == pytest.ExitCode.OK:
        session.exitstatus = pytest.ExitCode.TESTS_FAILED


def pytest_terminal_summary(terminalreporter: Any) -> None:
    if _unexpected:
        terminalreporter.section("salti non previsti: l'esecuzione fallisce")
        for line in _unexpected:
            terminalreporter.write_line(line)
