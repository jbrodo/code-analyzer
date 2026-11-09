"""M-03 (ADR-0004, R-09): SIGINT, SIGTERM e SIGHUP fermano la scansione (exit 2), `close` sempre."""

import os
import signal
import threading

import pytest

from ca_cli import main as cli
from ca_cli.composition import Context
from ca_core.fakes import FakePluginExecutor, FixedClock
from ca_plugins.source import LocalSourceReader


def context(closed: list[int]) -> Context:
    return Context(
        executor=FakePluginExecutor(),
        source=LocalSourceReader(),
        clock=FixedClock(),
        close=lambda: closed.append(1),
    )


@pytest.mark.parametrize("sig", [signal.SIGINT, signal.SIGTERM, signal.SIGHUP])
def test_signal_during_a_command_exits_2_closes_and_restores_handlers(
    sig: signal.Signals, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    closed: list[int] = []
    before = {s: signal.getsignal(s) for s in cli._SIGNALS}

    def handler(args: object, ctx: Context) -> int:
        os.kill(os.getpid(), sig)
        os.kill(os.getpid(), sig)  # un secondo segnale non interrompe la pulizia
        raise AssertionError("non raggiunto")

    monkeypatch.setitem(cli.HANDLERS, ("sbom", None), handler)
    assert cli.main(["sbom"], context=context(closed)) == 2
    assert closed == [1] and "interrotto" in capsys.readouterr().err
    assert {s: signal.getsignal(s) for s in cli._SIGNALS} == before


def test_close_is_called_on_success_and_on_errors_and_never_changes_the_exit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    closed: list[int] = []
    monkeypatch.setitem(cli.HANDLERS, ("sbom", None), lambda a, c: 0)
    assert cli.main(["sbom"], context=context(closed)) == 0

    def boom(args: object, ctx: Context) -> int:
        raise RuntimeError("x")

    monkeypatch.setitem(cli.HANDLERS, ("sbom", None), boom)
    assert cli.main(["sbom"], context=context(closed)) == 2
    assert closed == [1, 1]

    def bad_close() -> None:
        raise OSError("x")

    monkeypatch.setitem(cli.HANDLERS, ("sbom", None), lambda a, c: 0)
    ctx = Context(
        executor=FakePluginExecutor(),
        source=LocalSourceReader(),
        clock=FixedClock(),
        close=bad_close,
    )
    assert cli.main(["sbom"], context=ctx) == 0


def test_handlers_are_not_installed_outside_the_main_thread() -> None:
    seen: list[object] = []

    def work() -> None:
        with cli._interruptible():
            seen.append(signal.getsignal(signal.SIGTERM))

    before = signal.getsignal(signal.SIGTERM)
    thread = threading.Thread(target=work)
    thread.start()
    thread.join()
    assert seen == [before]
