"""S1-A2: tetti all'ingestione per repository e per tenant, con 429 e `Retry-After`."""

import threading
from datetime import UTC, datetime, timedelta

import pytest

from ca_api.config import Settings
from ca_api.problem import ApiProblem
from ca_api.throttle import IngestThrottle

T0 = datetime(2026, 11, 18, 12, 0, tzinfo=UTC)
REPO = ("acme", "github", "https://idp", "9001")


def test_the_attempt_over_the_hourly_cap_is_refused_with_the_time_to_wait() -> None:
    throttle = IngestThrottle(per_hour=3, concurrent=0)
    for i in range(3):
        throttle.admit(REPO, T0 + timedelta(minutes=i))
    with pytest.raises(ApiProblem) as refused:
        throttle.admit(REPO, T0 + timedelta(minutes=10))
    assert (
        refused.value.problem.status == 429 and refused.value.problem.code.value == "rate-limited"
    )
    assert refused.value.headers["Retry-After"] == str(50 * 60 + 1)  # la prima esce dopo un'ora


def test_the_window_slides_and_other_repositories_are_independent() -> None:
    throttle = IngestThrottle(per_hour=1, concurrent=0)
    throttle.admit(REPO, T0)
    throttle.admit(("acme", "github", "https://idp", "9002"), T0)  # un altro repository
    with pytest.raises(ApiProblem):
        throttle.admit(REPO, T0 + timedelta(minutes=59))
    throttle.admit(REPO, T0 + timedelta(hours=1, seconds=1))  # la finestra è scorsa


def test_a_refused_attempt_does_not_extend_the_window() -> None:
    throttle = IngestThrottle(per_hour=1, concurrent=0)
    throttle.admit(REPO, T0)
    for minute in (5, 20, 40):
        with pytest.raises(ApiProblem):
            throttle.admit(REPO, T0 + timedelta(minutes=minute))
    throttle.admit(REPO, T0 + timedelta(hours=1, seconds=1))


def test_zero_switches_both_caps_off() -> None:
    throttle = IngestThrottle(per_hour=0, concurrent=0)
    for _ in range(1000):
        throttle.admit(REPO, T0)
    with throttle.slot("acme"), throttle.slot("acme"), throttle.slot("acme"):
        pass


def test_parallel_ingestions_of_a_tenant_are_capped_and_the_slot_is_always_released() -> None:
    throttle = IngestThrottle(per_hour=0, concurrent=2)
    with throttle.slot("acme"), throttle.slot("acme"):
        with pytest.raises(ApiProblem) as busy, throttle.slot("acme"):
            pass
        assert busy.value.problem.status == 429 and busy.value.headers["Retry-After"] == "5"
        with throttle.slot("other"):  # un altro tenant non ne risente
            pass
    with throttle.slot("acme"):  # rilasciati all'uscita
        pass
    with pytest.raises(RuntimeError), throttle.slot("acme"):
        raise RuntimeError("fallisce dentro")
    with throttle.slot("acme"), throttle.slot("acme"):  # anche dopo un errore
        pass


def test_the_cap_holds_under_concurrent_threads() -> None:
    throttle = IngestThrottle(per_hour=0, concurrent=3)
    entered, refused = [], []
    gate = threading.Event()

    def worker() -> None:
        try:
            with throttle.slot("acme"):
                entered.append(1)
                gate.wait(2)
        except ApiProblem:
            refused.append(1)

    threads = [threading.Thread(target=worker) for _ in range(10)]
    for t in threads:
        t.start()
    while len(entered) + len(refused) < 10:
        pass
    gate.set()
    for t in threads:
        t.join()
    assert len(entered) == 3 and len(refused) == 7


def test_the_settings_read_the_caps_from_the_environment() -> None:
    settings = Settings.from_env(
        {"CA_API_MAX_INGESTS_PER_HOUR": "7", "CA_API_MAX_CONCURRENT_INGESTS": "0"}
    )
    assert (settings.max_ingests_per_hour, settings.max_concurrent_ingests) == (7, 0)
    assert Settings().max_ingests_per_hour == 120 and Settings().max_concurrent_ingests == 4
