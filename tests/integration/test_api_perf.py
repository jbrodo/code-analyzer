"""B-08: prestazioni dell'elenco dei finding su un volume pari a saleor al Gate 1 (47.718 finding).

Non gira di default: CA_TEST_DOCKER=1 CA_TEST_PERF=1, con `pytest -s` su questo file.
Misura su PostgreSQL 16 in un contenitore e pg8000, con l'API in processo: la rete non c'entra.
Stampa una tabella; il tetto per richiesta (`BUDGET_SECONDS`) è il criterio di accettazione.
"""
# ruff: noqa: F811

import json
import os
import statistics
import time
from datetime import timedelta
from typing import Any

import pytest
from test_api_ingest import (  # noqa: F401  (le fixture `database` e `env` servono alla prova)
    GITHUB_IDP,
    T0,
    USER_IDP,
    Env,
    FixedClock,
    Settings,
    TestClient,
    build,
    create_app,
    database,
    env,
    make_report,
    pipeline_issuer,
    user_issuer,
)

from ca_core.models.finding import Category, Level

pytestmark = pytest.mark.skipif(
    os.environ.get("CA_TEST_PERF") != "1", reason="misura lenta: CA_TEST_PERF=1"
)
VOLUME = 47_718
BUDGET_SECONDS = 1.0  # per una richiesta di elenco, mediana di cinque
LEVELS = [Level.CRITICAL, Level.HIGH, Level.MEDIUM, Level.LOW]
CATEGORIES = [Category.SAST, Category.DEPENDENCY, Category.QUALITY, Category.LICENSE]


def build_findings(count: int, offset: int = 0) -> list[Any]:
    from builders import finding

    return [
        finding(
            f"p{offset + i:06d}",
            level=LEVELS[i % 4],
            category=CATEGORIES[(i // 4) % 4],
            tool=["bandit", "osv-scanner", "ruff", "scancode"][(i // 4) % 4],
            path=f"app/module{i % 800}/file{i % 97}.py",
        )
        for i in range(count)
    ]


def timed(env: Env, path: str, **params: Any) -> tuple[float, dict[str, Any]]:
    runs: list[float] = []
    body: dict[str, Any] = {}
    for _ in range(5):
        start = time.perf_counter()
        response = env.client.get(path, headers=env.user("readers"), params=params)
        runs.append(time.perf_counter() - start)
        assert response.status_code == 200, response.text
        body = response.json()
    return statistics.median(runs), body


def test_the_finding_list_at_the_volume_of_saleor(env: Env) -> None:
    big = Settings(max_part_bytes=300 * 2**20, max_request_bytes=320 * 2**20)
    _, fetcher, _, verifier = build(
        user_issuer().model_copy(update={"tenant": env.tenant}),
        pipeline_issuer().model_copy(update={"owners": {"4242": env.tenant}}),
    )
    fetcher.publish(USER_IDP.jwks_url, USER_IDP.jwk())
    fetcher.publish(GITHUB_IDP.jwks_url, GITHUB_IDP.jwk())
    env.client = TestClient(
        create_app(big, verifier=verifier, engine=env.engine, store=env.store, clock=FixedClock(T0))
    )
    body = make_report(build_findings(VOLUME), started=T0)
    start = time.perf_counter()
    response = env.post(body)
    ingest_seconds = time.perf_counter() - start
    assert response.status_code == 201, response.text
    print(
        f"\nreport {len(body) / 2**20:.0f} MiB, {VOLUME} finding: ingestione {ingest_seconds:.1f} s"
    )

    repo = env.client.get("/v1/repositories", headers=env.user("readers")).json()["items"][0]["id"]
    path = f"/v1/repositories/{repo}/findings"
    cases: list[tuple[str, dict[str, Any]]] = [
        ("predefinito (impatto), 50", {"limit": 50}),
        ("livello critico", {"level": "critico", "limit": 50}),
        ("categoria+tool", {"category": "dependency", "tool": "osv-scanner", "limit": 50}),
        ("nuovi", {"new": "true", "limit": 50}),
        ("ricerca `module7`", {"q": "module7", "limit": 50}),
        ("ordine per percorso", {"sort": "path", "limit": 50}),
        ("ordine punteggio A", {"sort": "score_a", "limit": 50}),
        ("ordine prima vista", {"sort": "first_seen", "limit": 50}),
        ("limite 200", {"limit": 200}),
    ]
    table: list[tuple[str, float]] = []
    for name, params in cases:
        median, page = timed(env, path, **params)
        table.append((name, median))
        assert page["total"] > 0

    # in fondo all'elenco: si cammina per cursore fino alla pagina 800 (40.000 finding)
    cursor, walked = None, 0
    start = time.perf_counter()
    while walked < 40_000:
        params = {"limit": 200, **({"cursor": cursor} if cursor else {})}
        page = env.client.get(path, headers=env.user("readers"), params=params).json()
        walked += len(page["items"])
        cursor = page["next_cursor"]
        if cursor is None:
            break
    per_page = (time.perf_counter() - start) / max(1, walked // 200)
    table.append(("pagina profonda (media di 200 pagine da 200)", per_page))

    detail_id = env.client.get(path, headers=env.user("readers"), params={"limit": 1}).json()[
        "items"
    ][0]["id"]
    median, _ = timed(env, f"/v1/findings/{detail_id}")
    table.append(("dettaglio di un finding", median))

    for name, seconds in table:
        print(f"{name:<48} {seconds * 1000:8.0f} ms")
    print(json.dumps({"volume": VOLUME, "ingest_seconds": round(ingest_seconds, 1)}))
    slow = [name for name, seconds in table if seconds > BUDGET_SECONDS]
    assert not slow, f"oltre {BUDGET_SECONDS} s: {slow}"
    assert timedelta(seconds=ingest_seconds) < timedelta(minutes=5)
