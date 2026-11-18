"""T-06 (ADR-0017): le risposte reali di `ca-api` superano l'OpenAPI che le dichiara.

Si ingerisce una scansione vera su PostgreSQL e si chiamano tutte le rotte: ogni corpo JSON, di
successo o di errore, deve superare lo schema dichiarato per quel percorso, metodo e stato. È il
pezzo del contratto che il file `schemas/openapi.json` da solo non dimostra: che il server dica la
verità su ciò che risponde. `CA_TEST_DOCKER=1`.
"""
# ruff: noqa: F811

import json
import uuid
from datetime import date, timedelta
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker
from test_api_ingest import (  # noqa: F401  (fixture condivise)
    T0,
    Env,
    database,
    env,
    finding,
    make_report,
    valid_graph,
    valid_sarif,
    valid_sbom,
)

from ca_core.models.finding import Category, ImpactFactors, Level, VariantScore

ROOT = Path(__file__).resolve().parents[2]
SPEC: dict[str, Any] = json.loads((ROOT / "schemas" / "openapi.json").read_text())
COMPONENTS = SPEC["components"]["schemas"]
FORMATS = FormatChecker()


def declared(method: str, template: str, status: int) -> tuple[str, dict[str, Any]] | None:
    """Tipo di contenuto e schema dichiarati per una risposta, o `None` se è senza corpo."""
    response = SPEC["paths"][template][method]["responses"].get(str(status))
    assert response is not None, f"{method.upper()} {template}: stato {status} non dichiarato"
    content = response.get("content")
    if not content:
        return None
    media, body = next(iter(content.items()))
    return media, body.get("schema", {})


def conforms(method: str, template: str, response: Any) -> None:
    found = declared(method, template, response.status_code)
    if found is None:
        assert not response.content
        return
    media, schema = found
    assert response.headers["content-type"].startswith(media), (template, response.headers)
    if not media.endswith("json"):
        return  # SBOM e SARIF hanno i loro schemi, provati altrove (C-02, C-05)
    document = {**schema, "components": {"schemas": COMPONENTS}}
    errors = sorted(
        Draft202012Validator(document, format_checker=FORMATS).iter_errors(response.json()),
        key=lambda e: list(e.path),
    )
    assert not errors, f"{method.upper()} {template}: {errors[0].message} in {list(errors[0].path)}"


def scored(name: str, level: Level, category: Category = Category.SAST) -> Any:
    factors = ImpactFactors(g=0.5, p=0.5, e=1.0, c=1.0, variant="A", evidence={"g": {"rule": "x"}})
    a = VariantScore(variant="A", score=25.0, level=Level.MEDIUM, impact=factors)
    b = VariantScore(
        variant="B",
        score=25.0,
        level=Level.MEDIUM,
        impact=factors.model_copy(update={"variant": "B"}),
    )
    return finding(name, level=level, category=category).model_copy(
        update={"variant_scores": [a, b]}
    )


def test_every_route_answers_what_the_openapi_declares(env: Env) -> None:
    items = [scored("a", Level.HIGH), scored("b", Level.CRITICAL), finding("c", level=Level.LOW)]
    response = env.post(
        make_report(items, started=T0), sarif=valid_sarif(), sbom=valid_sbom(), graph=valid_graph()
    )
    assert response.status_code == 201
    conforms("post", "/v1/scans", response)
    conforms(
        "post", "/v1/scans", env.post(make_report(items, started=T0), sarif=valid_sarif())
    )  # 200: ripetizione

    def get(path: str, template: str, *groups: str, **params: Any) -> Any:
        reply = env.client.get(path, headers=env.user(*groups), params=params)
        conforms("get", template, reply)
        return reply

    everyone = ("readers", "triagers", "approvers", "admins")
    conforms("get", "/v1/health", env.client.get("/v1/health"))
    me = get("/v1/me", "/v1/me", *everyone)
    assert me.status_code == 200
    repos = get("/v1/repositories", "/v1/repositories", "readers", limit=1)
    repo = repos.json()["items"][0]["id"]
    get(f"/v1/repositories/{repo}", "/v1/repositories/{id}", "readers")
    scans = get(f"/v1/repositories/{repo}/scans", "/v1/repositories/{id}/scans", "readers")
    scan = scans.json()["items"][0]["id"]
    get(f"/v1/scans/{scan}", "/v1/scans/{id}", "readers")
    assert get(f"/v1/scans/{scan}/sarif", "/v1/scans/{id}/sarif", "readers").status_code == 200
    assert (
        get(f"/v1/repositories/{repo}/sbom", "/v1/repositories/{id}/sbom", "readers").status_code
        == 200
    )
    assert (
        get(f"/v1/repositories/{repo}/graph", "/v1/repositories/{id}/graph", "readers").status_code
        == 200
    )
    page = get(
        f"/v1/repositories/{repo}/findings",
        "/v1/repositories/{id}/findings",
        "readers",
        limit=2,
        sort="score_a",
    )
    assert page.status_code == 200 and page.json()["next_cursor"]
    get(
        f"/v1/repositories/{repo}/findings",
        "/v1/repositories/{id}/findings",
        "readers",
        cursor=page.json()["next_cursor"],
        limit=2,
        sort="score_a",
    )
    get(
        f"/v1/repositories/{repo}/findings",
        "/v1/repositories/{id}/findings",
        "readers",
        level=["critico"],
        q="t-",
        new=True,
    )
    fid = page.json()["items"][0]["id"]
    get(f"/v1/findings/{fid}", "/v1/findings/{id}", "readers")
    conforms(
        "get", "/v1/service-context", env.client.get("/v1/service-context", headers=env.token())
    )

    # PATCH: tutte le azioni, poi il registro delle modifiche dice la stessa cosa dello schema
    def patch(path: str, template: str, body: dict[str, Any], *groups: str) -> Any:
        reply = env.client.patch(path, headers=env.user(*groups), json=body)
        conforms("patch", template, reply)
        return reply

    admin = patch(
        f"/v1/repositories/{repo}",
        "/v1/repositories/{id}",
        {"tier": 2, "internet_facing": True},
        "admins",
    )
    assert admin.status_code == 200
    conforms(
        "get", "/v1/service-context", env.client.get("/v1/service-context", headers=env.token())
    )
    template = "/v1/findings/{id}"
    assert (
        patch(
            f"/v1/findings/{fid}", template, {"action": "set-owner", "owner": "bob"}, "triagers"
        ).status_code
        == 200
    )
    assert (
        patch(
            f"/v1/findings/{fid}",
            template,
            {"action": "set-status", "status": "in_corso"},
            "triagers",
        ).status_code
        == 200
    )
    expires = (date(2026, 11, 17) + timedelta(days=30)).isoformat()
    made = patch(
        f"/v1/findings/{fid}",
        template,
        {"action": "create-exception", "reason": "r", "expires": expires},
        "approvers",
    )
    assert made.status_code == 200
    revoke = {"action": "revoke-exception", "exception_id": made.json()["exceptions"][0]["id"]}
    assert patch(f"/v1/findings/{fid}", template, revoke, "approvers").status_code == 200


def test_every_error_is_the_single_problem_document_the_openapi_declares(env: Env) -> None:
    assert env.post(make_report([finding("a")], started=T0)).status_code == 201
    repo = env.client.get("/v1/repositories", headers=env.user("readers")).json()["items"][0]["id"]
    missing = str(uuid.uuid4())
    cases: list[tuple[str, str, str, Any, tuple[str, ...], int]] = [
        ("get", f"/v1/repositories/{missing}", "/v1/repositories/{id}", None, ("readers",), 404),
        ("get", "/v1/repositories/nope", "/v1/repositories/{id}", None, ("readers",), 422),
        (
            "get",
            f"/v1/repositories/{repo}/findings?cursor=garbage",
            "/v1/repositories/{id}/findings",
            None,
            ("readers",),
            422,
        ),
        ("get", f"/v1/scans/{missing}", "/v1/scans/{id}", None, ("readers",), 404),
        ("get", f"/v1/findings/{missing}", "/v1/findings/{id}", None, ("readers",), 404),
        (
            "patch",
            f"/v1/repositories/{repo}",
            "/v1/repositories/{id}",
            {"tier": 9},
            ("admins",),
            422,
        ),
        (
            "patch",
            f"/v1/repositories/{repo}",
            "/v1/repositories/{id}",
            {"tier": 1},
            ("readers",),
            403,
        ),
        (
            "patch",
            f"/v1/findings/{missing}",
            "/v1/findings/{id}",
            {"action": "set-owner", "owner": "x"},
            ("triagers",),
            404,
        ),
    ]
    for method, path, template, body, groups, status in cases:
        reply = env.client.request(method.upper(), path, headers=env.user(*groups), json=body)
        assert reply.status_code == status, (path, reply.text)
        conforms(method, template, reply)
        assert reply.headers["content-type"].startswith("application/problem+json")
    unauthenticated = env.client.get(f"/v1/repositories/{repo}")
    assert unauthenticated.status_code == 401
    conforms("get", "/v1/repositories/{id}", unauthenticated)
    refused = env.client.post(
        "/v1/scans", headers=env.token(), files={"report": ("r.json", b"{}", "application/json")}
    )
    assert refused.status_code == 422
    conforms("post", "/v1/scans", refused)
