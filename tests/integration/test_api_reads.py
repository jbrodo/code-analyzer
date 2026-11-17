"""B-06, B-08, B-09, B-10, B-11: letture e triage su PostgreSQL vero, con ruoli e tenant.

`CA_TEST_DOCKER=1`. Si parte da scansioni ingerite con `POST /v1/scans`, come in produzione.
"""

# ruff: noqa: F811
import json
import uuid
from datetime import timedelta
from typing import Any

import pytest
from test_api_ingest import (  # noqa: F401  (fixture condivise)
    SHA,
    T0,
    Env,
    builders_finding,
    database,
    env,
    make_report,
    valid_graph,
    valid_sarif,
    valid_sbom,
)

from ca_core.models.finding import BaselineState, Category, ImpactFactors, Level, VariantScore

READER = ("readers",)
TRIAGE = ("triagers",)
APPROVER = ("approvers",)
ADMIN = ("admins",)


def finding(name: str, **kv: Any):
    return builders_finding(name, **kv)


def get(env: Env, path: str, *groups: str, **params: Any):
    return env.client.get(path, headers=env.user(*groups), params=params)


def patch(env: Env, path: str, body: dict[str, Any], *groups: str):
    return env.client.patch(path, headers=env.user(*groups), json=body)


def ingest(env: Env, findings, minutes: int = 0, **extra: bytes) -> str:
    response = env.post(make_report(findings, started=T0 + timedelta(minutes=minutes)), **extra)
    assert response.status_code == 201, response.text
    return str(response.json()["id"])


def repo_id(env: Env) -> str:
    return str(get(env, "/v1/repositories", *READER).json()["items"][0]["id"])


def listing(env: Env, **params: Any) -> dict[str, Any]:
    response = get(env, f"/v1/repositories/{repo_id(env)}/findings", *READER, **params)
    assert response.status_code == 200, response.text
    return response.json()  # type: ignore[no-any-return]


# --- repository e scansioni (B-10) ---


def test_repositories_are_listed_with_their_current_scan_and_paged_by_cursor(env: Env) -> None:
    for i in range(5):
        response = env.post(
            make_report(), headers=env.token(repo_id=str(100 + i), name=f"acme/shop{i}")
        )
        assert response.status_code in {
            201,
            403,
        }  # il nome del report è `shop`: solo il primo coincide
    ingest(env, [finding("a")])
    first = get(env, "/v1/repositories", *READER, limit=1).json()
    assert len(first["items"]) == 1 and first["items"][0]["name"] == "acme/shop"
    assert first["items"][0]["current_scan"]["status"] == "complete"
    assert first["next_cursor"] is None


def test_a_repository_and_its_scans(env: Env) -> None:
    ingest(env, [finding("a")], 0)
    ingest(env, [finding("a")], 10)
    rid = repo_id(env)
    one = get(env, f"/v1/repositories/{rid}", *READER).json()
    assert one["provider"] == "github" and one["tier"] is None and one["current_scan"] is not None
    scans = get(env, f"/v1/repositories/{rid}/scans", *READER, limit=1).json()
    assert len(scans["items"]) == 1 and scans["next_cursor"]
    nxt = get(
        env, f"/v1/repositories/{rid}/scans", *READER, limit=1, cursor=scans["next_cursor"]
    ).json()
    assert nxt["items"][0]["id"] != scans["items"][0]["id"] and nxt["next_cursor"] is None
    assert scans["items"][0]["started_at"] > nxt["items"][0]["started_at"]  # dalla più recente


def test_an_unknown_or_malformed_repository_is_404_or_422(env: Env) -> None:
    assert get(env, f"/v1/repositories/{uuid.uuid4()}", *READER).status_code == 404
    assert get(env, "/v1/repositories/nope", *READER).status_code == 422
    assert get(env, f"/v1/repositories/{uuid.uuid4()}/scans", *READER).status_code == 404


def test_only_the_administrator_registers_tier_and_exposure_with_who_and_when(env: Env) -> None:
    ingest(env, [finding("a")])
    path = f"/v1/repositories/{repo_id(env)}"
    for groups in (READER, TRIAGE, APPROVER):
        assert patch(env, path, {"tier": 1}, *groups).status_code == 403
    done = patch(env, path, {"tier": 2, "internet_facing": True, "catalog_id": "shop"}, *ADMIN)
    assert done.status_code == 200
    assert (done.json()["tier"], done.json()["internet_facing"], done.json()["catalog_id"]) == (
        2,
        True,
        "shop",
    )
    only = patch(env, path, {"tier": 3}, *ADMIN).json()
    assert (only["tier"], only["internet_facing"]) == (3, True)  # un campo assente non si tocca
    cleared = patch(env, path, {"internet_facing": None}, *ADMIN).json()
    assert cleared["internet_facing"] is None  # un `null` esplicito lo azzera
    assert patch(env, path, {"tier": 4}, *ADMIN).status_code == 422
    assert patch(env, path, {"tier": 1, "owner": "x"}, *ADMIN).status_code == 422


def test_the_service_context_for_the_pipeline_of_the_repository(env: Env) -> None:
    assert (
        env.client.get("/v1/service-context", headers=env.token()).status_code == 404
    )  # repo ancora ignoto
    ingest(env, [finding("a")])
    patch(env, f"/v1/repositories/{repo_id(env)}", {"tier": 1, "internet_facing": False}, *ADMIN)
    context = env.client.get("/v1/service-context", headers=env.token())
    assert context.status_code == 200
    assert context.json() == {
        "version": 1,
        "tier": 1,
        "internet_facing": False,
        "origin": "code-analyzer-server",
    }
    assert (
        env.client.get(
            "/v1/service-context", headers=env.token(repo_id="777", name="acme/shop")
        ).status_code
        == 404
    )
    assert get(env, "/v1/service-context", *ADMIN).status_code == 403


def test_a_tenant_never_sees_another_tenants_repository(env: Env, database) -> None:
    from apiauth import GITHUB_IDP, USER_IDP
    from idp import build, pipeline_issuer, user_issuer
    from starlette.testclient import TestClient

    from ca_api.app import create_app
    from ca_api.db import stores

    ingest(env, [finding("a")])
    rid = repo_id(env)
    other = stores.create_tenant(database, f"other-{uuid.uuid4().hex[:6]}")
    _, fetcher, _, verifier = build(
        user_issuer().model_copy(update={"tenant": other.name}), pipeline_issuer()
    )
    fetcher.publish(USER_IDP.jwks_url, USER_IDP.jwk())
    fetcher.publish(GITHUB_IDP.jwks_url, GITHUB_IDP.jwk())
    client = TestClient(
        create_app(env.settings, verifier=verifier, engine=database, store=env.store)
    )
    headers = {
        "Authorization": "Bearer " + USER_IDP.sign(groups=["admins", "readers", "approvers"])
    }
    assert client.get("/v1/repositories", headers=headers).json()["items"] == []
    assert client.get(f"/v1/repositories/{rid}", headers=headers).status_code == 404
    assert client.get(f"/v1/repositories/{rid}/findings", headers=headers).status_code == 404
    assert (
        client.patch(f"/v1/repositories/{rid}", headers=headers, json={"tier": 1}).status_code
        == 404
    )
    finding_id = listing(env)["items"][0]["id"]
    assert client.get(f"/v1/findings/{finding_id}", headers=headers).status_code == 404
    assert (
        client.patch(
            f"/v1/findings/{finding_id}",
            headers=headers,
            json={"action": "set-owner", "owner": "x"},
        ).status_code
        == 404
    )


# --- scansione: stato, SARIF, SBOM e grafo (B-06, B-11) ---


def test_scan_detail_has_the_report_fields_that_are_not_findings(env: Env) -> None:
    scan = ingest(env, [finding("a")])
    body = get(env, f"/v1/scans/{scan}", *READER).json()
    assert body["summary"]["id"] == scan and body["summary"]["kind"] == "full"
    assert body["plugins"][0]["name"] == "bandit" and body["gate"]["mode"] == "all"
    assert "findings" not in body and body["warnings"] == []


def test_the_pipeline_reads_only_the_scans_of_its_own_repository(env: Env) -> None:
    scan = ingest(env, [finding("a")], sarif=valid_sarif())
    mine = env.client.get(f"/v1/scans/{scan}", headers=env.token())
    other = env.client.get(f"/v1/scans/{scan}", headers=env.token(repo_id="555", name="acme/other"))
    assert mine.status_code == 200 and other.status_code == 404
    assert (
        env.client.get(
            f"/v1/scans/{scan}/sarif", headers=env.token(repo_id="555", name="acme/other")
        ).status_code
        == 404
    )
    assert env.client.get(f"/v1/scans/{scan}/sarif", headers=env.token()).status_code == 200


def test_sarif_is_served_as_stored_and_404_when_the_scan_has_none(env: Env) -> None:
    sarif = valid_sarif()
    with_sarif = ingest(env, [finding("a")], 0, sarif=sarif)
    without = ingest(env, [finding("b")], 5)
    response = get(env, f"/v1/scans/{with_sarif}/sarif", *READER)
    assert response.status_code == 200 and response.content == sarif
    assert response.headers["content-type"].startswith("application/sarif+json")
    assert get(env, f"/v1/scans/{without}/sarif", *READER).status_code == 404
    assert get(env, f"/v1/scans/{uuid.uuid4()}", *READER).status_code == 404


def test_sbom_and_graph_of_the_current_scan(env: Env) -> None:
    ingest(env, [finding("a")], 0, sbom=valid_sbom(), graph=valid_graph())
    rid = repo_id(env)
    sbom = get(env, f"/v1/repositories/{rid}/sbom", *READER)
    assert sbom.status_code == 200 and sbom.json()["specVersion"] == "1.7"
    assert sbom.headers["content-type"].startswith("application/vnd.cyclonedx+json")
    graph = get(env, f"/v1/repositories/{rid}/graph", *READER).json()
    assert [m["path"] for m in graph["modules"]] == ["a.py", "b.py"] and graph["history"][
        "status"
    ] == "completa"
    ingest(env, [finding("a")], 10)  # la scansione corrente non ha né SBOM né grafo
    assert get(env, f"/v1/repositories/{rid}/sbom", *READER).status_code == 404
    assert get(env, f"/v1/repositories/{rid}/graph", *READER).status_code == 404


# --- elenco dei finding (B-08) ---


def seed(env: Env) -> list[Any]:
    items = [
        finding("crit", level=Level.CRITICAL, category=Category.SAST),
        finding(
            "high",
            level=Level.HIGH,
            category=Category.DEPENDENCY,
            tool="osv-scanner",
            path="requirements.txt",
        ),
        finding(
            "med", level=Level.MEDIUM, category=Category.QUALITY, tool="ruff", path="lib/util.py"
        ),
        finding("low", level=Level.LOW, category=Category.SAST, path="app/low.py"),
    ]
    ingest(env, items)
    return items


def titles(page: dict[str, Any]) -> list[str]:
    return [i["title"] for i in page["items"]]


def test_the_default_order_is_level_then_new_then_recent_and_the_counts_are_the_filters(
    env: Env,
) -> None:
    seed(env)
    page = listing(env)
    assert titles(page) == ["t-crit", "t-high", "t-med", "t-low"]
    assert (page["total"], page["total_new"]) == (4, 4) and page["next_cursor"] is None
    item = page["items"][0]
    assert (
        item["level"] == "critico"
        and item["fingerprint"].startswith("sha256:")
        and item["status"] == "aperto"
    )


def test_filters_by_level_category_tool_and_status_combine_and_repeat(env: Env) -> None:
    seed(env)
    assert titles(listing(env, level=["critico", "basso"])) == ["t-crit", "t-low"]
    assert titles(listing(env, category="sast")) == ["t-crit", "t-low"]
    assert titles(listing(env, tool="osv-scanner")) == ["t-high"]
    assert titles(listing(env, tool=["ruff", "osv-scanner"])) == ["t-high", "t-med"]
    assert titles(listing(env, level="critico", category="quality")) == []
    assert listing(env, status="in_corso")["total"] == 0


def test_search_is_a_case_insensitive_substring_and_never_a_pattern(env: Env) -> None:
    seed(env)
    assert titles(listing(env, q="UTIL")) == ["t-med"]  # sul percorso
    assert titles(listing(env, q="r-hi")) == ["t-high"]  # sulla regola
    assert listing(env, q="t-%")["total"] == 0  # `%` è un carattere, non un jolly
    assert listing(env, q=".*")["total"] == 0
    assert (
        get(env, f"/v1/repositories/{repo_id(env)}/findings", *READER, q="a").status_code == 422
    )  # almeno due


def test_the_new_filter_and_the_pr_scan_view(env: Env) -> None:
    ingest(env, [finding("old")], 0)
    pr = make_report(
        [
            finding("old", baseline_state=BaselineState.EXISTING),
            finding("added", baseline_state=BaselineState.NEW),
        ],
        started=T0 + timedelta(minutes=30),
        scan={"kind": "pr", "base_commit": "c" * 40, "pull_request": 5},
        baseline={
            "status": "valid",
            "commit": "c" * 40,
            "source": "ci-artifact",
            "new": 1,
            "existing": 1,
        },
    )
    response = env.post(pr, headers=env.token(ref="refs/pull/5/merge"))
    assert response.status_code == 201, response.text
    scan = response.json()["id"]
    assert titles(listing(env)) == ["t-old"]  # senza `scan`: la scansione corrente, non la PR
    page = listing(env, scan=scan)
    assert titles(page) == ["t-added", "t-old"] and (page["total"], page["total_new"]) == (
        2,
        1,
    )  # nuovi prima
    assert page["items"][0]["new"] is True and page["items"][1]["new"] is False
    assert titles(listing(env, scan=scan, new=True)) == ["t-added"]
    assert titles(listing(env, scan=scan, new=False)) == ["t-old"]
    assert (
        get(
            env, f"/v1/repositories/{repo_id(env)}/findings", *READER, scan=str(uuid.uuid4())
        ).status_code
        == 404
    )


def test_resolved_findings_appear_only_when_the_filter_asks_for_them(env: Env) -> None:
    ingest(env, [finding("a"), finding("gone")], 0)
    ingest(env, [finding("a")], 10)
    assert titles(listing(env)) == ["t-a"]
    resolved = listing(env, status="risolto")
    assert titles(resolved) == ["t-gone"] and resolved["items"][0]["status"] == "risolto"
    both = listing(env, status=["risolto", "aperto"])
    assert sorted(titles(both)) == ["t-a", "t-gone"]


def test_pagination_walks_every_finding_once_in_a_stable_total_order(env: Env) -> None:
    ingest(
        env,
        [
            finding(f"f{i:02d}", level=[Level.HIGH, Level.LOW, Level.MEDIUM][i % 3])
            for i in range(23)
        ],
    )
    whole = [i["id"] for i in listing(env, limit=200)["items"]]
    walked: list[str] = []
    cursor = None
    pages = 0
    while True:
        params: dict[str, Any] = {"limit": 5, **({"cursor": cursor} if cursor else {})}
        page = listing(env, **params)
        walked += [i["id"] for i in page["items"]]
        pages += 1
        cursor = page["next_cursor"]
        if cursor is None:
            break
    assert walked == whole and len(set(walked)) == 23 and pages == 5


@pytest.mark.parametrize("sort", ["impact", "first_seen", "path", "score_a", "score_b"])
def test_every_sort_is_total_and_walks_without_repeats(env: Env, sort: str) -> None:
    ingest(env, [finding(f"s{i:02d}", level=Level.HIGH, path=f"app/{i % 4}.py") for i in range(14)])
    whole = [i["id"] for i in listing(env, limit=200, sort=sort)["items"]]
    walked: list[str] = []
    cursor = None
    while True:
        page = listing(env, limit=4, sort=sort, **({"cursor": cursor} if cursor else {}))
        walked += [i["id"] for i in page["items"]]
        cursor = page["next_cursor"]
        if cursor is None:
            break
    assert walked == whole and len(set(walked)) == 14


def test_sort_by_path_orders_by_path(env: Env) -> None:
    ingest(env, [finding("z", path="z.py"), finding("a", path="a.py"), finding("m", path="m.py")])
    assert [i["path"] for i in listing(env, sort="path")["items"]] == ["a.py", "m.py", "z.py"]


def test_a_cursor_of_another_request_is_refused(env: Env) -> None:
    ingest(env, [finding(f"c{i}") for i in range(6)])
    cursor = listing(env, limit=2)["next_cursor"]
    for other in ({"level": "critico"}, {"sort": "path"}, {"q": "zz"}):
        response = get(
            env,
            f"/v1/repositories/{repo_id(env)}/findings",
            *READER,
            limit=2,
            cursor=cursor,
            **other,
        )
        assert response.status_code == 422 and response.json()["code"] == "invalid-cursor", other
    for bad in ("garbage", "e30", "AAAA"):
        response = get(env, f"/v1/repositories/{repo_id(env)}/findings", *READER, cursor=bad)
        assert response.json()["code"] == "invalid-cursor"
    assert cursor not in json.dumps(listing(env)["items"])  # opaco: non è un dato


def test_the_list_carries_the_shadow_scores_and_levels(env: Env) -> None:
    f = finding("scored", level=Level.HIGH)
    factors = ImpactFactors(g=0.5, p=0.5, e=1.0, c=1.0, variant="A")
    a = VariantScore(variant="A", score=25.0, level=Level.MEDIUM, impact=factors)
    b = VariantScore(
        variant="B",
        score=25.0,
        level=Level.MEDIUM,
        impact=factors.model_copy(update={"variant": "B"}),
    )
    ingest(env, [f.model_copy(update={"variant_scores": [a, b], "score": 25.0})])
    item = listing(env)["items"][0]
    assert (item["score_a"], item["level_a"], item["score_b"], item["level_b"]) == (
        25.0,
        "medio",
        25.0,
        "medio",
    )
    assert listing(env, sort="score_a")["total"] == 1


def test_only_readers_list_findings_and_the_decision_is_the_servers(env: Env) -> None:
    seed(env)
    path = f"/v1/repositories/{repo_id(env)}/findings"
    assert env.client.get(path, headers=env.user()).status_code == 403
    assert env.client.get(path, headers=env.token()).status_code == 403
    assert env.client.get(path).status_code == 401


# --- dettaglio e triage (B-09) ---


def one_finding(env: Env) -> str:
    ingest(env, [finding("a", level=Level.HIGH)])
    return str(listing(env)["items"][0]["id"])


def test_detail_has_the_finding_the_occurrence_exceptions_and_events(env: Env) -> None:
    f = finding("scored", level=Level.HIGH)
    factors = ImpactFactors(g=0.5, p=0.5, e=1.0, c=1.0, variant="A", evidence={"rule": "x"})
    scores = [
        VariantScore(variant="A", score=25.0, level=Level.MEDIUM, impact=factors),
        VariantScore(
            variant="B",
            score=25.0,
            level=Level.MEDIUM,
            impact=factors.model_copy(update={"variant": "B"}),
        ),
    ]
    ingest(env, [f.model_copy(update={"variant_scores": scores})])
    fid = str(listing(env)["items"][0]["id"])
    body = get(env, f"/v1/findings/{fid}", *READER).json()
    assert body["finding"]["id"] == fid and body["finding"]["fingerprint"] == f.fingerprint
    assert body["finding"]["first_seen"].startswith("2026-11-17T12:00:00")  # data del server
    assert [v["variant"] for v in body["occurrence"]["variant_scores"]] == ["A", "B"]
    assert body["occurrence"]["variant_scores"][0]["impact"]["evidence"] == {"rule": "x"}
    assert body["exceptions"] == [] and body["events"] == []
    assert get(env, f"/v1/findings/{uuid.uuid4()}", *READER).status_code == 404
    assert get(env, "/v1/findings/not-a-uuid", *READER).status_code == 422


def test_triage_changes_status_and_owner_and_records_who_did_what(env: Env) -> None:
    fid = one_finding(env)
    path = f"/v1/findings/{fid}"
    assert (
        patch(env, path, {"action": "set-status", "status": "in_corso"}, *TRIAGE).json()["finding"][
            "status"
        ]
        == "in_corso"
    )
    detail = patch(env, path, {"action": "set-owner", "owner": "bob"}, *TRIAGE).json()
    assert detail["finding"]["owner"] == "bob"
    events = detail["events"]
    assert [e["action"] for e in events] == ["set-owner", "set-status"]  # dal più recente
    assert events[1]["from_state"] == "aperto" and events[1]["to_state"] == "in_corso"
    assert events[0]["actor"] == "https://idp.example|user-1"
    assert (
        patch(env, path, {"action": "set-owner", "owner": None}, *TRIAGE)
        .json()["finding"]
        .get("owner")
        is None
    )


def test_a_false_positive_needs_a_reason_and_an_approver(env: Env) -> None:
    path = f"/v1/findings/{one_finding(env)}"
    body = {"action": "set-status", "status": "falso_positivo"}
    assert patch(env, path, body, *TRIAGE).status_code == 403
    missing = patch(env, path, body, *APPROVER)
    assert missing.status_code == 422 and missing.json()["errors"][0]["pointer"] == "/reason"
    done = patch(env, path, {**body, "reason": "input validato a monte"}, *APPROVER)
    assert done.status_code == 200 and done.json()["finding"]["status"] == "falso_positivo"
    assert done.json()["events"][0]["reason"] == "input validato a monte"


def test_an_exception_needs_an_approver_a_future_date_within_the_maximum_and_is_authenticated(
    env: Env,
) -> None:
    path = f"/v1/findings/{one_finding(env)}"

    def create(days: int, *groups: str, reason: str = "migrazione"):
        expires = (T0.date() + timedelta(days=days)).isoformat()
        return patch(
            env, path, {"action": "create-exception", "reason": reason, "expires": expires}, *groups
        )

    assert create(30, *TRIAGE).status_code == 403
    assert create(0, *APPROVER).status_code == 422 and create(-5, *APPROVER).status_code == 422
    too_long = create(366, *APPROVER)
    assert too_long.status_code == 422 and "365" in too_long.json()["errors"][0]["message"]
    done = create(30, *APPROVER)
    assert done.status_code == 200
    body = done.json()
    assert body["finding"]["status"] == "accettato"  # stato effettivo
    (exception,) = body["exceptions"]
    assert exception["origin"] == "server" and exception["approved_by_verified"] is True
    assert (
        exception["approved_by"] == "https://idp.example|user-1"
    )  # l'identità, non un testo del corpo
    listed = listing(env, status="accettato")["items"][0]
    assert listed["exception_origin"] == "server" and listed["status"] == "accettato"


def test_an_exception_can_be_revoked_once_and_the_finding_returns_to_its_state(env: Env) -> None:
    path = f"/v1/findings/{one_finding(env)}"
    expires = (T0.date() + timedelta(days=10)).isoformat()
    created = patch(
        env, path, {"action": "create-exception", "reason": "r", "expires": expires}, *APPROVER
    ).json()
    exception_id = created["exceptions"][0]["id"]
    revoke = {"action": "revoke-exception", "exception_id": exception_id}
    assert patch(env, path, revoke, *TRIAGE).status_code == 403
    done = patch(env, path, revoke, *APPROVER)
    assert done.status_code == 200 and done.json()["finding"]["status"] == "aperto"
    assert done.json()["exceptions"][0]["revoked_at"] is not None
    again = patch(env, path, revoke, *APPROVER)
    assert again.status_code == 409 and again.json()["code"] == "state-conflict"
    assert (
        patch(env, path, {**revoke, "exception_id": str(uuid.uuid4())}, *APPROVER).status_code
        == 404
    )


def test_a_repository_exception_is_shown_apart_unverified_and_cannot_be_revoked_here(
    env: Env,
) -> None:
    f = finding("a")
    data = json.loads(make_report([f]))
    data["exceptions"] = [
        {
            "fingerprint": f.fingerprint,
            "reason": "dal file",
            "expires": "2999-01-01",
            "approved_by": "Chiunque",
        }
    ]
    assert env.post(json.dumps(data).encode()).status_code == 201
    fid = str(listing(env)["items"][0]["id"])
    detail = get(env, f"/v1/findings/{fid}", *READER).json()
    (exception,) = detail["exceptions"]
    assert (exception["origin"], exception["approved_by"], exception["approved_by_verified"]) == (
        "repository",
        "Chiunque",
        False,
    )
    assert detail["finding"]["status"] == "accettato"
    assert listing(env)["items"][0]["exception_origin"] == "repository"
    revoke = {"action": "revoke-exception", "exception_id": exception["id"]}
    assert patch(env, f"/v1/findings/{fid}", revoke, *APPROVER).status_code == 409


def test_an_expired_exception_no_longer_accepts_the_finding(env: Env) -> None:
    f = finding("a")
    data = json.loads(make_report([f]))
    data["exceptions"] = [
        {
            "fingerprint": f.fingerprint,
            "reason": "scaduta",
            "expires": "2020-01-01",
            "approved_by": "x",
        }
    ]
    assert env.post(json.dumps(data).encode()).status_code == 201
    assert listing(env)["items"][0]["status"] == "aperto"


def test_a_resolved_finding_cannot_be_changed_by_a_user(env: Env) -> None:
    ingest(env, [finding("a"), finding("gone")], 0)
    ingest(env, [finding("a")], 10)
    gone = listing(env, status="risolto")["items"][0]["id"]
    path = f"/v1/findings/{gone}"
    assert (
        patch(env, path, {"action": "set-status", "status": "aperto"}, *TRIAGE).status_code == 409
    )
    expires = (T0.date() + timedelta(days=10)).isoformat()
    assert (
        patch(
            env, path, {"action": "create-exception", "reason": "r", "expires": expires}, *APPROVER
        ).status_code
        == 409
    )
    assert (
        patch(env, path, {"action": "set-status", "status": "risolto"}, *APPROVER).status_code
        == 422
    )


def test_a_pipeline_and_a_reader_cannot_touch_findings(env: Env) -> None:
    path = f"/v1/findings/{one_finding(env)}"
    body = {"action": "set-owner", "owner": "x"}
    assert patch(env, path, body, *READER).status_code == 403
    assert env.client.patch(path, headers=env.token(), json=body).status_code == 403
    assert patch(env, path, body, *ADMIN).status_code == 403


def test_the_status_set_by_a_user_survives_the_next_scan(
    env: Env,
) -> None:
    fid = one_finding(env)
    patch(env, f"/v1/findings/{fid}", {"action": "set-status", "status": "in_corso"}, *TRIAGE)
    ingest(env, [finding("a", level=Level.HIGH)], 10)
    assert get(env, f"/v1/findings/{fid}", *READER).json()["finding"]["status"] == "in_corso"


def test_new_on_a_full_scan_means_first_seen_in_that_scan(env: Env) -> None:
    ingest(env, [finding("old")], 0)
    ingest(env, [finding("old"), finding("fresh")], 10)
    page = listing(env)
    assert (page["total"], page["total_new"]) == (2, 1)
    assert titles(page) == ["t-fresh", "t-old"]  # i nuovi prima, a parità di livello
    assert titles(listing(env, new=True)) == ["t-fresh"]
    assert titles(listing(env, new=False)) == ["t-old"]
    assert [i["new"] for i in page["items"]] == [True, False]  # il campo coincide con il filtro
