"""B-04, B-05: autenticazione e matrice dei ruoli di ADR-0019 sulle route dichiarate."""

import uuid

import pytest
from apiauth import GITHUB_IDP, USER_IDP, make_client
from fastapi.testclient import TestClient
from idp import build, pipeline_issuer, user_issuer

from ca_api.app import create_app
from ca_api.config import Settings

ID = str(uuid.uuid4())
PROBLEM = "application/problem+json"

CLIENT, TOKENS = make_client()
READ_ROLES = ["lettore", "triage", "approvatore", "amministratore"]

# (metodo, percorso, corpo) delle route che i soli utenti con un ruolo di lettura raggiungono
READ_ROUTES = [
    ("GET", "/v1/repositories", None),
    ("GET", f"/v1/repositories/{ID}", None),
    ("GET", f"/v1/repositories/{ID}/scans", None),
    ("GET", f"/v1/repositories/{ID}/findings", None),
    ("GET", f"/v1/findings/{ID}", None),
    ("GET", f"/v1/repositories/{ID}/sbom", None),
    ("GET", f"/v1/repositories/{ID}/graph", None),
]
SCAN_READ_ROUTES = [("GET", f"/v1/scans/{ID}", None), ("GET", f"/v1/scans/{ID}/sarif", None)]
PIPELINE_ROUTES = [("POST", "/v1/scans", None), ("GET", "/v1/service-context", None)]
UPLOAD = {"files": {"report": ("r.json", b"{}", "application/json")}}


def call(method: str, path: str, who: str, **kw: object):
    extra = UPLOAD if (method, path) == ("POST", "/v1/scans") else kw
    return CLIENT.request(method, path, headers={"Authorization": TOKENS[who]}, **extra)


# --- autenticazione -------------------------------------------------------------------------------


def test_no_token_is_401_with_a_challenge() -> None:
    response = CLIENT.get("/v1/me")
    assert response.status_code == 401
    assert response.headers["content-type"].startswith(PROBLEM)
    assert response.headers["www-authenticate"] == "Bearer"
    assert response.json()["code"] == "unauthenticated"


@pytest.mark.parametrize(
    "header",
    ["Basic dXNlcjpwYXNz", "Bearer", "Bearer not.a.jwt", "Bearer " + "x" * 20_000, "Token abc"],
)
def test_a_bad_authorization_header_is_401_and_never_echoed(header: str) -> None:
    response = CLIENT.get("/v1/me", headers={"Authorization": header})
    assert response.status_code == 401
    secret = header.split(" ", 1)[-1]
    assert len(secret) < 6 or secret not in response.text  # un token lungo non viene mai ripetuto
    assert response.json()["code"] == "unauthenticated"


def test_an_invalid_token_challenges_with_invalid_token() -> None:
    response = CLIENT.get("/v1/me", headers={"Authorization": "Bearer a.b.c"})
    assert response.headers["www-authenticate"] == 'Bearer error="invalid_token"'


def test_without_any_configured_issuer_every_authenticated_request_is_401() -> None:
    client = TestClient(create_app(Settings()))
    assert client.get("/v1/me", headers={"Authorization": TOKENS["tutti"]}).status_code == 401


def test_a_token_from_an_unconfigured_issuer_is_401() -> None:
    _, fetcher, _, verifier = build(user_issuer())
    fetcher.publish(USER_IDP.jwks_url, USER_IDP.jwk())
    client = TestClient(create_app(Settings(), verifier=verifier))
    assert client.get("/v1/me", headers={"Authorization": TOKENS["pipeline"]}).status_code == 401


def test_a_pipeline_owner_outside_the_map_is_403() -> None:
    _, fetcher, _, verifier = build(pipeline_issuer())
    fetcher.publish(GITHUB_IDP.jwks_url, GITHUB_IDP.jwk())
    claims = GITHUB_IDP.claims(repository_id="1", repository_owner_id="999")
    client = TestClient(create_app(Settings(), verifier=verifier))
    response = client.post(
        "/v1/scans", headers={"Authorization": "Bearer " + GITHUB_IDP.sign(claims)}, **UPLOAD
    )
    assert response.status_code == 403 and response.json()["code"] == "forbidden"


# --- GET /me --------------------------------------------------------------------------------------


def test_me_is_200_for_any_user_even_without_roles_and_lists_identity_roles_and_tenant() -> None:
    response = call("GET", "/v1/me", "nessun ruolo")
    assert response.status_code == 200
    assert response.json() == {
        "issuer": "https://idp.example",
        "subject": "user-1",
        "name": "Ada",
        "email": "ada@example.org",
        "tenant": "acme",
        "roles": [],
    }
    both = call("GET", "/v1/me", "tutti").json()
    assert set(both["roles"]) == set(READ_ROLES)


def test_me_is_forbidden_to_a_pipeline() -> None:
    response = call("GET", "/v1/me", "pipeline")
    assert response.status_code == 403 and response.json()["required_role"] == "utente"


# --- matrice ----------------------------------------------------------------------------


@pytest.mark.parametrize("who", READ_ROLES)
@pytest.mark.parametrize(("method", "path", "body"), READ_ROUTES + SCAN_READ_ROUTES)
def test_every_role_can_read(method: str, path: str, body: object, who: str) -> None:
    assert call(method, path, who).status_code == 500  # autorizzato: arriva alla route


@pytest.mark.parametrize(("method", "path", "body"), READ_ROUTES + SCAN_READ_ROUTES)
def test_a_user_without_roles_is_403_everywhere_but_me(
    method: str, path: str, body: object
) -> None:
    response = call(method, path, "nessun ruolo")
    assert response.status_code == 403 and response.json()["required_role"] == "lettore"


@pytest.mark.parametrize(("method", "path", "body"), READ_ROUTES)
def test_a_pipeline_cannot_read_what_users_read(method: str, path: str, body: object) -> None:
    assert call(method, path, "pipeline").status_code == 403


@pytest.mark.parametrize(("method", "path", "body"), SCAN_READ_ROUTES + PIPELINE_ROUTES)
def test_a_pipeline_reaches_its_own_routes(method: str, path: str, body: object) -> None:
    response = call(method, path, "pipeline")
    # autorizzata: arriva alla route, che senza database né archivio configurati risponde 500
    assert response.status_code == 500


@pytest.mark.parametrize("who", READ_ROLES + ["nessun ruolo"])
@pytest.mark.parametrize(("method", "path", "body"), PIPELINE_ROUTES)
def test_a_user_cannot_upload_scans_or_read_the_service_context(
    method: str, path: str, body: object, who: str
) -> None:
    response = call(method, path, who)
    assert response.status_code == 403 and response.json()["required_role"] == "pipeline"


@pytest.mark.parametrize(
    ("who", "expected"),
    [
        ("lettore", 403),
        ("triage", 403),
        ("approvatore", 403),
        ("amministratore", 500),
        ("pipeline", 403),
    ],
)
def test_only_the_administrator_registers_tier_and_exposure(who: str, expected: int) -> None:
    assert call("PATCH", f"/v1/repositories/{ID}", who, json={"tier": 1}).status_code == expected


PATCHES = {
    "owner": {"action": "set-owner", "owner": "ada"},
    "in_corso": {"action": "set-status", "status": "in_corso"},
    "aperto": {"action": "set-status", "status": "aperto"},
    "falso_positivo": {"action": "set-status", "status": "falso_positivo", "reason": "r"},
    "create-exception": {"action": "create-exception", "reason": "r", "expires": "2999-01-01"},
    "revoke-exception": {"action": "revoke-exception", "exception_id": ID},
}


@pytest.mark.parametrize(
    ("who", "patch", "expected"),
    [
        # triage: stato aperto o in corso e owner
        *[("triage", p, 500) for p in ("owner", "in_corso", "aperto")],
        *[("triage", p, 403) for p in ("falso_positivo", "create-exception", "revoke-exception")],
        # approvatore: tutto
        *[("approvatore", p, 500) for p in PATCHES],
        # lettore, amministratore, pipeline e senza ruolo: nulla
        *[("lettore", p, 403) for p in PATCHES],
        *[("amministratore", p, 403) for p in PATCHES],
        *[("pipeline", p, 403) for p in PATCHES],
        *[("nessun ruolo", p, 403) for p in PATCHES],
    ],
)
def test_finding_patch_roles(who: str, patch: str, expected: int) -> None:
    response = call("PATCH", f"/v1/findings/{ID}", who, json=PATCHES[patch])
    assert response.status_code == expected, (who, patch)
    if expected == 403:
        needed = (
            "approvatore"
            if patch in ("falso_positivo", "create-exception", "revoke-exception")
            else "triage"
        )
        assert response.json()["required_role"] in {needed, "triage"}


def test_a_forbidden_answer_names_the_role_required_for_the_action_asked() -> None:
    response = call("PATCH", f"/v1/findings/{ID}", "triage", json=PATCHES["falso_positivo"])
    assert response.json()["required_role"] == "approvatore"
    response = call("PATCH", f"/v1/findings/{ID}", "lettore", json=PATCHES["owner"])
    assert response.json()["required_role"] == "triage"


def test_administrator_does_not_include_approver_and_triage_includes_reader() -> None:
    assert (
        call(
            "PATCH", f"/v1/findings/{ID}", "amministratore", json=PATCHES["falso_positivo"]
        ).status_code
        == 403
    )
    assert call("GET", f"/v1/repositories/{ID}/findings", "triage").status_code == 500


def test_a_forbidden_response_never_contains_the_token() -> None:
    token = TOKENS["lettore"].split(" ", 1)[1]
    assert token not in call("PATCH", f"/v1/repositories/{ID}", "lettore", json={"tier": 1}).text
