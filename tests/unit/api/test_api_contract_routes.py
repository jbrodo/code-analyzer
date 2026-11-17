"""C-08: le route dichiarate rispondono col formato di errore unico, anche senza realizzazione."""

import uuid

import pytest
from apiauth import make_client
from fastapi.testclient import TestClient

ID = str(uuid.uuid4())
PROBLEM = "application/problem+json"


PIPELINE_ONLY = {("POST", "/v1/scans"), ("GET", "/v1/service-context")}


@pytest.fixture
def client() -> TestClient:
    """Un client già autenticato: un utente con tutti i ruoli, o la pipeline dove serve."""
    client, tokens = make_client()
    client.headers["Authorization"] = tokens["tutti"]
    client.pipeline = tokens["pipeline"]  # type: ignore[attr-defined]
    return client


ROUTES = [
    ("GET", "/v1/me"),
    ("GET", "/v1/repositories"),
    ("GET", f"/v1/repositories/{ID}"),
    ("PATCH", f"/v1/repositories/{ID}"),
    ("GET", f"/v1/repositories/{ID}/scans"),
    ("POST", "/v1/scans"),
    ("GET", f"/v1/scans/{ID}"),
    ("GET", f"/v1/scans/{ID}/sarif"),
    ("GET", f"/v1/repositories/{ID}/findings"),
    ("GET", f"/v1/findings/{ID}"),
    ("PATCH", f"/v1/findings/{ID}"),
    ("GET", f"/v1/repositories/{ID}/sbom"),
    ("GET", f"/v1/repositories/{ID}/graph"),
    ("GET", "/v1/service-context"),
]
BODIES = {
    ("PATCH", f"/v1/repositories/{ID}"): {"json": {"tier": 2}},
    ("PATCH", f"/v1/findings/{ID}"): {"json": {"action": "set-owner", "owner": "ada"}},
    ("POST", "/v1/scans"): {"files": {"report": ("report.json", b"{}", "application/json")}},
}


@pytest.mark.parametrize(("method", "path"), ROUTES)
def test_an_authorized_route_without_a_database_answers_500_as_problem_json(
    client: TestClient, method: str, path: str
) -> None:
    headers = {"Authorization": client.pipeline} if (method, path) in PIPELINE_ONLY else {}  # type: ignore[attr-defined]
    response = client.request(method, path, headers=headers, **BODIES.get((method, path), {}))
    if (method, path) == ("GET", "/v1/me"):
        assert response.status_code == 200  # realizzato da B-04
        return
    assert response.status_code == 500
    assert response.headers["content-type"].startswith(PROBLEM)
    body = response.json()
    assert body["code"] == "internal-error" and body["status"] == 500
    assert set(body) <= {"type", "title", "status", "code", "detail", "required_role", "errors"}


def test_a_validation_error_is_a_problem_that_never_echoes_the_value(client: TestClient) -> None:
    secret = "valore-riservato-da-non-ripetere"
    response = client.get(f"/v1/repositories/{ID}/findings", params={"limit": secret})
    assert response.status_code == 422
    assert response.headers["content-type"].startswith(PROBLEM)
    body = response.json()
    assert body["code"] == "validation-failed"
    assert body["errors"][0]["pointer"] == "/query/limit"
    assert secret not in response.text


def test_a_bad_id_and_an_oversized_limit_are_validation_problems(client: TestClient) -> None:
    assert client.get("/v1/findings/not-a-uuid").json()["code"] == "validation-failed"
    too_many = client.get(f"/v1/repositories/{ID}/findings", params={"limit": 201})
    assert too_many.status_code == 422


def test_the_patch_body_must_be_one_known_action_with_no_extra_fields(client: TestClient) -> None:
    for body in (
        {"action": "set-owner", "owner": "ada", "approved_by": "someone-else"},
        {"action": "set-status", "status": "risolto"},
        {"action": "set-status", "status": "accettato"},
        {"action": "unknown"},
        {},
    ):
        response = client.patch(f"/v1/findings/{ID}", json=body)
        assert response.status_code == 422, body
        assert response.json()["code"] == "validation-failed"


def test_the_error_body_of_a_problem_has_no_stack_or_internal_text(client: TestClient) -> None:
    text = client.get("/v1/me").text
    assert "Traceback" not in text and 'File "' not in text
