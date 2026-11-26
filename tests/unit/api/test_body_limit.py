"""B-03: il limite di dimensione si applica mentre si legge il corpo (ADR-0016)."""

from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import PlainTextResponse
from starlette.routing import Route
from starlette.testclient import TestClient

from ca_api.limits import BodyLimitMiddleware

READ: list[int] = []


async def endpoint(request: Request) -> PlainTextResponse:
    body = await request.body()
    READ.append(len(body))
    return PlainTextResponse(str(len(body)))


def client(limit: int = 1000) -> TestClient:
    READ.clear()
    app = BodyLimitMiddleware(
        Starlette(routes=[Route("/", endpoint, methods=["POST", "GET"])]), max_bytes=limit
    )
    return TestClient(app)


def test_a_body_within_the_limit_passes_untouched() -> None:
    response = client().post("/", content=b"x" * 1000)
    assert (response.status_code, response.text) == (200, "1000")


def test_a_declared_length_over_the_limit_is_refused_before_reading() -> None:
    response = client().post("/", content=b"x" * 2000)
    assert response.status_code == 413
    assert response.headers["content-type"] == "application/problem+json"
    assert response.json()["code"] == "payload-too-large" and READ == []


def test_a_chunked_body_without_a_length_is_counted_while_it_is_read() -> None:
    def chunks():
        for _ in range(10):
            yield b"x" * 500

    response = client().post("/", content=chunks())
    assert response.status_code == 413 and READ == []


def test_a_lying_content_length_does_not_bypass_the_count() -> None:
    response = client().post("/", content=b"x" * 5000, headers={"Content-Length": "10"})
    assert response.status_code == 413


def test_the_refusal_names_no_value_and_no_internal_text() -> None:
    body = client().post("/", content=b"x" * 5000).text
    assert "Traceback" not in body and "xxxx" not in body


def test_requests_without_a_body_are_untouched() -> None:
    assert client().get("/").status_code == 200
