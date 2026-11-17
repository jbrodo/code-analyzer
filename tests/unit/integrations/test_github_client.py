"""N-02: client GitHub con un trasporto finto e con un server finto in loopback (nessuna rete)."""

import json
import threading
from collections.abc import Callable, Mapping
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any

import pytest

from ca_integrations.github import (
    GitHubClient,
    GitHubError,
    Response,
    TransportError,
    UrllibTransport,
)
from ca_integrations.github.transport import MAX_RESPONSE_BYTES, check_base_url
from ca_integrations.models import (
    Annotation,
    CheckRun,
    CheckRunOutput,
    Conclusion,
    PullRequestComment,
)

TOKEN = "ghs_TOKEN-THAT-MUST-NEVER-APPEAR-0123456789"
MARKER = "<!-- code-analyzer:42 -->"
SHA = "a" * 40
REPO = "acme/shop"
BOT = "github-actions[bot]"


def comment(text: str = "# Code Analyzer\n") -> PullRequestComment:
    return PullRequestComment(
        marker=MARKER, body=f"{MARKER}\n{text}", findings_shown=1, findings_hidden=0
    )


def check(annotations: int = 0, conclusion: Conclusion = Conclusion.FAILURE) -> CheckRun:
    notes = [
        Annotation(
            path="app/a.py", start_line=3, end_line=4, level="warning", title="t", message="m"
        )
        for _ in range(annotations)
    ]
    return CheckRun(
        conclusion=conclusion,
        output=CheckRunOutput(title="Code Analyzer", summary="2 nuovi", annotations=notes),
    )


class Fake:
    """Trasporto finto: registra le richieste e risponde con una funzione."""

    def __init__(
        self, reply: Callable[[str, str, dict[str, Any] | None], Response | dict | list]
    ) -> None:
        self.reply = reply
        self.calls: list[tuple[str, str, Mapping[str, str], dict[str, Any] | None]] = []

    def request(
        self, method: str, url: str, headers: Mapping[str, str], body: bytes | None, timeout: float
    ) -> Response:
        payload = json.loads(body) if body else None
        self.calls.append((method, url, dict(headers), payload))
        result = self.reply(method, url, payload)
        if isinstance(result, Response):
            return result
        return Response(200, {}, json.dumps(result).encode())


def client(fake: Fake, **kw: Any) -> GitHubClient:
    return GitHubClient(TOKEN, transport=fake, **kw)


def user(login: str) -> dict[str, str]:
    return {"login": login}


# --- commento ------------------------------------------------------------------------------------


def test_a_new_comment_is_created_when_none_exists() -> None:
    def reply(method: str, url: str, payload: Any) -> Any:
        return [] if method == "GET" else {"id": 99}

    fake = Fake(reply)
    result = client(fake).upsert_comment(REPO, 7, comment())
    assert (result.id, result.created) == (99, True)
    methods = [(m, u.split("api.github.com")[1]) for m, u, _, _ in fake.calls]
    assert methods == [
        ("GET", f"/repos/{REPO}/issues/7/comments?per_page=100&page=1"),
        ("POST", f"/repos/{REPO}/issues/7/comments"),
    ]
    assert fake.calls[1][3] == {"body": comment().body}


def test_the_existing_comment_is_updated_not_duplicated() -> None:
    items = [{"id": 5, "user": user(BOT), "body": f"{MARKER}\nvecchio"}]

    def reply(method: str, url: str, payload: Any) -> Any:
        return items if method == "GET" else {"id": 5}

    fake = Fake(reply)
    result = client(fake).upsert_comment(REPO, 7, comment("nuovo\n"))
    assert (result.id, result.created) == (5, False)
    assert [m for m, *_ in fake.calls] == ["GET", "PATCH"]
    assert fake.calls[1][1].endswith(f"/repos/{REPO}/issues/comments/5")


@pytest.mark.parametrize(
    "item",
    [
        {"id": 1, "user": user("someone-else"), "body": f"{MARKER}\nforged"},  # altro autore
        {"id": 2, "user": user(BOT), "body": f"testo\n{MARKER}"},  # marcatore non iniziale
        {"id": 3, "user": user(BOT), "body": "senza marcatore"},
        {"id": 4, "user": None, "body": f"{MARKER}\n"},
        {"id": True, "user": user(BOT), "body": f"{MARKER}\n"},
        "non un oggetto",
    ],
    ids=["other-author", "marker-not-first", "no-marker", "no-user", "bool-id", "junk"],
)
def test_comments_that_are_not_ours_are_ignored(item: Any) -> None:
    fake = Fake(lambda m, u, p: [item] if m == "GET" else {"id": 100})
    assert client(fake).upsert_comment(REPO, 7, comment()).created is True


def test_the_author_is_configurable_and_the_comment_is_found_across_pages() -> None:
    pages = {
        1: [{"id": i, "user": user("x"), "body": "x"} for i in range(100)],
        2: [{"id": 200, "user": user("me"), "body": f"{MARKER}\n"}],
    }

    def reply(method: str, url: str, payload: Any) -> Any:
        if method != "GET":
            return {"id": 200}
        return pages[int(url.rsplit("page=", 1)[1])]

    fake = Fake(reply)
    assert client(fake, author="me").upsert_comment(REPO, 7, comment()).id == 200
    assert [m for m, *_ in fake.calls] == ["GET", "GET", "PATCH"]


def test_the_search_stops_at_the_page_cap_and_then_creates() -> None:
    full = [{"id": i, "user": user("x"), "body": "x"} for i in range(100)]
    fake = Fake(lambda m, u, p: full if m == "GET" else {"id": 1})
    assert client(fake).upsert_comment(REPO, 7, comment()).created is True
    assert sum(1 for m, *_ in fake.calls if m == "GET") == 20


# --- check run -----------------------------------------------------------------------------------


def test_the_check_run_is_created_completed_with_the_conclusion_and_annotations() -> None:
    fake = Fake(lambda m, u, p: {"id": 321})
    assert client(fake).create_check_run(REPO, SHA, check(annotations=2)) == 321
    method, url, _, payload = fake.calls[0]
    assert (method, url.endswith(f"/repos/{REPO}/check-runs")) == ("POST", True)
    assert payload["status"] == "completed" and payload["conclusion"] == "failure"
    assert payload["head_sha"] == SHA and payload["name"] == "Code Analyzer"
    assert payload["output"]["annotations"][0] == {
        "path": "app/a.py", "start_line": 3, "end_line": 4,
        "annotation_level": "warning", "title": "t", "message": "m",
    }  # fmt: skip


@pytest.mark.parametrize("conclusion", list(Conclusion))
def test_every_conclusion_reaches_the_provider(conclusion: Conclusion) -> None:
    fake = Fake(lambda m, u, p: {"id": 1})
    client(fake).create_check_run(REPO, SHA, check(conclusion=conclusion))
    assert fake.calls[0][3]["conclusion"] == conclusion.value


def test_a_check_run_without_annotations_has_no_annotations_key() -> None:
    fake = Fake(lambda m, u, p: {"id": 1})
    client(fake).create_check_run(REPO, SHA, check())
    assert "annotations" not in fake.calls[0][3]["output"]


# --- errori e sicurezza ---------------------------------------------------------------


@pytest.mark.parametrize(
    ("status", "headers", "code"),
    [
        (401, {}, "unauthorized"),
        (403, {}, "forbidden"),
        (403, {"x-ratelimit-remaining": "0"}, "rate-limited"),
        (403, {"retry-after": "30"}, "rate-limited"),
        (429, {}, "rate-limited"),
        (404, {}, "not-found"),
        (422, {}, "validation"),
        (409, {}, "validation"),
        (500, {}, "server"),
        (503, {}, "server"),
        (302, {"location": "https://evil.example/x"}, "redirect"),
        (418, {}, "client-error"),
    ],
)
def test_every_failure_maps_to_a_stable_code_that_never_carries_the_body_or_the_token(
    status: int, headers: dict[str, str], code: str
) -> None:
    body = f"errore con dati riservati e {TOKEN}".encode()
    fake = Fake(lambda m, u, p: Response(status, headers, body))
    with pytest.raises(GitHubError) as error:
        client(fake).upsert_comment(REPO, 7, comment())
    assert error.value.code == code and error.value.status == status
    assert TOKEN not in str(error.value) and "riservati" not in str(error.value)


def test_a_network_failure_and_a_garbled_answer_are_codes_not_leaks() -> None:
    class Down:
        def request(self, *a: Any, **k: Any) -> Response:
            raise TransportError("richiesta non riuscita")

    with pytest.raises(GitHubError) as network:
        GitHubClient(TOKEN, transport=Down()).find_comment(REPO, 1, MARKER)
    assert network.value.code == "network"
    for body, code in ((b"non json", "bad-response"), (b'{"not": "a list"}', "bad-response")):
        fake = Fake(lambda m, u, p, b=body: Response(200, {}, b))
        with pytest.raises(GitHubError) as error:
            client(fake).find_comment(REPO, 1, MARKER)
        assert error.value.code == code


def test_the_create_answers_must_carry_an_integer_id() -> None:
    for answer in ({"id": "7"}, {"id": True}, {}, [], None):
        fake = Fake(lambda m, u, p, a=answer: [] if m == "GET" else a)
        with pytest.raises(GitHubError):
            client(fake).upsert_comment(REPO, 7, comment())
    with pytest.raises(GitHubError):
        client(Fake(lambda m, u, p: {"id": "x"})).create_check_run(REPO, SHA, check())


def test_the_token_is_only_in_the_authorization_header_and_hidden_everywhere_else() -> None:
    fake = Fake(lambda m, u, p: [] if m == "GET" else {"id": 1})
    api = client(fake)
    api.upsert_comment(REPO, 7, comment())
    for _, url, headers, payload in fake.calls:
        assert TOKEN not in url and TOKEN not in json.dumps(payload)
        assert headers["Authorization"] == f"Bearer {TOKEN}"
        assert headers["X-GitHub-Api-Version"] == "2022-11-28" and "Accept" in headers
    assert TOKEN not in repr(api) and TOKEN not in str(vars(api).get("_base", ""))


@pytest.mark.parametrize("token", ["", "a b", "a\nb", "a\r\nX-Evil: 1", "a\x00b"])
def test_a_token_that_could_inject_headers_is_refused(token: str) -> None:
    with pytest.raises(ValueError, match="token"):
        GitHubClient(token, transport=Fake(lambda m, u, p: {}))


@pytest.mark.parametrize(
    "url",
    [
        "http://api.github.com",
        "ftp://x",
        "file:///etc/passwd",
        "https://u:p@api.github.com",
        "https://",
        "api.github.com",
        "https://a.example/?x=1",
    ],
)
def test_the_api_address_must_be_https_without_credentials(url: str) -> None:
    with pytest.raises(ValueError, match="indirizzo"):
        GitHubClient(TOKEN, api_url=url, transport=Fake(lambda m, u, p: {}))


def test_plain_http_is_allowed_only_on_loopback_and_only_when_asked() -> None:
    assert (
        check_base_url("http://127.0.0.1:8080/", allow_loopback_http=True)
        == "http://127.0.0.1:8080"
    )
    assert check_base_url("http://localhost:1", allow_loopback_http=True) == "http://localhost:1"
    for url in ("http://127.0.0.1:8080", "http://evil.example", "http://10.0.0.1"):
        with pytest.raises(ValueError):
            check_base_url(url, allow_loopback_http=False if "127" in url else True)


@pytest.mark.parametrize(
    "repo", ["", "acme", "acme/", "/shop", "a/b/c", "a b/c", "acme/shop\n", "../x/y"]
)
def test_a_malformed_repository_never_reaches_the_url(repo: str) -> None:
    fake = Fake(lambda m, u, p: {"id": 1})
    for call in (
        lambda: client(fake).find_comment(repo, 1, MARKER),
        lambda: client(fake).create_check_run(repo, SHA, check()),
    ):
        with pytest.raises(ValueError):
            call()
    assert fake.calls == []


@pytest.mark.parametrize("sha", ["", "abc", "A" * 40, "g" * 40, "a" * 41])
def test_a_bad_commit_is_refused(sha: str) -> None:
    with pytest.raises(ValueError, match="commit"):
        client(Fake(lambda m, u, p: {"id": 1})).create_check_run(REPO, sha, check())


def test_a_bad_pull_request_number_is_refused() -> None:
    for number in (0, -1):
        with pytest.raises(ValueError):
            client(Fake(lambda m, u, p: [])).find_comment(REPO, number, MARKER)


# --- trasporto reale contro un server in loopback -----------------------------------------


class Handler(BaseHTTPRequestHandler):
    log: list[dict[str, Any]] = []
    mode = "ok"

    def log_message(self, *args: Any) -> None:
        return

    def _handle(self) -> None:
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length) if length else b""
        type(self).log.append(
            {
                "method": self.command,
                "path": self.path,
                "auth": self.headers.get("Authorization"),
                "body": body,
            }
        )
        mode = type(self).mode
        if mode == "redirect":
            self.send_response(302)
            self.send_header("Location", f"http://127.0.0.1:{self.server.server_port}/elsewhere")  # type: ignore[attr-defined]
            self.end_headers()
            return
        if mode == "huge":
            self.send_response(200)
            self.send_header("Content-Length", str(MAX_RESPONSE_BYTES + 10))
            self.end_headers()
            self.wfile.write(b"x" * (MAX_RESPONSE_BYTES + 10))
            return
        if mode == "error-body":
            data = f"segreto {TOKEN}".encode()
            self.send_response(500)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
            return
        data = json.dumps([] if self.command == "GET" else {"id": 77}).encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    do_GET = do_POST = do_PATCH = _handle  # noqa: N815


@pytest.fixture
def server():
    Handler.log = []
    Handler.mode = "ok"
    httpd = HTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    yield httpd
    httpd.shutdown()
    httpd.server_close()


def real(server: HTTPServer) -> GitHubClient:
    return GitHubClient(
        TOKEN,
        api_url=f"http://127.0.0.1:{server.server_port}",
        transport=UrllibTransport(),
        allow_loopback_http=True,
        timeout=5,
    )


def test_a_full_round_trip_over_http_sends_the_token_and_the_json(server: HTTPServer) -> None:
    result = real(server).upsert_comment(REPO, 7, comment())
    assert (result.id, result.created) == (77, True)
    get, post = Handler.log
    assert get["method"] == "GET" and post["method"] == "POST"
    assert post["auth"] == f"Bearer {TOKEN}" and json.loads(post["body"]) == {
        "body": comment().body
    }
    assert real(server).create_check_run(REPO, SHA, check(annotations=1)) == 77


def test_a_redirect_is_refused_and_the_token_is_never_sent_to_the_target(
    server: HTTPServer,
) -> None:
    Handler.mode = "redirect"
    with pytest.raises(GitHubError) as error:
        real(server).find_comment(REPO, 7, MARKER)
    assert error.value.code == "redirect"
    assert [e["path"] for e in Handler.log] == [
        f"/repos/{REPO}/issues/7/comments?per_page=100&page=1"
    ]


def test_an_oversized_answer_is_a_network_error_not_memory(server: HTTPServer) -> None:
    Handler.mode = "huge"
    with pytest.raises(GitHubError) as error:
        real(server).find_comment(REPO, 7, MARKER)
    assert error.value.code == "network"


def test_an_error_body_that_echoes_the_token_never_reaches_the_exception(
    server: HTTPServer,
) -> None:
    Handler.mode = "error-body"
    with pytest.raises(GitHubError) as error:
        real(server).find_comment(REPO, 7, MARKER)
    assert (
        error.value.code == "server"
        and TOKEN not in str(error.value)
        and TOKEN not in repr(error.value)
    )


def test_a_closed_port_is_a_network_error() -> None:
    api = GitHubClient(
        TOKEN,
        api_url="http://127.0.0.1:1",
        transport=UrllibTransport(),
        allow_loopback_http=True,
        timeout=2,
    )
    with pytest.raises(GitHubError) as error:
        api.find_comment(REPO, 7, MARKER)
    assert error.value.code == "network"
