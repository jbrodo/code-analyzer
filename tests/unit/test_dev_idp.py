"""I-05, W-03: l'IdP finto parla authorization code con PKCE e firma token che l'API accetta."""

import base64
import hashlib
import importlib.util
import json
import threading
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Iterator
from http.server import ThreadingHTTPServer
from pathlib import Path
from types import ModuleType

import jwt
import pytest

SOURCE = Path(__file__).resolve().parents[2] / "deploy/docker/dev-idp/idp.py"
REDIRECT = "http://localhost:5173/auth/callback"


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args: object, **kwargs: object) -> None:  # type: ignore[override]
        return None


@pytest.fixture(scope="module")
def idp() -> Iterator[tuple[ModuleType, str]]:
    spec = importlib.util.spec_from_file_location("dev_idp", SOURCE)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    server = ThreadingHTTPServer(("127.0.0.1", 0), module.Handler)
    base = f"http://127.0.0.1:{server.server_port}"
    module.BASE = base
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield module, base
    server.shutdown()


def call(url: str, *, data: dict[str, str] | None = None, origin: str | None = None):
    body = urllib.parse.urlencode(data).encode() if data is not None else None
    request = urllib.request.Request(url, data=body, method="POST" if data is not None else "GET")
    if origin:
        request.add_header("Origin", origin)
    opener = urllib.request.build_opener(_NoRedirect)
    try:
        return opener.open(request, timeout=5)
    except urllib.error.HTTPError as error:
        return error


def challenge(verifier: str) -> str:
    digest = hashlib.sha256(verifier.encode()).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode()


def authorize(base: str, verifier: str, profile: str = "approvatore", redirect: str = REDIRECT):
    query = urllib.parse.urlencode(
        {
            "response_type": "code",
            "client_id": "ca-spa",
            "redirect_uri": redirect,
            "state": "st-1",
            "nonce": "nn-1",
            "code_challenge": challenge(verifier),
            "code_challenge_method": "S256",
            "profile": profile,
        }
    )
    return call(f"{base}/user/authorize?{query}")


def code_of(response) -> str:
    location = urllib.parse.urlsplit(response.headers["Location"])
    query = urllib.parse.parse_qs(location.query)
    assert query["state"] == ["st-1"]
    return query["code"][0]


def exchange(base: str, code: str, verifier: str, **over: str):
    form = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": REDIRECT,
        "client_id": "ca-spa",
        "code_verifier": verifier,
    }
    return call(f"{base}/user/token", data={**form, **over}, origin="http://localhost:5173")


def test_discovery_names_the_issuer_the_api_trusts(idp) -> None:
    _, base = idp
    doc = json.load(call(f"{base}/user/.well-known/openid-configuration"))
    assert doc["issuer"] == f"{base}/user"
    assert doc["code_challenge_methods_supported"] == ["S256"]


def test_the_authorization_code_flow_gives_a_token_with_the_roles_of_the_profile(idp) -> None:
    module, base = idp
    verifier = "v" * 43
    reply = authorize(base, verifier)
    assert reply.status == 302
    done = exchange(base, code_of(reply), verifier)
    assert (
        done.status == 200
        and done.headers["Access-Control-Allow-Origin"] == "http://localhost:5173"
    )
    body = json.load(done)
    keys = json.load(call(f"{base}/user/jwks.json"))["keys"]
    signing = jwt.PyJWK(keys[0]).key
    claims = jwt.decode(
        body["access_token"], signing, algorithms=["RS256"], audience=module.AUDIENCE
    )
    assert claims["iss"] == f"{base}/user" and claims["groups"] == ["triagers", "approvers"]
    id_claims = jwt.decode(body["id_token"], signing, algorithms=["RS256"], audience="ca-spa")
    assert id_claims["nonce"] == "nn-1"
    assert body["token_type"] == "Bearer" and body["expires_in"] == module.LIFETIME


def test_a_code_works_once_and_only_with_its_verifier_and_redirect(idp) -> None:
    _, base = idp
    verifier = "w" * 43
    code = code_of(authorize(base, verifier))
    assert (
        exchange(base, code, "x" * 43).status == 400
    )  # verificatore sbagliato: il codice è bruciato
    assert exchange(base, code, verifier).status == 400
    code = code_of(authorize(base, verifier))
    assert exchange(base, code, verifier, redirect_uri="http://localhost:9/other").status == 400
    code = code_of(authorize(base, verifier))
    assert exchange(base, code, verifier).status == 200
    assert exchange(base, code, verifier).status == 400  # secondo uso


def test_only_loopback_redirects_and_s256_are_accepted(idp) -> None:
    _, base = idp
    assert authorize(base, "v" * 43, redirect="https://evil.example/cb").status == 400
    assert authorize(base, "v" * 43, redirect="http://localhost:1@evil.example/cb").status == 400
    plain = call(
        f"{base}/user/authorize?response_type=code&redirect_uri={urllib.parse.quote(REDIRECT)}&code_challenge=x&code_challenge_method=plain&profile=lettore"
    )
    assert plain.status == 400


def test_without_a_profile_the_page_asks_for_one_and_escapes_what_it_echoes(idp) -> None:
    _, base = idp
    query = urllib.parse.urlencode(
        {
            "response_type": "code",
            "redirect_uri": REDIRECT,
            "code_challenge": "c",
            "code_challenge_method": "S256",
            "state": '"><script>1</script>',
        }
    )
    page = call(f"{base}/user/authorize?{query}").read().decode()
    assert "amministratore" in page and "<script>" not in page


def test_cors_only_for_local_origins(idp) -> None:
    _, base = idp
    assert (
        call(f"{base}/user/jwks.json", origin="https://evil.example").headers.get(
            "Access-Control-Allow-Origin"
        )
        is None
    )
