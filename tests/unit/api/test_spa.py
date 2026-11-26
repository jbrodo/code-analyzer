"""I-03: la SPA servita dal processo dell'API, senza coprire `/v1` e senza uscire dalla cartella."""

import re
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from ca_api.app import create_app
from ca_api.config import Settings

TEMPLATE = (
    '<!doctype html><title>Code Analyzer</title><meta name="csp-nonce" content="__CSP_NONCE__">'
    "<div id=root></div>"
)
NONCE = re.compile(r'name="csp-nonce" content="([A-Za-z0-9_-]{16,})"')


@pytest.fixture
def web(tmp_path: Path) -> Path:
    root = tmp_path / "web"
    (root / "assets").mkdir(parents=True)
    (root / "index.html").write_text(TEMPLATE)
    (root / "assets" / "index-abc123.js").write_text("console.log(1)")
    (root / "favicon.svg").write_text("<svg/>")
    (root / "config.json").write_text('{"issuer": "https://idp.example.org", "clientId": "web"}')
    (tmp_path / "secret.txt").write_text("fuori dalla cartella")
    return root


def client(web: Path, **kw: object) -> TestClient:
    return TestClient(create_app(Settings(web_dir=str(web), **kw)))  # type: ignore[arg-type]


def test_the_root_and_every_view_address_get_index_html(web: Path) -> None:
    c = client(web)
    for path in ("/", "/r/6f1c7a6e", "/r/6f1c7a6e/f/abc?level=alto", "/auth/callback", "/scans"):
        reply = c.get(path)
        assert reply.status_code == 200 and "<div id=root>" in reply.text, path
        assert reply.headers["cache-control"] == "no-store"
        assert "__CSP_NONCE__" not in reply.text


def test_files_are_served_and_assets_are_cached_forever(web: Path) -> None:
    c = client(web)
    asset = c.get("/assets/index-abc123.js")
    assert asset.status_code == 200 and asset.text == "console.log(1)"
    assert asset.headers["cache-control"] == "public, max-age=31536000, immutable"
    assert c.get("/favicon.svg").headers["cache-control"] == "no-cache"


def test_a_missing_file_is_404_not_html(web: Path) -> None:
    c = client(web)
    for path in ("/assets/nope.js", "/missing.css", "/r/x/file.map"):
        assert c.get(path).status_code == 404, path


def test_the_api_is_never_shadowed_by_the_spa(web: Path) -> None:
    c = client(web)
    unknown = c.get("/v1/does-not-exist")
    assert unknown.status_code == 404 and "<" not in unknown.text
    assert c.get("/v1").status_code == 404
    assert c.get("/v1/health").json() == {"status": "ok"}
    assert c.post("/r/x").status_code == 405  # la SPA risponde solo a GET


@pytest.mark.parametrize(
    "path",
    [
        "/../secret.txt",
        "/%2e%2e/secret.txt",
        "/assets/../../secret.txt",
        "/assets/%2e%2e/%2e%2e/secret.txt",
        "/..%2fsecret.txt",
        "/a%00b",
        "/assets\\..\\..\\secret.txt",
        "/" + "a" * 400,
    ],
)
def test_no_path_reaches_outside_the_folder(web: Path, path: str) -> None:
    reply = client(web).get(path)
    assert "fuori dalla cartella" not in reply.text
    assert reply.status_code in (200, 404)
    if reply.status_code == 200:
        assert "<div id=root>" in reply.text


def test_a_symlink_that_leaves_the_folder_is_not_followed(web: Path, tmp_path: Path) -> None:
    (web / "link.txt").symlink_to(tmp_path / "secret.txt")
    assert client(web).get("/link.txt").status_code == 404


def test_config_json_comes_from_the_environment_file_and_is_never_cached(
    web: Path, tmp_path: Path
) -> None:
    other = tmp_path / "env-config.json"
    other.write_text('{"issuer": "https://idp.prod.example.org", "clientId": "prod"}')
    reply = client(web, web_config=str(other)).get("/config.json")
    assert reply.json()["clientId"] == "prod" and reply.headers["cache-control"] == "no-store"
    assert (
        client(web).get("/config.json").json()["clientId"] == "web"
    )  # senza file: quello della SPA


def test_every_response_carries_the_security_headers_with_only_the_idp_as_extra_origin(
    web: Path,
) -> None:
    reply = client(web, csp_connect=("https://idp.example.org",)).get("/")
    policy = reply.headers["content-security-policy"]
    assert "connect-src 'self' https://idp.example.org" in policy
    assert "default-src 'none'" in policy and "frame-ancestors 'none'" in policy
    assert (
        "script-src 'self'" in policy
        and "unsafe-inline" not in policy
        and "unsafe-eval" not in policy
    )
    assert reply.headers["x-content-type-options"] == "nosniff"
    assert (
        reply.headers["referrer-policy"] == "no-referrer"
        and reply.headers["x-frame-options"] == "DENY"
    )
    assert (
        "frame-ancestors"
        in client(web).get("/assets/index-abc123.js").headers["content-security-policy"]
    )


def test_the_style_nonce_is_new_in_every_index_and_matches_the_policy(web: Path) -> None:
    c = client(web)
    seen = set()
    for path in ("/", "/", "/r/x"):
        reply = c.get(path)
        nonce = NONCE.search(reply.text)
        assert nonce is not None
        seen.add(nonce.group(1))
        assert (
            f"style-src 'self' 'nonce-{nonce.group(1)}'" in reply.headers["content-security-policy"]
        )
    assert len(seen) == 3
    # un file statico non porta il nonce: non ha stili da autorizzare
    assert "nonce-" not in c.get("/assets/index-abc123.js").headers["content-security-policy"]


def test_without_a_web_dir_the_api_is_unchanged() -> None:
    c = TestClient(create_app(Settings()))
    assert c.get("/").status_code == 404 and c.get("/v1/health").status_code == 200


def test_a_folder_without_index_html_is_a_configuration_error(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="index.html"):
        create_app(Settings(web_dir=str(tmp_path)))


def test_the_settings_read_the_environment() -> None:
    settings = Settings.from_env(
        {
            "CA_API_WEB_DIR": "/srv/web",
            "CA_API_WEB_CONFIG": "/etc/ca/web.json",
            "CA_API_CSP_CONNECT": "https://a.example, https://b.example",
        }
    )
    assert (settings.web_dir, settings.web_config) == ("/srv/web", "/etc/ca/web.json")
    assert settings.csp_connect == ("https://a.example", "https://b.example")
