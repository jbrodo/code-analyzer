"""IdP finto per lo sviluppo del server (I-05, ADR-0019). NON e' un IdP: niente autenticazione.

Chiunque raggiunga la porta ottiene un token con i gruppi o i claim che chiede, quindi sta solo su
loopback e solo in questo compose. Le chiavi RSA nascono a ogni avvio e restano in memoria: nessun
segreto nel repository, e un riavvio invalida i token emessi.

  GET  /{user|github}/jwks.json                       chiavi pubbliche dell'emittente
  POST /user/token?sub=ada&groups=readers,triagers    token di un utente (per curl)
  POST /github/token?repository=acme/shop&repository_id=9001&owner_id=4242&ref=refs/heads/main

Per la SPA (W-03) parla OIDC authorization code con PKCE S256, come client pubblico:
  GET  /user/.well-known/openid-configuration         scoperta
  GET  /user/authorize?...                            un profilo per ruolo, senza password
  POST /user/token  (grant_type=authorization_code)   scambio del codice, con CORS per localhost

L'emittente (`iss`) e' `ISSUER_BASE` + `/user` o `/github`: lo stesso valore va in `dev-auth.json`.
Solo libreria standard e PyJWT/cryptography, gia' nell'immagine del server.
"""

import base64
import hashlib
import html
import json
import os
import secrets
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlencode, urlsplit

import jwt
from cryptography.hazmat.primitives.asymmetric import rsa

BASE = os.environ.get("ISSUER_BASE", "http://idp:9000").rstrip("/")
AUDIENCE = os.environ.get("AUDIENCE", "code-analyzer")
LIFETIME = 600
KID = "dev-1"
KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
JWK = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(KEY.public_key()))
JWK.update({"kid": KID, "use": "sig", "alg": "RS256"})


PROFILES = {
    "lettore": ["readers"],
    "triage": ["triagers"],
    "approvatore": ["triagers", "approvers"],
    "amministratore": ["admins"],
    "tutti i ruoli": ["readers", "triagers", "approvers", "admins"],
}
CODES: dict[str, dict[str, str | float]] = {}
CODE_LIFETIME = 60
LOCAL_ORIGINS = ("http://localhost:", "http://127.0.0.1:")


def local_redirect(uri: str) -> bool:
    return uri.startswith(LOCAL_ORIGINS) and "@" not in uri.split("/")[2]


def token(kind: str, query: dict[str, list[str]]) -> str:
    def one(name: str, default: str) -> str:
        return query.get(name, [default])[0][:200]

    now = int(time.time())
    claims: dict[str, object] = {"iss": f"{BASE}/{kind}", "aud": AUDIENCE, "iat": now, "nbf": now}
    claims["exp"] = now + LIFETIME
    if kind == "user":
        claims.update(
            sub=one("sub", "dev-user"),
            name=one("name", "Dev User"),
            email=one("email", "dev@example.org"),
            groups=[g for g in one("groups", "readers").split(",") if g],
        )
    else:
        claims.update(
            sub=f"repo:{one('repository', 'acme/shop')}:ref:{one('ref', 'refs/heads/main')}",
            repository=one("repository", "acme/shop"),
            repository_id=one("repository_id", "9001"),
            repository_owner_id=one("owner_id", "4242"),
            ref=one("ref", "refs/heads/main"),
        )
        if "sha" in query:
            claims["sha"] = one("sha", "")
    return jwt.encode(claims, KEY, algorithm="RS256", headers={"kid": KID})


class Handler(BaseHTTPRequestHandler):
    def _cors(self) -> None:
        origin = self.headers.get("Origin", "")
        if origin.startswith(LOCAL_ORIGINS):  # solo la SPA di sviluppo su loopback
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Access-Control-Allow-Headers", "Content-Type")
            self.send_header("Vary", "Origin")

    def _send(self, status: int, payload: object, *, kind: str = "application/json") -> None:
        body = payload if isinstance(payload, bytes) else json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", kind)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self._cors()
        self.end_headers()
        self.wfile.write(body)

    def _redirect(self, location: str) -> None:
        self.send_response(302)
        self.send_header("Location", location)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_OPTIONS(self) -> None:  # noqa: N802
        self.send_response(204)
        self._cors()
        self.send_header("Access-Control-Allow-Methods", "POST, GET")
        self.end_headers()

    def _authorize(self, query: dict[str, list[str]]) -> None:
        def one(name: str) -> str:
            return query.get(name, [""])[0][:2000]

        redirect = one("redirect_uri")
        if not local_redirect(redirect) or one("response_type") != "code":
            self._send(400, {"error": "invalid_request"})
            return
        if one("code_challenge_method") != "S256" or not one("code_challenge"):
            self._send(400, {"error": "invalid_request"})
            return
        profile = one("profile")
        if profile not in PROFILES:
            options = "".join(
                f'<p><button name="profile" value="{html.escape(name)}">'
                f"{html.escape(name)}</button></p>"
                for name in PROFILES
            )
            hidden = "".join(
                f'<input type="hidden" name="{html.escape(k)}" value="{html.escape(v[0])}">'
                for k, v in query.items()
            )
            page = (
                "<!doctype html><meta charset=utf-8><title>Accesso di sviluppo</title>"
                "<h1>Accesso di sviluppo</h1><p>IdP finto: nessuna password. Scegli un ruolo.</p>"
                f'<form method="get">{hidden}{options}</form>'
            )
            self._send(200, page.encode(), kind="text/html; charset=utf-8")
            return
        code = secrets.token_urlsafe(24)
        CODES[code] = {
            "challenge": one("code_challenge"),
            "profile": profile,
            "redirect_uri": redirect,
            "client_id": one("client_id"),
            "nonce": one("nonce"),
            "expires": time.time() + CODE_LIFETIME,
        }
        back = {"code": code, **({"state": one("state")} if one("state") else {})}
        self._redirect(f"{redirect}?{urlencode(back)}")

    def _exchange(self, form: dict[str, list[str]]) -> None:
        def one(name: str) -> str:
            return form.get(name, [""])[0]

        entry = CODES.pop(one("code"), None)  # si usa una volta sola
        digest = hashlib.sha256(one("code_verifier").encode()).digest()
        challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode()
        if (
            entry is None
            or float(entry["expires"]) < time.time()
            or entry["redirect_uri"] != one("redirect_uri")
            or entry["client_id"] != one("client_id")
            or not secrets.compare_digest(str(entry["challenge"]), challenge)
        ):
            self._send(400, {"error": "invalid_grant"})
            return
        groups = ",".join(PROFILES[str(entry["profile"])])
        access = token(
            "user",
            {
                "sub": [f"dev-{entry['profile']}"],
                "name": [str(entry["profile"])],
                "groups": [groups],
            },
        )
        id_claims = {
            "iss": f"{BASE}/user",
            "aud": one("client_id"),
            "sub": f"dev-{entry['profile']}",
            "nonce": entry["nonce"],
            "iat": int(time.time()),
            "exp": int(time.time()) + LIFETIME,
        }
        self._send(
            200,
            {
                "access_token": access,
                "token_type": "Bearer",
                "expires_in": LIFETIME,
                "id_token": jwt.encode(id_claims, KEY, algorithm="RS256", headers={"kid": KID}),
            },
        )

    def do_GET(self) -> None:  # noqa: N802
        url = urlsplit(self.path)
        parts = url.path.strip("/").split("/")
        if len(parts) == 2 and parts[0] in ("user", "github") and parts[1] == "jwks.json":
            self._send(200, {"keys": [JWK]})
        elif parts == ["user", ".well-known", "openid-configuration"]:
            self._send(
                200,
                {
                    "issuer": f"{BASE}/user",
                    "authorization_endpoint": f"{BASE}/user/authorize",
                    "token_endpoint": f"{BASE}/user/token",
                    "jwks_uri": f"{BASE}/user/jwks.json",
                    "response_types_supported": ["code"],
                    "code_challenge_methods_supported": ["S256"],
                    "id_token_signing_alg_values_supported": ["RS256"],
                },
            )
        elif parts == ["user", "authorize"]:
            self._authorize(parse_qs(url.query))
        elif parts == ["health"]:
            self._send(200, {"status": "ok"})
        else:
            self._send(404, {"error": "not-found"})

    def do_POST(self) -> None:  # noqa: N802
        url = urlsplit(self.path)
        parts = url.path.strip("/").split("/")
        length = min(int(self.headers.get("Content-Length") or 0), 8192)
        form = parse_qs(self.rfile.read(length).decode()) if length else {}
        if parts == ["user", "token"] and form.get("grant_type") == ["authorization_code"]:
            self._exchange(form)
        elif len(parts) == 2 and parts[0] in ("user", "github") and parts[1] == "token":
            self._send(200, {"token": token(parts[0], parse_qs(url.query))})
        else:
            self._send(404, {"error": "not-found"})

    def log_message(self, *_: object) -> None:  # niente indirizzi e query nei log
        return


if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", 9000), Handler).serve_forever()  # noqa: S104 - rete del compose
