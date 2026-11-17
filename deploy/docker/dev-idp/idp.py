"""IdP finto per lo sviluppo del server (I-05, ADR-0019). NON e' un IdP: niente autenticazione.

Chiunque raggiunga la porta ottiene un token con i gruppi o i claim che chiede, quindi sta solo su
loopback e solo in questo compose. Le chiavi RSA nascono a ogni avvio e restano in memoria: nessun
segreto nel repository, e un riavvio invalida i token emessi.

  GET  /{user|github}/jwks.json                       chiavi pubbliche dell'emittente
  POST /user/token?sub=ada&groups=readers,triagers    token di un utente
  POST /github/token?repository=acme/shop&repository_id=9001&owner_id=4242&ref=refs/heads/main

L'emittente (`iss`) e' `ISSUER_BASE` + `/user` o `/github`: lo stesso valore va in `dev-auth.json`.
Solo libreria standard e PyJWT/cryptography, gia' nell'immagine del server.
"""

import json
import os
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

import jwt
from cryptography.hazmat.primitives.asymmetric import rsa

BASE = os.environ.get("ISSUER_BASE", "http://idp:9000").rstrip("/")
AUDIENCE = os.environ.get("AUDIENCE", "code-analyzer")
LIFETIME = 600
KID = "dev-1"
KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
JWK = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(KEY.public_key()))
JWK.update({"kid": KID, "use": "sig", "alg": "RS256"})


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
    def _send(self, status: int, payload: object) -> None:
        body = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802
        parts = urlsplit(self.path).path.strip("/").split("/")
        if len(parts) == 2 and parts[0] in ("user", "github") and parts[1] == "jwks.json":
            self._send(200, {"keys": [JWK]})
        elif parts == ["health"]:
            self._send(200, {"status": "ok"})
        else:
            self._send(404, {"error": "not-found"})

    def do_POST(self) -> None:  # noqa: N802
        url = urlsplit(self.path)
        parts = url.path.strip("/").split("/")
        if len(parts) == 2 and parts[0] in ("user", "github") and parts[1] == "token":
            self._send(200, {"token": token(parts[0], parse_qs(url.query))})
        else:
            self._send(404, {"error": "not-found"})

    def log_message(self, *_: object) -> None:  # niente indirizzi e query nei log
        return


if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", 9000), Handler).serve_forever()  # noqa: S104 - rete del compose
