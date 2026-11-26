"""Un emittente OIDC finto in processo, con chiavi generate dal test (nessuna rete, regola 7)."""

import base64
import json
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

import jwt
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from ca_api.auth.config import AuthSettings, PipelineIssuer, UserIssuer
from ca_api.auth.jwks import JwksCache, JwksFetcher, KeysUnavailable
from ca_api.auth.verify import TokenVerifier
from ca_api.models import Role
from ca_core.fakes import FixedClock

ISSUER = "https://idp.example"
PIPELINE = "https://token.actions.example"
GITLAB = "https://gitlab.example"
AUDIENCE = "https://code-analyzer.example"
T0 = datetime(2026, 11, 17, 12, 0, tzinfo=UTC)


def _b64(number: int) -> str:
    raw = number.to_bytes((number.bit_length() + 7) // 8, "big")
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def rsa_key() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def ec_key() -> ec.EllipticCurvePrivateKey:
    return ec.generate_private_key(ec.SECP256R1())


def jwk_of(key: Any, kid: str) -> dict[str, Any]:
    public = (
        json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(key.public_key()))
        if isinstance(key, rsa.RSAPrivateKey)
        else json.loads(jwt.algorithms.ECAlgorithm.to_jwk(key.public_key()))
    )
    return {**public, "kid": kid, "use": "sig"}


class FakeJwks(JwksFetcher):
    """Serve il JWKS di ogni emittente e conta le richieste in uscita."""

    def __init__(self) -> None:
        self.documents: dict[str, bytes | Exception] = {}
        self.calls: list[str] = []

    def publish(self, url: str, *keys: dict[str, Any]) -> None:
        self.documents[url] = json.dumps({"keys": list(keys)}).encode()

    def fetch(self, url: str, *, max_bytes: int) -> bytes:
        self.calls.append(url)
        value = self.documents.get(url)
        if value is None:
            raise KeysUnavailable("status")
        if isinstance(value, Exception):
            raise value
        return value


@dataclass
class Idp:
    """Chiavi e token di un emittente. `sign` costruisce un JWT con i claim voluti."""

    issuer: str
    audience: str = AUDIENCE
    kid: str = "k1"
    key: Any = field(default_factory=rsa_key)
    algorithm: str = "RS256"

    @property
    def jwks_url(self) -> str:
        return f"{self.issuer}/.well-known/jwks.json"

    def jwk(self) -> dict[str, Any]:
        return jwk_of(self.key, self.kid)

    def claims(self, subject: str = "user-1", **extra: Any) -> dict[str, Any]:
        now = int(T0.timestamp())
        base = {
            "iss": self.issuer,
            "sub": subject,
            "aud": self.audience,
            "iat": now,
            "exp": now + 600,
        }
        return {**base, **extra}

    def sign(
        self,
        claims: dict[str, Any] | None = None,
        *,
        key: Any = None,
        algorithm: str | None = None,
        kid: str | None = "default",
        **extra: Any,
    ) -> str:
        payload = claims if claims is not None else self.claims(**extra)
        headers = {} if kid is None else {"kid": self.kid if kid == "default" else kid}
        return jwt.encode(
            payload, key or self.key, algorithm=algorithm or self.algorithm, headers=headers
        )


def user_issuer(**kv: Any) -> UserIssuer:
    return UserIssuer(
        issuer=ISSUER,
        audience=AUDIENCE,
        jwks_url=f"{ISSUER}/.well-known/jwks.json",
        tenant="acme",
        roles_claim="groups",
        roles_map={
            "readers": [Role.READER],
            "triagers": [Role.TRIAGE],
            "approvers": [Role.APPROVER],
            "admins": [Role.ADMIN],
        },
        **kv,
    )


def pipeline_issuer(provider: str = "github", **kv: Any) -> PipelineIssuer:
    issuer = PIPELINE if provider == "github" else GITLAB
    return PipelineIssuer(
        issuer=issuer,
        audience=AUDIENCE,
        jwks_url=f"{issuer}/.well-known/jwks.json",
        provider=provider,  # type: ignore[arg-type]
        owners={"4242": "acme"},
        **kv,
    )


def build(
    *issuers: UserIssuer | PipelineIssuer, **settings: Any
) -> tuple[AuthSettings, FakeJwks, FixedClock, TokenVerifier]:
    auth = AuthSettings(issuers=list(issuers), **settings)
    fetcher, clock = FakeJwks(), FixedClock(T0)
    verifier = TokenVerifier(auth, JwksCache(auth, fetcher, clock), clock)
    return auth, fetcher, clock, verifier
