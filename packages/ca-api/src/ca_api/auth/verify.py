"""Verifica dei token OIDC di utenti e pipeline (B-04, ADR-0019). Un solo percorso per entrambi.

1. Si legge `iss` senza fidarsi del resto e lo si cerca nell'elenco: un emittente sconosciuto è 401
   e non provoca alcuna richiesta in uscita (l'indirizzo delle chiavi viene dalla configurazione).
2. Firma con le chiavi pubbliche dell'emittente, con un elenco fisso di algoritmi asimmetrici:
   `none` e quelli simmetrici sono sempre respinti.
3. `aud` uguale a quello configurato; `exp`, `nbf` e `iat` con la tolleranza di orologio; durata
   `exp - iat` entro un massimo, così un emittente mal configurato non introduce token lunghi.
4. Le chiavi in memoria con una scadenza; un `kid` sconosciuto provoca un solo aggiornamento.

Gli errori hanno un codice stabile e mai un contenuto del token. Il tempo viene dal `Clock`.
"""

from dataclasses import dataclass, field
from typing import Any

import jwt

from ca_api.auth.config import (
    ALLOWED_ALGORITHMS,
    AuthSettings,
    PipelineIssuer,
    UserIssuer,
)
from ca_api.auth.jwks import JwksCache, KeysUnavailable
from ca_api.models import Role
from ca_core.ports import Clock

_REQUIRED = ("iss", "sub", "aud", "exp", "iat")


class AuthError(Exception):
    """Token non valido (401) o non ammesso (403). `code` è stabile; mai un valore del token."""

    def __init__(self, code: str, *, forbidden: bool = False) -> None:
        super().__init__(code)
        self.code = code
        self.forbidden = forbidden


@dataclass(frozen=True)
class PipelineRepository:
    provider: str
    external_id: str  # identificativo numerico dato dal provider, non il nome
    name: str | None
    owner_id: str
    ref: str | None = None
    sha: str | None = None


@dataclass(frozen=True)
class Identity:
    kind: str  # `user` o `pipeline`
    issuer: str
    subject: str
    tenant: str
    name: str | None = None
    email: str | None = None
    roles: frozenset[Role] = field(default_factory=frozenset)
    repository: PipelineRepository | None = None

    @property
    def actor(self) -> str:
        """Chi compare nel registro delle modifiche: la coppia `(iss, sub)` (ADR-0019)."""
        return f"{self.issuer}|{self.subject}"


def _text(claims: dict[str, Any], name: str, limit: int = 300) -> str | None:
    value = claims.get(name)
    return value[:limit] if isinstance(value, str) and value else None


def _id(claims: dict[str, Any], name: str) -> str | None:
    """Gli identificativi numerici dei provider arrivano come stringa o come intero."""
    value = claims.get(name)
    if isinstance(value, bool):
        return None
    if isinstance(value, int) or (isinstance(value, str) and value.isascii() and value.isdigit()):
        return str(value)
    return None


def _roles(claims: dict[str, Any], issuer: UserIssuer) -> frozenset[Role]:
    raw = claims.get(issuer.roles_claim)
    values = [raw] if isinstance(raw, str) else raw if isinstance(raw, list) else []
    found: set[Role] = set()
    for value in values:
        if isinstance(value, str):
            found.update(issuer.roles_map.get(value, []))
    return frozenset(found)


class TokenVerifier:
    def __init__(self, settings: AuthSettings, keys: JwksCache, clock: Clock) -> None:
        self._settings, self._keys, self._clock = settings, keys, clock
        self._issuers = {i.issuer: i for i in settings.issuers}

    def verify(self, token: str) -> Identity:
        if (
            len(token.encode("utf-8", "ignore")) > self._settings.max_token_bytes
            or token.count(".") != 2
        ):
            raise AuthError("malformed")
        try:
            header = jwt.get_unverified_header(token)
            claimed = jwt.decode(token, options={"verify_signature": False})
        except (jwt.PyJWTError, ValueError):
            raise AuthError("malformed") from None
        algorithm, kid = header.get("alg"), header.get("kid")
        if algorithm not in ALLOWED_ALGORITHMS:  # compresi `none` e HS256/384/512
            raise AuthError("algorithm")
        issuer_name = claimed.get("iss")
        config = self._issuers.get(issuer_name) if isinstance(issuer_name, str) else None
        if config is None:
            raise AuthError("issuer")  # nessuna richiesta in uscita
        if not isinstance(kid, str) or not kid:
            raise AuthError("kid")
        try:
            key = self._keys.key_for(config.issuer, kid, algorithm)
        except KeysUnavailable:
            raise AuthError("keys") from None
        try:
            claims = jwt.decode(
                token,
                key.key,
                algorithms=[algorithm],
                audience=config.audience,
                issuer=config.issuer,
                options={
                    "require": list(_REQUIRED),
                    "verify_exp": False,  # il tempo lo controlla il `Clock`, qui sotto
                    "verify_nbf": False,
                    "verify_iat": False,
                },
            )
        except jwt.InvalidAudienceError:
            raise AuthError("audience") from None
        except jwt.InvalidIssuerError:
            raise AuthError("issuer") from None
        except jwt.PyJWTError:
            raise AuthError("signature") from None
        self._check_time(claims)
        subject = _text(claims, "sub", 300)
        if subject is None:
            raise AuthError("subject")
        if isinstance(config, UserIssuer):
            return Identity(
                kind="user",
                issuer=config.issuer,
                subject=subject,
                tenant=config.tenant,
                name=_text(claims, "name", 200),
                email=_text(claims, "email", 320),
                roles=_roles(claims, config),
            )
        return self._pipeline(config, claims, subject)

    def _check_time(self, claims: dict[str, Any]) -> None:
        now = self._clock.now().timestamp()
        skew = self._settings.clock_skew_seconds
        exp, iat, nbf = claims.get("exp"), claims.get("iat"), claims.get("nbf")
        for value in (exp, iat, nbf):
            if value is not None and (
                isinstance(value, bool) or not isinstance(value, int | float)
            ):
                raise AuthError("time")
        assert isinstance(exp, int | float) and isinstance(iat, int | float)
        if exp + skew < now:
            raise AuthError("expired")
        if nbf is not None and nbf - skew > now:
            raise AuthError("not-yet-valid")
        if iat - skew > now:
            raise AuthError("issued-in-the-future")
        if exp - iat > self._settings.max_token_lifetime_seconds:
            raise AuthError("lifetime")

    def _pipeline(self, config: PipelineIssuer, claims: dict[str, Any], subject: str) -> Identity:
        # Nomi dei claim confermati sulla documentazione dei provider il 2026-11-17 (B-04).
        owner = _id(
            claims, "repository_owner_id" if config.provider == "github" else "namespace_id"
        )
        repo_id = _id(claims, "repository_id" if config.provider == "github" else "project_id")
        if owner is None or repo_id is None:
            raise AuthError("claims")
        tenant = config.owners.get(owner)
        if tenant is None:
            raise AuthError("owner", forbidden=True)  # proprietario fuori mappa: 403
        name = _text(claims, "repository" if config.provider == "github" else "project_path", 500)
        repository = PipelineRepository(
            provider=config.provider,
            external_id=repo_id,
            name=name,
            owner_id=owner,
            ref=_text(claims, "ref", 500),
            sha=_text(claims, "sha", 64),
        )
        return Identity(
            kind="pipeline",
            issuer=config.issuer,
            subject=subject,
            tenant=tenant,
            roles=frozenset(),
            repository=repository,
        )
