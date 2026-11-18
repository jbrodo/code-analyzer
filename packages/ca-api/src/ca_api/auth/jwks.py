"""Chiavi pubbliche degli emittenti (B-04, ADR-0019): cache con scadenza e un solo aggiornamento.

Le chiavi si tengono in memoria con una scadenza. Un `kid` sconosciuto provoca **un solo**
aggiornamento, con un limite di frequenza per emittente: un token con `kid` inventati non fa
martellare l'emittente. Si fa una richiesta in uscita solo verso l'indirizzo configurato.
"""

import json
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Protocol
from urllib.parse import urlsplit

import jwt
from jwt import PyJWK

from ca_api.auth.config import ALLOWED_ALGORITHMS, AuthSettings
from ca_core.ports import Clock

MAX_JWKS_BYTES = 1024 * 1024
MAX_KEYS = 50
TIMEOUT_SECONDS = 10


class KeysUnavailable(RuntimeError):
    """Non si hanno le chiavi dell'emittente; il messaggio è un codice, mai un contenuto."""


class JwksFetcher(Protocol):
    def fetch(self, url: str, *, max_bytes: int) -> bytes: ...


class HttpsJwksFetcher:
    """HTTPS con tetto di byte e di tempo, senza redirect verso altri host né credenziali."""

    def __init__(self, *, allow_loopback_http: bool = False) -> None:
        self._allow_http = allow_loopback_http

    def fetch(self, url: str, *, max_bytes: int) -> bytes:
        parts = urlsplit(url)
        local = parts.hostname in ("127.0.0.1", "::1", "localhost")
        if parts.scheme != "https" and not (self._allow_http and local and parts.scheme == "http"):
            raise KeysUnavailable("scheme")
        host = parts.hostname

        class _Same(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[no-untyped-def]
                if urlsplit(newurl).hostname != host:
                    raise urllib.error.URLError("redirect-refused")
                return super().redirect_request(req, fp, code, msg, headers, newurl)

        opener = urllib.request.build_opener(_Same())
        request = urllib.request.Request(url, headers={"User-Agent": "code-analyzer"})  # noqa: S310
        try:
            with opener.open(request, timeout=TIMEOUT_SECONDS) as response:  # noqa: S310
                if response.status != 200:
                    raise KeysUnavailable("status")
                data: bytes = response.read(max_bytes + 1)
        except (urllib.error.URLError, OSError, ValueError) as exc:
            raise KeysUnavailable("network") from exc
        if len(data) > max_bytes:
            raise KeysUnavailable("too-large")
        return data


@dataclass
class _Entry:
    keys: dict[str, PyJWK] = field(default_factory=dict)
    fetched_at: float = 0.0
    attempted_at: float = float("-inf")


class JwksCache:
    def __init__(self, settings: AuthSettings, fetcher: JwksFetcher, clock: Clock) -> None:
        self._settings, self._fetcher, self._clock = settings, fetcher, clock
        self._entries: dict[str, _Entry] = {}
        self._urls = {i.issuer: i.jwks_url for i in settings.issuers}
        self.requests = 0  # per le prove: richieste in uscita fatte

    def _now(self) -> float:
        return self._clock.now().timestamp()

    def _refresh(self, issuer: str, entry: _Entry) -> None:
        entry.attempted_at = self._now()
        self.requests += 1
        raw = self._fetcher.fetch(self._urls[issuer], max_bytes=MAX_JWKS_BYTES)
        try:
            document = json.loads(raw)
            items = document["keys"]
            if not isinstance(items, list) or len(items) > MAX_KEYS:
                raise KeysUnavailable("shape")
            keys: dict[str, PyJWK] = {}
            for item in items:
                if not isinstance(item, dict) or not isinstance(item.get("kid"), str):
                    continue  # senza `kid` non si può scegliere: si ignora
                try:
                    key = PyJWK.from_dict(item)
                except jwt.PyJWTError, ValueError:
                    continue
                if key.key_type != "oct":  # mai chiavi simmetriche
                    keys[item["kid"]] = key
        except (ValueError, KeyError, TypeError) as exc:
            raise KeysUnavailable("shape") from exc
        entry.keys, entry.fetched_at = keys, self._now()

    def key_for(self, name: str, kid: str, algorithm: str) -> PyJWK:
        if name not in self._urls or algorithm not in ALLOWED_ALGORITHMS:
            raise KeysUnavailable("issuer")
        entry = self._entries.setdefault(name, _Entry())
        now = self._now()
        if not entry.keys or now - entry.fetched_at > self._settings.jwks_ttl_seconds:
            if (
                now - entry.attempted_at >= self._settings.jwks_min_refresh_seconds
                or not entry.keys
            ):
                self._refresh(name, entry)
        if kid not in entry.keys:
            # un solo aggiornamento per un `kid` sconosciuto, con il limite di frequenza
            if now - entry.attempted_at >= self._settings.jwks_min_refresh_seconds:
                self._refresh(name, entry)
            if kid not in entry.keys:
                raise KeysUnavailable("unknown-kid")
        return entry.keys[kid]
