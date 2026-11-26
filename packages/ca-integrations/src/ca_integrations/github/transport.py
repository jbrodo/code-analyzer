"""Trasporto HTTP del client GitHub (N-02, ADR-0027): stdlib, nessuna dipendenza nuova.

Scelte di sicurezza, tutte verificate dai test:

- **Nessun redirect.** `urllib` li seguirebbe e inoltrerebbe l'intestazione `Authorization`
  all'indirizzo di destinazione: qui un 3xx è una risposta come le altre, e il client lo rifiuta.
- **Solo HTTPS**, tranne il loopback quando lo si chiede (i test con un server finto).
- **Tetto sulla risposta** (`MAX_RESPONSE_BYTES`) e un timeout: un server che non risponde o che
  manda un corpo enorme non blocca né gonfia la pipeline.
- Il corpo di un errore non esce mai dal trasporto: serve solo allo stato.
"""

import ipaddress
import urllib.error
import urllib.request
from collections.abc import Mapping
from dataclasses import dataclass
from email.message import Message
from typing import IO, Protocol
from urllib.parse import urlsplit

MAX_RESPONSE_BYTES = 5 * 1024 * 1024
DEFAULT_TIMEOUT = 15.0


@dataclass(frozen=True)
class Response:
    status: int
    headers: Mapping[str, str]
    body: bytes


class TransportError(Exception):
    """Errore di rete o risposta oltre il tetto. Il messaggio non contiene mai l'indirizzo."""


class Transport(Protocol):
    def request(
        self,
        method: str,
        url: str,
        headers: Mapping[str, str],
        body: bytes | None,
        timeout: float,
    ) -> Response: ...


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args: object, **kwargs: object) -> None:  # type: ignore[override]
        return None  # il 3xx torna al chiamante come risposta


def is_loopback(host: str | None) -> bool:
    if host in ("localhost", None):
        return host == "localhost"
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def check_base_url(url: str, *, allow_loopback_http: bool) -> str:
    """URL di base valido: `https`, oppure `http` su loopback se permesso. Senza credenziali."""
    parts = urlsplit(url)
    secure = parts.scheme == "https"
    local = parts.scheme == "http" and allow_loopback_http and is_loopback(parts.hostname)
    if not (secure or local) or not parts.hostname or parts.username or parts.password:
        raise ValueError("indirizzo dell'API non ammesso: serve https e nessuna credenziale")
    if parts.query or parts.fragment:
        raise ValueError("indirizzo dell'API con parametri")
    return url.rstrip("/")


class UrllibTransport:
    """Trasporto reale. Un'istanza non tiene stato: ogni richiesta apre la sua connessione."""

    def __init__(self) -> None:
        self._opener = urllib.request.build_opener(_NoRedirect)

    def request(
        self,
        method: str,
        url: str,
        headers: Mapping[str, str],
        body: bytes | None,
        timeout: float,
    ) -> Response:
        request = urllib.request.Request(url, data=body, headers=dict(headers), method=method)  # noqa: S310 - schema controllato da `check_base_url`
        try:
            with self._opener.open(request, timeout=timeout) as reply:  # noqa: S310
                return self._read(reply.status, reply.headers, reply)
        except urllib.error.HTTPError as error:  # 3xx, 4xx, 5xx: sono risposte, non eccezioni
            try:
                return self._read(error.code, error.headers, error)
            finally:
                error.close()
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            raise TransportError("richiesta non riuscita") from exc

    @staticmethod
    def _read(status: int, headers: Message, stream: IO[bytes]) -> Response:
        data = stream.read(MAX_RESPONSE_BYTES + 1)
        if len(data) > MAX_RESPONSE_BYTES:
            raise TransportError("risposta oltre il limite")
        return Response(
            status=status, headers={k.lower(): v for k, v in headers.items()}, body=data
        )
