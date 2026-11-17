"""Limite di dimensione del corpo, applicato mentre lo si legge (B-03, ADR-0016).

`Content-Length` serve solo a rifiutare prima; il conteggio dei byte letti vale anche senza
(trasferimento a pezzi) e con un valore falso. Oltre il limite la lettura si ferma e la risposta è
413 `payload-too-large`. Middleware ASGI puro: non legge il corpo se non per contarlo.
"""

import json
from collections.abc import Awaitable, Callable, MutableMapping
from typing import Any

Scope = MutableMapping[str, Any]
Message = MutableMapping[str, Any]
Receive = Callable[[], Awaitable[Message]]
Send = Callable[[Message], Awaitable[None]]

_BODY = json.dumps(
    {
        "type": "about:blank",
        "title": "Richiesta troppo grande",
        "status": 413,
        "code": "payload-too-large",
    }
).encode()


class BodyLimitMiddleware:
    def __init__(self, app: Callable[[Scope, Receive, Send], Awaitable[None]], *, max_bytes: int):
        self._app, self._max = app, max_bytes

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self._app(scope, receive, send)
            return
        declared = dict(scope["headers"]).get(b"content-length")
        if declared is not None and declared.isdigit() and int(declared) > self._max:
            await self._refuse(send)
            return
        seen = 0
        refused = False

        async def counted() -> Message:
            nonlocal seen, refused
            message = await receive()
            if message["type"] == "http.request":
                seen += len(message.get("body", b""))
                if seen > self._max and not refused:
                    refused = True
                    return {"type": "http.disconnect"}  # ferma la lettura
            return message

        started = False

        async def guarded(message: Message) -> None:
            nonlocal started
            if not refused:  # dopo il rifiuto la risposta dell'applicazione non esce
                started = started or message["type"] == "http.response.start"
                await send(message)

        try:
            await self._app(scope, counted, guarded)
        except Exception:
            if not refused:
                raise
            # la lettura si è fermata: l'applicazione ha visto una disconnessione, non un errore suo
        if refused and not started:
            await self._refuse(send)

    @staticmethod
    async def _refuse(send: Send) -> None:
        await send(
            {
                "type": "http.response.start",
                "status": 413,
                "headers": [
                    (b"content-type", b"application/problem+json"),
                    (b"content-length", str(len(_BODY)).encode()),
                ],
            }
        )
        await send({"type": "http.response.body", "body": _BODY})
