"""Intestazioni di sicurezza di ogni risposta dell'API (S1-M1 di `sicurezza-fase-2.md`).

Il testo del report è scelto da chi controlla il repository: ogni risposta ha un tipo esplicito e
`nosniff`, così un browser non lo reinterpreta come HTML o script. Le intestazioni della SPA
(`spa.py`) vanno oltre.
"""

from starlette.datastructures import MutableHeaders
from starlette.types import ASGIApp, Message, Receive, Scope, Send


class SecurityHeadersMiddleware:
    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        async def add(message: Message) -> None:
            if message["type"] == "http.response.start":
                headers = MutableHeaders(scope=message)
                headers.setdefault("X-Content-Type-Options", "nosniff")
            await send(message)

        await self.app(scope, receive, add)
