"""Defense-in-depth request filtering.

uvicorn is already bound to a loopback address by ``config.settings``
(``ApiConfig.host`` rejects anything else), but this middleware adds a
second, independent check on the actual TCP peer address of every
request so a misconfiguration elsewhere can't silently expose the
agent to the LAN.

Deliberately a plain ASGI callable, not a
``starlette.middleware.base.BaseHTTPMiddleware`` subclass. That class
wraps every response through an internal ``anyio`` stream, and has
long-standing hangs when combined with real socket I/O under asyncio's
default Windows event loop (``ProactorEventLoop``) -- the request
reaches the server and gets read, but the response is never sent back,
which is exactly the failure this project hit running for real on
Windows (every test passed, because ``TestClient`` talks to the ASGI
app in-process over ``httpx.ASGITransport`` and never touches a real
socket or the platform event loop -- the one path that actually
triggers this). A bare ASGI callable has none of that wrapping.
"""

from __future__ import annotations

import json

from starlette.types import ASGIApp, Receive, Scope, Send

_ALLOWED_CLIENT_HOSTS = {"127.0.0.1", "::1", "localhost"}

_FORBIDDEN_BODY = json.dumps({"detail": "SentinelGuard agent only accepts loopback connections"}).encode("utf-8")


class LoopbackOnlyMiddleware:
    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        client = scope.get("client")
        host = client[0] if client else None
        if host not in _ALLOWED_CLIENT_HOSTS:
            await send(
                {
                    "type": "http.response.start",
                    "status": 403,
                    "headers": [(b"content-type", b"application/json")],
                }
            )
            await send({"type": "http.response.body", "body": _FORBIDDEN_BODY})
            return

        await self.app(scope, receive, send)
