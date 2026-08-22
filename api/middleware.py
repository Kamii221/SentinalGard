"""Defense-in-depth request filtering.

uvicorn is already bound to a loopback address by ``config.settings``
(``ApiConfig.host`` rejects anything else), but this middleware adds a
second, independent check on the actual TCP peer address of every
request so a misconfiguration elsewhere can't silently expose the
agent to the LAN.
"""

from __future__ import annotations

from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

_ALLOWED_CLIENT_HOSTS = {"127.0.0.1", "::1", "localhost"}


class LoopbackOnlyMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        client = request.client
        if client is None or client.host not in _ALLOWED_CLIENT_HOSTS:
            return JSONResponse(
                status_code=403,
                content={"detail": "SentinelGuard agent only accepts loopback connections"},
            )
        return await call_next(request)
