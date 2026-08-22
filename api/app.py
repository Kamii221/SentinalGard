"""FastAPI application factory for the SentinelGuard local agent."""

from __future__ import annotations

import time
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.encoders import jsonable_encoder
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from agent.logging_setup import get_logger
from api.middleware import LoopbackOnlyMiddleware
from api.routes import auth as auth_routes
from api.routes import health as health_routes
from api.routes import status as status_routes
from api.routes import websites as websites_routes
from api.security import TokenStore
from config.settings import Settings
from database.engine import create_session_factory, init_db

_log = get_logger("api")


def create_app(settings: Settings) -> FastAPI:
    engine = init_db(settings)
    session_factory = create_session_factory(engine)
    token_store = TokenStore(settings.data.resolved_data_dir() / "agent_token")
    # Ensure a token exists (and its file permissions are set) before the
    # agent starts accepting requests.
    token_store.load_or_create()

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        _log.info("SentinelGuard agent starting on %s:%d", settings.api.host, settings.api.port)
        yield
        _log.info("SentinelGuard agent shutting down")

    app = FastAPI(
        title="SentinelGuard Agent",
        version=settings.app.version,
        lifespan=lifespan,
        # No public docs by default; still reachable on loopback but keeps
        # the surface intentional. Flip on locally if needed for debugging.
        docs_url=None,
        redoc_url=None,
    )

    app.state.settings = settings
    app.state.engine = engine
    app.state.session_factory = session_factory
    app.state.token_store = token_store
    app.state.started_monotonic = time.monotonic()

    app.add_middleware(LoopbackOnlyMiddleware)

    app.include_router(health_routes.router, prefix="/api/v1")
    app.include_router(status_routes.router, prefix="/api/v1")
    app.include_router(auth_routes.router, prefix="/api/v1")
    app.include_router(websites_routes.router, prefix="/api/v1")

    @app.exception_handler(RequestValidationError)
    async def _validation_error_handler(_: Request, exc: RequestValidationError) -> JSONResponse:
        # exc.errors() can embed the raw exception object (e.g. under
        # ctx.error, from a field_validator raising ValueError), which the
        # stdlib json module can't serialize — jsonable_encoder handles it
        # the same way FastAPI's own default handler does.
        return JSONResponse(status_code=422, content={"detail": jsonable_encoder(exc.errors())})

    @app.exception_handler(StarletteHTTPException)
    async def _http_exception_handler(_: Request, exc: StarletteHTTPException) -> JSONResponse:
        return JSONResponse(status_code=exc.status_code, content={"detail": exc.detail})

    @app.exception_handler(Exception)
    async def _unhandled_exception_handler(_: Request, exc: Exception) -> JSONResponse:
        _log.exception("Unhandled error in agent request: %s", exc)
        return JSONResponse(status_code=500, content={"detail": "Internal agent error"})

    return app
