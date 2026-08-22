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
from api.routes import response as response_routes
from api.routes import status as status_routes
from api.routes import websites as websites_routes
from api.security import TokenStore
from config.settings import Settings
from database.engine import create_session_factory, init_db
from monitors.correlation_monitor import CorrelationMonitor
from monitors.file_monitor import FileMonitor
from monitors.log_monitor import LogMonitor
from monitors.network_monitor import NetworkMonitor
from monitors.persistence_monitor import PersistenceMonitor
from monitors.process_monitor import ProcessMonitor
from monitors.retention_monitor import RetentionMonitor

_log = get_logger("api")


def create_app(settings: Settings) -> FastAPI:
    engine = init_db(settings)
    session_factory = create_session_factory(engine)
    token_store = TokenStore(settings.data.resolved_data_dir() / "agent_token")
    # Ensure a token exists (and its file permissions are set) before the
    # agent starts accepting requests.
    token_store.load_or_create()

    process_monitor: ProcessMonitor | None = None
    file_monitor: FileMonitor | None = None
    network_monitor: NetworkMonitor | None = None
    persistence_monitor: PersistenceMonitor | None = None
    log_monitor: LogMonitor | None = None
    correlation_monitor: CorrelationMonitor | None = None
    retention_monitor: RetentionMonitor | None = None
    if settings.monitoring.enabled:
        process_monitor = ProcessMonitor(session_factory, settings.monitoring, settings.risk)
        file_monitor = FileMonitor(session_factory, settings.monitoring, settings.risk)
        network_monitor = NetworkMonitor(session_factory, settings.monitoring, settings.risk)
        persistence_monitor = PersistenceMonitor(session_factory, settings.monitoring, settings.risk)
        log_monitor = LogMonitor(session_factory, settings.monitoring, settings.risk)
        correlation_monitor = CorrelationMonitor(session_factory, settings.monitoring, settings.risk)
        retention_monitor = RetentionMonitor(session_factory, settings.monitoring, settings.retention)

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        _log.info("SentinelGuard agent starting on %s:%d", settings.api.host, settings.api.port)
        if process_monitor is not None:
            process_monitor.start()
        if file_monitor is not None:
            file_monitor.start()
        if network_monitor is not None:
            network_monitor.start()
        if persistence_monitor is not None:
            persistence_monitor.start()
        if log_monitor is not None:
            log_monitor.start()
        if correlation_monitor is not None:
            correlation_monitor.start()
        if retention_monitor is not None:
            retention_monitor.start()
        yield
        if retention_monitor is not None:
            retention_monitor.stop()
        if correlation_monitor is not None:
            correlation_monitor.stop()
        if log_monitor is not None:
            log_monitor.stop()
        if persistence_monitor is not None:
            persistence_monitor.stop()
        if network_monitor is not None:
            network_monitor.stop()
        if file_monitor is not None:
            file_monitor.stop()
        if process_monitor is not None:
            process_monitor.stop()
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
    app.state.process_monitor = process_monitor
    app.state.file_monitor = file_monitor
    app.state.network_monitor = network_monitor
    app.state.persistence_monitor = persistence_monitor
    app.state.log_monitor = log_monitor
    app.state.correlation_monitor = correlation_monitor
    app.state.retention_monitor = retention_monitor

    app.add_middleware(LoopbackOnlyMiddleware)

    app.include_router(health_routes.router, prefix="/api/v1")
    app.include_router(status_routes.router, prefix="/api/v1")
    app.include_router(auth_routes.router, prefix="/api/v1")
    app.include_router(websites_routes.router, prefix="/api/v1")
    app.include_router(response_routes.router, prefix="/api/v1")

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
