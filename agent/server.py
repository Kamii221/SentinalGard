"""Programmatic uvicorn runner for the SentinelGuard agent."""

from __future__ import annotations

import uvicorn

from agent.logging_setup import get_logger
from api.app import create_app
from config.settings import Settings

_log = get_logger("server")


def run_agent(settings: Settings) -> None:
    """Start the FastAPI agent and block until it's stopped."""
    app = create_app(settings)
    _log.info("Binding agent to %s:%d (loopback only)", settings.api.host, settings.api.port)
    uvicorn.run(app, host=settings.api.host, port=settings.api.port, log_config=None)
