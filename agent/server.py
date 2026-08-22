"""Programmatic uvicorn runner for the SentinelGuard agent.

Two ways to run it:

* ``run_agent`` — blocking, for ``main.py --serve`` (agent-only, no GUI).
* ``start_agent_in_background`` — non-blocking, for ``main.py --gui``,
  which hosts the agent on a daemon thread inside the same process as
  the desktop window and talks to it over loopback HTTP like any other
  local client.
"""

from __future__ import annotations

import asyncio
import threading
import time
from dataclasses import dataclass

import httpx
import uvicorn

from agent.logging_setup import get_logger
from api.app import create_app
from config.settings import Settings

_log = get_logger("server")


def _build_server(settings: Settings) -> uvicorn.Server:
    app = create_app(settings)
    config = uvicorn.Config(app, host=settings.api.host, port=settings.api.port, log_config=None)
    return uvicorn.Server(config)


def run_agent(settings: Settings) -> None:
    """Start the FastAPI agent and block until it's stopped."""
    server = _build_server(settings)
    _log.info("Binding agent to %s:%d (loopback only)", settings.api.host, settings.api.port)
    server.run()


@dataclass
class AgentHandle:
    """A background-thread-hosted agent, controllable from the GUI."""

    thread: threading.Thread
    server: uvicorn.Server

    def stop(self, timeout: float = 5.0) -> None:
        self.server.should_exit = True
        self.thread.join(timeout=timeout)


def start_agent_in_background(settings: Settings) -> AgentHandle:
    """Start the agent on a daemon thread; returns a handle to stop it later."""
    server = _build_server(settings)

    def _run() -> None:
        asyncio.run(server.serve())

    thread = threading.Thread(target=_run, name="sentinelguard-agent", daemon=True)
    thread.start()
    _log.info("Agent starting in background thread on %s:%d", settings.api.host, settings.api.port)
    return AgentHandle(thread=thread, server=server)


def wait_for_agent_ready(settings: Settings, timeout: float = 5.0) -> bool:
    """Poll /health until the agent responds or the timeout elapses.

    A one-time startup synchronization, not a runtime polling loop.
    """
    url = f"http://{settings.api.host}:{settings.api.port}/api/v1/health"
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            if httpx.get(url, timeout=0.5).status_code == 200:
                return True
        except httpx.HTTPError:
            pass
        time.sleep(0.1)
    return False
