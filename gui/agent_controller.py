"""Single source of truth for whether this GUI process started (and
thus owns) the agent it's connected to.

Both run_gui()'s startup/shutdown sequence and the dashboard's Start/
Stop buttons (gui/pages/dashboard.py) share one of these instead of
each keeping their own separate notion of "do we own a handle" --
otherwise a Stop click and window-close shutdown could each try to
stop (or fail to stop) an agent the other side already changed its
mind about.
"""

from __future__ import annotations

from agent.logging_setup import get_logger
from agent.server import AgentConnection, ensure_agent_running
from config.settings import Settings

_log = get_logger("gui.agent_controller")


class AgentController:
    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        self.handle = None  # AgentHandle | None -- set only if we started it
        self.reachable = False

    def start(self) -> AgentConnection:
        """Connect to an already-running agent, or start one. Safe to
        call again after stop() (or after a failed attempt) -- each
        call is independent, same as ensure_agent_running itself."""
        result = ensure_agent_running(self._settings)
        self.handle = result.handle
        self.reachable = result.reachable
        return result

    def stop(self) -> None:
        """No-op if we don't own a handle (connected to an agent this
        process didn't start, or never connected at all) -- there's no
        way to stop a process this object doesn't hold a handle to."""
        if self.handle is not None:
            self.handle.stop()
            _log.info("Stopped the agent this GUI started")
            self.handle = None
        self.reachable = False

    @property
    def owns_agent(self) -> bool:
        return self.handle is not None
