import time
from pathlib import Path

from agent.server import start_agent_in_background, wait_for_agent_ready
from config.settings import load_settings


def _settings_with_port(tmp_path: Path, port: int):
    settings = load_settings()
    settings.data.data_dir = tmp_path
    settings.api.port = port
    settings.monitoring.enabled = False
    return settings


def test_agent_handle_has_no_error_on_clean_start(tmp_path: Path) -> None:
    settings = _settings_with_port(tmp_path, 8791)
    handle = start_agent_in_background(settings)
    try:
        assert wait_for_agent_ready(settings, timeout=5.0)
        assert handle.error is None
    finally:
        handle.stop()


def test_second_agent_on_same_port_captures_its_bind_error(tmp_path: Path) -> None:
    """Regression test: a background-thread agent that fails to start
    (most commonly, the port is already taken by another instance) used
    to die completely silently -- an uncaught exception on a daemon
    thread has nowhere to go in a windowed PyInstaller build, since
    there's no console for the traceback to print to. AgentHandle.error
    must capture it instead."""
    settings = _settings_with_port(tmp_path, 8790)
    first = start_agent_in_background(settings)
    try:
        assert wait_for_agent_ready(settings, timeout=5.0)

        second = start_agent_in_background(settings)
        try:
            deadline = time.monotonic() + 5.0
            while second.error is None and time.monotonic() < deadline:
                time.sleep(0.05)
            assert second.error is not None
        finally:
            second.stop()

        # The instance that actually holds the port is unaffected by
        # the other one's failed attempt.
        assert wait_for_agent_ready(settings, timeout=1.0)
    finally:
        first.stop()
