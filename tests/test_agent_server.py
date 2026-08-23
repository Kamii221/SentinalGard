import time
from pathlib import Path

import pytest

import agent.server as agent_server
from agent.server import ensure_agent_running, start_agent_in_background, wait_for_agent_ready
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


def test_ensure_agent_running_connects_without_starting_a_second_one(tmp_path: Path) -> None:
    settings = _settings_with_port(tmp_path, 8785)
    existing = start_agent_in_background(settings)
    try:
        assert wait_for_agent_ready(settings, timeout=5.0)

        result = ensure_agent_running(settings)

        assert result.reachable is True
        assert result.handle is None  # didn't start one, so doesn't own one
        assert wait_for_agent_ready(settings, timeout=1.0)  # existing agent untouched
    finally:
        existing.stop()


def test_ensure_agent_running_starts_one_when_nothing_is_running(tmp_path: Path) -> None:
    settings = _settings_with_port(tmp_path, 8784)

    result = ensure_agent_running(settings)
    try:
        assert result.reachable is True
        assert result.handle is not None
        assert wait_for_agent_ready(settings, timeout=1.0)
    finally:
        if result.handle is not None:
            result.handle.stop()


def test_ensure_agent_running_recovers_from_a_lost_race(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Deterministic reproduction of two callers racing to start the
    agent at once (e.g. the installer's autostart entry vs. a manual
    launch): this attempt's own start fails, but a recheck finds
    another instance already up -- ensure_agent_running must stop its
    own failed handle and report reachable=True with no handle of its
    own, not sit disconnected forever next to a working agent."""
    settings = _settings_with_port(tmp_path, 8783)

    calls = {"wait": 0}

    def fake_wait(_settings: object, timeout: float) -> bool:
        calls["wait"] += 1
        # 1: initial "is one already running?" check -> no.
        # 2: post-start readiness wait -> this attempt's own start failed.
        # 3: race recheck -> another instance is up now.
        return calls["wait"] >= 3

    class FakeHandle:
        def __init__(self) -> None:
            self.error = OSError("address already in use")
            self.stopped = False

        def stop(self, timeout: float = 5.0) -> None:
            self.stopped = True

    fake_handle = FakeHandle()
    monkeypatch.setattr(agent_server, "wait_for_agent_ready", fake_wait)
    monkeypatch.setattr(agent_server, "start_agent_in_background", lambda _settings: fake_handle)

    result = ensure_agent_running(settings)

    assert calls["wait"] == 3
    assert result.reachable is True
    assert result.handle is None
    assert fake_handle.stopped is True


def test_ensure_agent_running_cleans_up_after_a_genuine_failure(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """When the agent never becomes reachable at all -- not a race,
    a real failure -- the failed attempt must be stopped (so a
    subsequent retry, e.g. the dashboard's "Start Agent" button, gets a
    free port instead of "address already in use" against its own dead
    predecessor) and the real error surfaced instead of a generic
    message."""
    settings = _settings_with_port(tmp_path, 8782)

    class FakeHandle:
        def __init__(self) -> None:
            self.error = OSError("something went wrong")
            self.stopped = False

        def stop(self, timeout: float = 5.0) -> None:
            self.stopped = True

    fake_handle = FakeHandle()
    monkeypatch.setattr(agent_server, "wait_for_agent_ready", lambda _settings, timeout: False)
    monkeypatch.setattr(agent_server, "start_agent_in_background", lambda _settings: fake_handle)

    result = ensure_agent_running(settings)

    assert result.reachable is False
    assert result.handle is None
    assert "something went wrong" in result.error
    assert fake_handle.stopped is True
