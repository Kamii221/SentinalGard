"""Full-agent integration test.

Every other test file disables ``settings.monitoring.enabled`` for speed
and isolation. This is the one place that starts the real FastAPI app
with every monitor turned on together, confirming the whole lifespan
(startup order, shutdown order, and that nothing in one monitor's
startup trips over another's) actually works end to end -- not just
each monitor in isolation.
"""

from pathlib import Path

from fastapi.testclient import TestClient

from api.app import create_app
from api.security import TOKEN_HEADER_NAME
from config.settings import load_settings

_MONITOR_ATTRS = [
    "process_monitor",
    "file_monitor",
    "network_monitor",
    "persistence_monitor",
    "log_monitor",
    "correlation_monitor",
    "retention_monitor",
]


def _worker(monitor) -> object:
    # Every monitor runs its poll loop on a background worker, but
    # FileMonitor uses watchdog's Observer (its own thread subclass)
    # instead of a plain threading.Thread like the others.
    return getattr(monitor, "_observer", None) or monitor._thread


def test_agent_starts_and_stops_cleanly_with_every_monitor_enabled(tmp_path: Path) -> None:
    settings = load_settings()
    settings.data.data_dir = tmp_path
    settings.monitoring.enabled = True
    # Fast intervals so this test doesn't need to wait long to observe a
    # poll actually happening, while still leaving every monitor on.
    settings.monitoring.process_poll_interval_seconds = 0.2
    settings.monitoring.network_poll_interval_seconds = 0.2
    settings.monitoring.persistence_poll_interval_seconds = 0.2
    settings.monitoring.log_poll_interval_seconds = 0.2
    settings.monitoring.correlation_poll_interval_seconds = 0.2
    settings.monitoring.retention_prune_interval_hours = 999

    app = create_app(settings)

    with TestClient(app, client=("127.0.0.1", 12345)) as client:
        # All monitors should have been constructed and started by the
        # lifespan startup handler.
        for attr in _MONITOR_ATTRS:
            monitor = getattr(app.state, attr)
            assert monitor is not None, f"{attr} was not constructed"
            assert _worker(monitor).is_alive(), f"{attr} worker did not start"

        health = client.get("/api/v1/health")
        assert health.status_code == 200

        token = app.state.token_store.load_or_create()
        status = client.get("/api/v1/status", headers={TOKEN_HEADER_NAME: token})
        assert status.status_code == 200
        assert status.json()["protection_status"] == "active"

    # Lifespan shutdown should have stopped every monitor's worker.
    for attr in _MONITOR_ATTRS:
        monitor = getattr(app.state, attr)
        assert not _worker(monitor).is_alive(), f"{attr} worker did not stop"
