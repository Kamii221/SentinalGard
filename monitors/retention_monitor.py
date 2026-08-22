"""Scheduled retention pruning.

``database/retention.py``'s ``prune_old_records`` has existed since
Phase 1 but was never actually scheduled anywhere -- every table would
have grown unbounded forever. This wires it up: runs once at startup
(so a database that's never been pruned gets cleaned up promptly) and
then on a long interval (``monitoring.retention_prune_interval_hours``,
default 24h) -- retention doesn't need to run often, so this is
deliberately one of the least chatty monitors in the agent.
"""

from __future__ import annotations

import threading

from sqlalchemy.orm import sessionmaker

from agent.logging_setup import get_logger
from config.settings import MonitoringConfig, RetentionConfig
from database.retention import prune_old_records

_log = get_logger("monitors.retention")


class RetentionMonitor:
    def __init__(
        self,
        session_factory: sessionmaker,
        monitoring_config: MonitoringConfig,
        retention_config: RetentionConfig,
    ) -> None:
        self._session_factory = session_factory
        self._config = monitoring_config
        self._retention_config = retention_config
        self._stop_event = threading.Event()
        self._thread = threading.Thread(target=self._run, name="sentinelguard-retention-monitor", daemon=True)

    def start(self) -> None:
        self._thread.start()
        _log.info(
            "Retention monitor started (prune interval %.1fh)", self._config.retention_prune_interval_hours
        )

    def stop(self, timeout: float = 5.0) -> None:
        self._stop_event.set()
        self._thread.join(timeout=timeout)
        _log.info("Retention monitor stopped")

    def _run(self) -> None:
        self._prune_once()
        interval_seconds = self._config.retention_prune_interval_hours * 3600
        while not self._stop_event.wait(interval_seconds):
            self._prune_once()

    def _prune_once(self) -> None:
        try:
            session = self._session_factory()
        except Exception:
            _log.exception("Retention pruning failed: could not open a database session")
            return
        try:
            deleted = prune_old_records(session, self._retention_config)
            total = sum(deleted.values())
            if total:
                _log.info("Retention pruning removed %d row(s): %s", total, deleted)
            else:
                _log.debug("Retention pruning: nothing to remove")
        except Exception:
            session.rollback()
            _log.exception("Retention pruning failed")
        finally:
            session.close()
