"""Rule engine + correlation worker.

Unlike the other monitors, this one doesn't observe the OS directly --
it reads the `events` table that every other monitor (and the website
check endpoint) already writes to, which is exactly why Phase 11 can
sit on top of everything built so far without touching any of it.

Two independent passes run each poll:

1. **Condition rules** (detection/rule_engine.py): every event newer
   than the last one seen gets checked against the loaded YAML
   condition rules; a match creates an Alert.
2. **Correlation scenarios** (detection/correlation_engine.py): events
   within the configured rolling window get checked against loaded
   YAML scenarios; a match creates one Incident (grouping every
   matched event) plus one Alert pointing at it, instead of raising
   a separate alert per event -- the spec's own "Office -> PowerShell
   -> network -> executable -> persistence = one incident" example.

Rules are loaded once at start() -- picking up an edited rule file
requires restarting the agent in this v1 (no file-watching/hot-reload,
to keep this phase's scope contained). Already-correlated event IDs
are tracked in memory only, not persisted, so a restart could in
theory re-match a chain whose events are still within the window; a
minor, documented trade-off consistent with how the other monitors
don't persist their "seen" state across restarts either.
"""

from __future__ import annotations

import datetime as dt
import threading

from sqlalchemy import select
from sqlalchemy.orm import sessionmaker

from agent.logging_setup import get_logger
from config.settings import MonitoringConfig, RiskConfig
from database.models import Alert, Event, Incident
from detection.correlation_engine import CorrelationEvent, find_scenario_matches
from detection.risk import severity_floor
from detection.rule_engine import evaluate_condition_rules
from detection.rules_loader import ConditionRule, CorrelationScenario, load_rules

_log = get_logger("monitors.correlation")

_SEVERITY_RANK = {"informational": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def _max_severity(a: str, b: str) -> str:
    return a if _SEVERITY_RANK.get(a, 0) >= _SEVERITY_RANK.get(b, 0) else b


class CorrelationMonitor:
    def __init__(
        self,
        session_factory: sessionmaker,
        monitoring_config: MonitoringConfig,
        risk_config: RiskConfig,
        condition_rules: list[ConditionRule] | None = None,
        scenarios: list[CorrelationScenario] | None = None,
    ) -> None:
        self._session_factory = session_factory
        self._config = monitoring_config
        self._risk_config = risk_config

        if condition_rules is None or scenarios is None:
            loaded_rules, loaded_scenarios = load_rules()
            self._condition_rules = condition_rules if condition_rules is not None else loaded_rules
            self._scenarios = scenarios if scenarios is not None else loaded_scenarios
        else:
            self._condition_rules = condition_rules
            self._scenarios = scenarios

        self._stop_event = threading.Event()
        self._thread = threading.Thread(target=self._run, name="sentinelguard-correlation-monitor", daemon=True)
        self._last_event_id = 0
        self._correlated_event_ids: set[int] = set()

    def start(self) -> None:
        self._thread.start()
        _log.info(
            "Correlation monitor started (poll interval %.1fs, %d condition rules, %d scenarios)",
            self._config.correlation_poll_interval_seconds,
            len(self._condition_rules),
            len(self._scenarios),
        )

    def stop(self, timeout: float = 5.0) -> None:
        self._stop_event.set()
        self._thread.join(timeout=timeout)
        _log.info("Correlation monitor stopped")

    def _run(self) -> None:
        # Start from the current max event id so we never replay old
        # history on startup, same philosophy as the other monitors.
        try:
            session = self._session_factory()
            try:
                max_id = session.execute(select(Event.id).order_by(Event.id.desc()).limit(1)).scalar_one_or_none()
                self._last_event_id = max_id or 0
            finally:
                session.close()
        except Exception:
            _log.exception("Correlation monitor failed to determine the starting event id; starting from 0")

        while not self._stop_event.wait(self._config.correlation_poll_interval_seconds):
            self._poll_once()

    def _poll_once(self) -> None:
        try:
            session = self._session_factory()
        except Exception:
            _log.exception("Correlation monitor poll failed: could not open a database session")
            return
        try:
            self._run_condition_rules(session)
            self._run_correlation(session)
            session.commit()
        except Exception:
            session.rollback()
            _log.exception("Correlation monitor poll failed")
        finally:
            session.close()

    def _run_condition_rules(self, session) -> None:
        if not self._condition_rules:
            return
        new_events = session.execute(
            select(Event).where(Event.id > self._last_event_id).order_by(Event.id)
        ).scalars().all()
        if not new_events:
            return

        for event in new_events:
            matches = evaluate_condition_rules(
                self._condition_rules,
                event_type=event.event_type,
                process=event.process,
                risk_score=event.risk_score,
                details=event.details or {},
            )
            for match in matches:
                severity = _max_severity(event.severity, match.rule.severity)
                risk = max(event.risk_score, severity_floor(match.rule.severity, self._risk_config))
                session.add(
                    Alert(
                        title=match.rule.name,
                        description=match.reason,
                        severity=severity,
                        risk_score=risk,
                        event_type=event.event_type,
                        source="rule_engine",
                        details={"event_id": event.id, "rule_file": match.rule.source_file, "reason": match.reason},
                    )
                )
            self._last_event_id = event.id

    def _run_correlation(self, session) -> None:
        if not self._scenarios:
            return
        max_window = max((s.window_minutes for s in self._scenarios), default=self._config.correlation_window_minutes)
        window_start = dt.datetime.now(dt.timezone.utc).replace(tzinfo=None) - dt.timedelta(minutes=max_window)

        recent = session.execute(select(Event).where(Event.timestamp >= window_start)).scalars().all()
        correlation_events = [
            CorrelationEvent(id=e.id, event_type=e.event_type, process=e.process, timestamp=e.timestamp)
            for e in recent
        ]

        matches = find_scenario_matches(self._scenarios, correlation_events, self._correlated_event_ids)
        if not matches:
            return

        events_by_id = {e.id: e for e in recent}
        for match in matches:
            self._correlated_event_ids.update(match.matched_event_ids)
            matched_severities = [events_by_id[eid].severity for eid in match.matched_event_ids if eid in events_by_id]
            severity = match.scenario.severity
            for s in matched_severities:
                severity = _max_severity(severity, s)
            risk = severity_floor(severity, self._risk_config)

            incident = Incident(
                title=match.scenario.name,
                description=match.reason,
                severity=severity,
                risk_score=risk,
                related_event_ids=match.matched_event_ids,
            )
            session.add(incident)
            session.flush()  # assign incident.id before referencing it

            session.add(
                Alert(
                    title=f"Incident: {match.scenario.name}",
                    description=match.reason,
                    severity=severity,
                    risk_score=risk,
                    event_type="incident",
                    source="correlation_engine",
                    details={
                        "incident_id": incident.id,
                        "scenario_file": match.scenario.source_file,
                        "matched_event_ids": match.matched_event_ids,
                    },
                )
            )
