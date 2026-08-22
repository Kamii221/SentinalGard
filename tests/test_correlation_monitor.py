import time
from pathlib import Path

import pytest
from sqlalchemy import select

from config.settings import MonitoringConfig, RiskConfig
from database.engine import create_db_engine, create_session_factory
from database.models import Alert, Base, Event, Incident
from detection.rules_loader import ConditionRule, CorrelationScenario, CorrelationStep, RuleConditions
from monitors.correlation_monitor import CorrelationMonitor

RISK = RiskConfig()


@pytest.fixture()
def session_factory(tmp_path: Path):
    engine = create_db_engine(tmp_path / "test.db")
    Base.metadata.create_all(engine)
    return create_session_factory(engine)


def _powershell_rule() -> ConditionRule:
    return ConditionRule(
        name="Suspicious PowerShell",
        severity="high",
        conditions=RuleConditions(
            event_type="process_create", process="powershell.exe", indicators=["encodedcommand"]
        ),
    )


def test_condition_rule_match_creates_an_alert(session_factory) -> None:
    with session_factory() as session:
        session.add(
            Event(
                event_type="process_create",
                source="process_monitor",
                process="powershell.exe",
                severity="low",
                risk_score=20,
                details={"command_line": "powershell.exe -EncodedCommand abc"},
            )
        )
        session.commit()

    monitor = CorrelationMonitor(session_factory, MonitoringConfig(), RISK, condition_rules=[_powershell_rule()], scenarios=[])
    monitor._last_event_id = 0
    with session_factory() as session:
        monitor._run_condition_rules(session)
        session.commit()

        alert = session.execute(select(Alert)).scalars().one()
        assert alert.title == "Suspicious PowerShell"
        assert alert.severity == "high"
        assert alert.source == "rule_engine"


def test_condition_rule_no_match_creates_no_alert(session_factory) -> None:
    with session_factory() as session:
        session.add(
            Event(
                event_type="process_create",
                source="process_monitor",
                process="notepad.exe",
                severity="informational",
                risk_score=0,
                details={"command_line": "notepad.exe"},
            )
        )
        session.commit()

    monitor = CorrelationMonitor(session_factory, MonitoringConfig(), RISK, condition_rules=[_powershell_rule()], scenarios=[])
    monitor._last_event_id = 0
    with session_factory() as session:
        monitor._run_condition_rules(session)
        session.commit()
        assert session.execute(select(Alert)).scalars().all() == []


def test_condition_rules_only_process_events_newer_than_cursor(session_factory) -> None:
    with session_factory() as session:
        old_event = Event(
            event_type="process_create",
            source="process_monitor",
            process="powershell.exe",
            severity="low",
            risk_score=20,
            details={"command_line": "powershell.exe -EncodedCommand abc"},
        )
        session.add(old_event)
        session.commit()
        old_id = old_event.id

    monitor = CorrelationMonitor(session_factory, MonitoringConfig(), RISK, condition_rules=[_powershell_rule()], scenarios=[])
    monitor._last_event_id = old_id  # simulate having already processed this event

    with session_factory() as session:
        monitor._run_condition_rules(session)
        session.commit()
        assert session.execute(select(Alert)).scalars().all() == []


def _office_powershell_scenario() -> CorrelationScenario:
    return CorrelationScenario(
        name="Office spawns PowerShell then persists",
        severity="critical",
        window_minutes=15,
        steps=[
            CorrelationStep(event_types=["process_create"], process_contains=["winword.exe"]),
            CorrelationStep(event_types=["process_create"], process_contains=["powershell.exe"]),
            CorrelationStep(event_types=["network_connection"]),
            CorrelationStep(event_types=["persistence_new"]),
        ],
    )


def test_full_chain_creates_one_incident_and_one_alert(session_factory) -> None:
    with session_factory() as session:
        session.add_all(
            [
                Event(event_type="process_create", source="process_monitor", process="WINWORD.EXE", severity="informational", risk_score=0),
                Event(event_type="process_create", source="process_monitor", process="powershell.exe", severity="low", risk_score=20),
                Event(event_type="network_connection", source="network_monitor", process="powershell.exe", severity="low", risk_score=10),
                Event(event_type="persistence_new", source="persistence_monitor", severity="medium", risk_score=45),
            ]
        )
        session.commit()

    monitor = CorrelationMonitor(
        session_factory, MonitoringConfig(), RISK, condition_rules=[], scenarios=[_office_powershell_scenario()]
    )
    with session_factory() as session:
        monitor._run_correlation(session)
        session.commit()

        incident = session.execute(select(Incident)).scalars().one()
        assert incident.title == "Office spawns PowerShell then persists"
        assert incident.severity == "critical"
        assert len(incident.related_event_ids) == 4

        alert = session.execute(select(Alert)).scalars().one()
        assert alert.source == "correlation_engine"
        assert alert.details["incident_id"] == incident.id


def test_correlation_does_not_rematch_same_events_across_polls(session_factory) -> None:
    with session_factory() as session:
        session.add_all(
            [
                Event(event_type="process_create", source="process_monitor", process="WINWORD.EXE", severity="informational", risk_score=0),
                Event(event_type="process_create", source="process_monitor", process="powershell.exe", severity="low", risk_score=20),
                Event(event_type="network_connection", source="network_monitor", process="powershell.exe", severity="low", risk_score=10),
                Event(event_type="persistence_new", source="persistence_monitor", severity="medium", risk_score=45),
            ]
        )
        session.commit()

    monitor = CorrelationMonitor(
        session_factory, MonitoringConfig(), RISK, condition_rules=[], scenarios=[_office_powershell_scenario()]
    )
    with session_factory() as session:
        monitor._run_correlation(session)
        monitor._run_correlation(session)  # second poll over the same events
        session.commit()

        incidents = session.execute(select(Incident)).scalars().all()
        assert len(incidents) == 1  # not duplicated


def test_incomplete_chain_creates_nothing(session_factory) -> None:
    with session_factory() as session:
        session.add_all(
            [
                Event(event_type="process_create", source="process_monitor", process="WINWORD.EXE", severity="informational", risk_score=0),
                Event(event_type="process_create", source="process_monitor", process="powershell.exe", severity="low", risk_score=20),
                # no network_connection, no persistence_new
            ]
        )
        session.commit()

    monitor = CorrelationMonitor(
        session_factory, MonitoringConfig(), RISK, condition_rules=[], scenarios=[_office_powershell_scenario()]
    )
    with session_factory() as session:
        monitor._run_correlation(session)
        session.commit()
        assert session.execute(select(Incident)).scalars().all() == []
        assert session.execute(select(Alert)).scalars().all() == []


def test_correlation_monitor_end_to_end_with_real_thread(tmp_path: Path) -> None:
    """Real thread + polling loop, using injected rules/scenarios."""
    engine = create_db_engine(tmp_path / "test.db")
    Base.metadata.create_all(engine)
    session_factory = create_session_factory(engine)

    monitor = CorrelationMonitor(
        session_factory,
        MonitoringConfig(correlation_poll_interval_seconds=0.2),
        RiskConfig(),
        condition_rules=[_powershell_rule()],
        scenarios=[],
    )
    monitor.start()
    try:
        time.sleep(0.3)  # let the initial cursor seed complete
        with session_factory() as session:
            session.add(
                Event(
                    event_type="process_create",
                    source="process_monitor",
                    process="powershell.exe",
                    severity="low",
                    risk_score=20,
                    details={"command_line": "powershell.exe -EncodedCommand abc"},
                )
            )
            session.commit()

        deadline = time.monotonic() + 5.0
        found = False
        while time.monotonic() < deadline:
            with session_factory() as session:
                if session.execute(select(Alert)).scalars().first() is not None:
                    found = True
                    break
            time.sleep(0.2)
        assert found, "expected the rule match to produce an alert"
    finally:
        monitor.stop()
