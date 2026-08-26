import time
from pathlib import Path

import pytest
from sqlalchemy import select

from config.settings import MonitoringConfig, RiskConfig, load_settings
from database.engine import create_db_engine, create_session_factory
from database.models import Alert, Base, Event, Incident, ProcessRecord
from detection.rules_loader import AutoResponseAction, ConditionRule, CorrelationScenario, CorrelationStep, RuleConditions
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


def _lineage_scenario() -> CorrelationScenario:
    return CorrelationScenario(
        name="Office spawns PowerShell which phones home",
        severity="critical",
        steps=[
            CorrelationStep(event_types=["process_create"], process_contains=["winword.exe"], require_lineage=True),
            CorrelationStep(event_types=["network_connection"], require_lineage=True),
        ],
    )


def test_lineage_scenario_matches_a_real_descendant_process(session_factory) -> None:
    with session_factory() as session:
        session.add_all(
            [
                ProcessRecord(pid=100, ppid=1, name="winword.exe"),
                ProcessRecord(pid=200, ppid=100, name="powershell.exe"),
                Event(
                    event_type="process_create", source="process_monitor", process="winword.exe",
                    severity="informational", risk_score=0, details={"pid": 100, "ppid": 1},
                ),
                Event(
                    event_type="network_connection", source="network_monitor", process="powershell.exe",
                    severity="low", risk_score=10, details={"pid": 200},
                ),
            ]
        )
        session.commit()

    monitor = CorrelationMonitor(
        session_factory, MonitoringConfig(), RISK, condition_rules=[], scenarios=[_lineage_scenario()]
    )
    with session_factory() as session:
        monitor._run_correlation(session)
        session.commit()
        assert len(session.execute(select(Incident)).scalars().all()) == 1


def test_lineage_scenario_rejects_an_unrelated_process(session_factory) -> None:
    """Same event types, same time window, same process names even --
    but the network connection's pid has no ancestry link to the
    Office process, so this must not match."""
    with session_factory() as session:
        session.add_all(
            [
                ProcessRecord(pid=100, ppid=1, name="winword.exe"),
                ProcessRecord(pid=999, ppid=1, name="powershell.exe"),  # unrelated, own parent
                Event(
                    event_type="process_create", source="process_monitor", process="winword.exe",
                    severity="informational", risk_score=0, details={"pid": 100, "ppid": 1},
                ),
                Event(
                    event_type="network_connection", source="network_monitor", process="powershell.exe",
                    severity="low", risk_score=10, details={"pid": 999},
                ),
            ]
        )
        session.commit()

    monitor = CorrelationMonitor(
        session_factory, MonitoringConfig(), RISK, condition_rules=[], scenarios=[_lineage_scenario()]
    )
    with session_factory() as session:
        monitor._run_correlation(session)
        session.commit()
        assert session.execute(select(Incident)).scalars().all() == []


def test_condition_rule_auto_response_is_wired_up(session_factory, tmp_path: Path) -> None:
    """End-to-end through the real monitor (not just the standalone
    maybe_auto_respond unit tests in tests/test_auto_response.py):
    a rule with an auto_response block, matched while the global
    switch is on, must actually kill the process."""
    import subprocess
    import sys

    import psutil

    settings = load_settings()
    settings.data.data_dir = tmp_path
    settings.response.auto_response_enabled = True

    proc = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"])
    time.sleep(0.3)
    try:
        rule = ConditionRule(
            name="Auto-kill suspicious powershell",
            severity="critical",
            conditions=RuleConditions(event_type="process_create", process="powershell.exe"),
            auto_response=AutoResponseAction(action="kill_process", min_severity="critical"),
        )
        with session_factory() as session:
            session.add(
                Event(
                    event_type="process_create", source="process_monitor", process="powershell.exe",
                    severity="critical", risk_score=90, details={"pid": proc.pid},
                )
            )
            session.commit()

        monitor = CorrelationMonitor(
            session_factory, MonitoringConfig(), RISK, condition_rules=[rule], scenarios=[], settings=settings
        )
        monitor._last_event_id = 0
        with session_factory() as session:
            monitor._run_condition_rules(session)
            session.commit()

        assert not psutil.pid_exists(proc.pid)
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait(timeout=3)
