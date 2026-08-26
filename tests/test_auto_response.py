import subprocess
import sys
import time
from pathlib import Path

import psutil
import pytest
from sqlalchemy import select

from config.settings import load_settings
from database.engine import create_db_engine, create_session_factory
from database.models import Base, Event
from detection.rules_loader import AutoResponseAction, ConditionRule, RuleConditions
from response.auto_response import maybe_auto_respond


@pytest.fixture()
def session_factory(tmp_path: Path):
    engine = create_db_engine(tmp_path / "test.db")
    Base.metadata.create_all(engine)
    return create_session_factory(engine)


def _settings(tmp_path: Path, *, auto_response_enabled: bool):
    settings = load_settings()
    settings.data.data_dir = tmp_path
    settings.response.auto_response_enabled = auto_response_enabled
    return settings


def _rule(min_severity: str = "critical") -> ConditionRule:
    return ConditionRule(
        name="Auto-kill test rule",
        conditions=RuleConditions(event_type="process_create"),
        auto_response=AutoResponseAction(action="kill_process", min_severity=min_severity),
    )


@pytest.fixture()
def child_process():
    proc = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"])
    time.sleep(0.3)
    yield proc
    if proc.poll() is None:
        proc.kill()
        proc.wait(timeout=3)


def test_noop_when_globally_disabled(session_factory, tmp_path: Path, child_process) -> None:
    settings = _settings(tmp_path, auto_response_enabled=False)
    with session_factory() as session:
        event = Event(event_type="process_create", source="process_monitor", details={"pid": child_process.pid})
        session.add(event)
        session.commit()

        maybe_auto_respond(session, rule=_rule(), event=event, alert_severity="critical", settings=settings)
        session.commit()

    assert psutil.pid_exists(child_process.pid)
    with session_factory() as session:
        # Nothing beyond the seed event -- no audit log, no auto-response Event.
        assert len(session.execute(select(Event)).scalars().all()) == 1


def test_noop_when_rule_has_no_auto_response(session_factory, tmp_path: Path, child_process) -> None:
    settings = _settings(tmp_path, auto_response_enabled=True)
    rule = ConditionRule(name="No auto response", conditions=RuleConditions(event_type="process_create"))
    with session_factory() as session:
        event = Event(event_type="process_create", source="process_monitor", details={"pid": child_process.pid})
        session.add(event)
        session.commit()

        maybe_auto_respond(session, rule=rule, event=event, alert_severity="critical", settings=settings)
        session.commit()

    assert psutil.pid_exists(child_process.pid)


def test_noop_when_severity_below_the_rules_own_threshold(session_factory, tmp_path: Path, child_process) -> None:
    settings = _settings(tmp_path, auto_response_enabled=True)
    with session_factory() as session:
        event = Event(event_type="process_create", source="process_monitor", details={"pid": child_process.pid})
        session.add(event)
        session.commit()

        maybe_auto_respond(
            session, rule=_rule(min_severity="critical"), event=event, alert_severity="high", settings=settings
        )
        session.commit()

    assert psutil.pid_exists(child_process.pid)


def test_kills_the_process_when_enabled_and_severity_met(session_factory, tmp_path: Path, child_process) -> None:
    settings = _settings(tmp_path, auto_response_enabled=True)
    with session_factory() as session:
        event = Event(event_type="process_create", source="process_monitor", details={"pid": child_process.pid})
        session.add(event)
        session.commit()
        event_id = event.id

        maybe_auto_respond(
            session, rule=_rule(min_severity="high"), event=event, alert_severity="critical", settings=settings
        )
        session.commit()

    assert not psutil.pid_exists(child_process.pid)

    with session_factory() as session:
        events = session.execute(select(Event).where(Event.id != event_id)).scalars().all()
        event_types = {e.event_type for e in events}
        assert "admin_action" in event_types  # agent/audit.py's log_admin_action
        assert "auto_response_kill_process" in event_types


def test_quarantines_a_file_when_enabled_and_severity_met(session_factory, tmp_path: Path) -> None:
    settings = _settings(tmp_path, auto_response_enabled=True)
    target = tmp_path / "suspicious.exe"
    target.write_bytes(b"not actually malware, just test bytes")

    rule = ConditionRule(
        name="Auto-quarantine test rule",
        conditions=RuleConditions(event_type="file_created"),
        auto_response=AutoResponseAction(action="quarantine_file", min_severity="high"),
    )

    with session_factory() as session:
        event = Event(event_type="file_created", source="file_monitor", details={"path": str(target)})
        session.add(event)
        session.commit()

        maybe_auto_respond(session, rule=rule, event=event, alert_severity="critical", settings=settings)
        session.commit()

    assert not target.exists()
    quarantine_dir = tmp_path / "quarantine"
    assert len(list(quarantine_dir.glob("*.quarantined"))) == 1


def test_failure_is_logged_and_does_not_raise(session_factory, tmp_path: Path) -> None:
    settings = _settings(tmp_path, auto_response_enabled=True)
    with session_factory() as session:
        # No pid in details at all -- the action can't possibly succeed.
        event = Event(event_type="process_create", source="process_monitor", details={})
        session.add(event)
        session.commit()

        maybe_auto_respond(
            session, rule=_rule(min_severity="high"), event=event, alert_severity="critical", settings=settings
        )
        session.commit()  # must not raise

        events = session.execute(select(Event)).scalars().all()
        assert any(e.event_type == "admin_action" for e in events)
