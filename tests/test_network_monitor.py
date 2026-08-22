import socket
import threading
import time
from pathlib import Path

import pytest
from sqlalchemy import select

from config.settings import MonitoringConfig, RiskConfig
from database.engine import create_db_engine, create_session_factory
from database.models import Base, BlocklistEntry, Event, NetworkConnection
from detection.network_analysis import analyze_connection, check_lolbin_network_activity, check_suspicious_port
from monitors.network_monitor import NetworkMonitor, _ConnInfo, _ReverseDnsResolver, _snapshot

RISK = RiskConfig()


def _local_non_loopback_ip() -> str:
    """Find a real, non-loopback IP this machine can bind to, without
    needing any actual internet access -- used to simulate an
    "external-looking" connection entirely offline."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("10.255.255.255", 1))
        return s.getsockname()[0]
    except OSError:
        pytest.skip("no non-loopback network interface available in this environment")
    finally:
        s.close()


def test_lolbin_network_activity_is_flagged() -> None:
    finding = check_lolbin_network_activity("powershell.exe")
    assert finding is not None
    assert "powershell.exe" in finding.reason


def test_benign_process_network_activity_not_flagged() -> None:
    assert check_lolbin_network_activity("chrome.exe") is None
    assert check_lolbin_network_activity(None) is None


def test_suspicious_port_is_flagged() -> None:
    finding = check_suspicious_port(4444)
    assert finding is not None


def test_normal_port_not_flagged() -> None:
    assert check_suspicious_port(443) is None
    assert check_suspicious_port(80) is None


def test_analyze_benign_connection_has_no_detection() -> None:
    analysis = analyze_connection(
        process_name="chrome.exe", remote_port=443, domain="example.com", known_malicious_ip=False, risk_config=RISK
    )
    assert analysis.risk == 0
    assert analysis.reasons == ["No detection"]


def test_analyze_missing_reverse_dns_is_not_scored() -> None:
    # No PTR record is common and legitimate -- must never be treated
    # as suspicious on its own.
    analysis = analyze_connection(
        process_name="chrome.exe", remote_port=443, domain=None, known_malicious_ip=False, risk_config=RISK
    )
    assert analysis.risk == 0


def test_analyze_lolbin_plus_suspicious_port_combines() -> None:
    analysis = analyze_connection(
        process_name="certutil.exe", remote_port=4444, domain=None, known_malicious_ip=False, risk_config=RISK
    )
    assert analysis.risk == 60
    assert len(analysis.reasons) == 2


def test_known_malicious_ip_short_circuits() -> None:
    analysis = analyze_connection(
        process_name="chrome.exe", remote_port=443, domain="example.com", known_malicious_ip=True, risk_config=RISK
    )
    assert analysis.known_malicious is True
    assert analysis.risk == 95
    assert analysis.severity == "critical"
    assert len(analysis.reasons) == 1


def test_reverse_dns_resolver_caches_and_handles_failure() -> None:
    resolver = _ReverseDnsResolver(timeout=1.0)
    try:
        # An address unlikely to have a PTR record reachable here;
        # regardless of the actual result, a second call must be an
        # instant cache hit (not a second real lookup).
        first = resolver.resolve("203.0.113.5")
        second = resolver.resolve("203.0.113.5")
        assert first == second
        assert "203.0.113.5" in resolver._cache
    finally:
        resolver.shutdown()


def test_snapshot_filters_loopback_connections() -> None:
    # Whatever real connections exist on this machine, none of our own
    # loopback traffic should ever appear.
    current = _snapshot()
    for info in current.values():
        assert info.raddr_ip not in ("127.0.0.1", "::1")


@pytest.fixture()
def session_factory(tmp_path: Path):
    engine = create_db_engine(tmp_path / "test.db")
    Base.metadata.create_all(engine)
    return create_session_factory(engine)


def test_write_one_persists_connection_and_event(session_factory) -> None:
    monitor = NetworkMonitor(session_factory, MonitoringConfig(), RISK)
    try:
        info = _ConnInfo(
            pid=999,
            process_name="powershell.exe",
            laddr_ip="10.0.0.5",
            laddr_port=54321,
            raddr_ip="203.0.113.9",
            raddr_port=4444,
            protocol="tcp",
        )
        with session_factory() as session:
            monitor._write_one(session, info)
            session.commit()

            record = session.execute(
                select(NetworkConnection).where(NetworkConnection.remote_address == "203.0.113.9")
            ).scalars().one()
            assert record.remote_port == 4444
            assert record.process_name == "powershell.exe"
            assert record.risk_score == 60
            assert record.severity == "medium"

            event = session.execute(select(Event).where(Event.event_type == "network_connection")).scalars().one()
            assert event.source == "network_monitor"
            assert event.details["remote_address"] == "203.0.113.9"
    finally:
        monitor._resolver.shutdown()


def test_write_one_detects_known_malicious_ip(session_factory) -> None:
    with session_factory() as session:
        session.add(BlocklistEntry(entry_type="ip", value="198.51.100.7", reason="test feed"))
        session.commit()

    monitor = NetworkMonitor(session_factory, MonitoringConfig(), RISK)
    try:
        info = _ConnInfo(
            pid=1,
            process_name="chrome.exe",
            laddr_ip="10.0.0.5",
            laddr_port=1234,
            raddr_ip="198.51.100.7",
            raddr_port=443,
            protocol="tcp",
        )
        with session_factory() as session:
            monitor._write_one(session, info)
            session.commit()

            record = session.execute(
                select(NetworkConnection).where(NetworkConnection.remote_address == "198.51.100.7")
            ).scalars().one()
            assert record.severity == "critical"
            assert record.risk_score == 95
    finally:
        monitor._resolver.shutdown()


def test_poll_diff_only_emits_new_connections(session_factory, monkeypatch) -> None:
    monitor = NetworkMonitor(session_factory, MonitoringConfig(), RISK)
    try:
        seen = []
        monkeypatch.setattr(monitor._writer, "put", lambda item: seen.append(item))

        existing = _ConnInfo(1, "a.exe", "10.0.0.1", 1, "203.0.113.1", 443, "tcp")
        monitor._known = {(1, "10.0.0.1", 1, "203.0.113.1", 443): existing}

        new_conn = _ConnInfo(2, "b.exe", "10.0.0.2", 2, "203.0.113.2", 443, "tcp")
        import monitors.network_monitor as nm_module

        monkeypatch.setattr(
            nm_module,
            "_snapshot",
            lambda: {
                (1, "10.0.0.1", 1, "203.0.113.1", 443): existing,
                (2, "10.0.0.2", 2, "203.0.113.2", 443): new_conn,
            },
        )
        monitor._poll_once()

        assert len(seen) == 1
        assert seen[0].raddr_ip == "203.0.113.2"
    finally:
        monitor._resolver.shutdown()


def test_network_monitor_detects_a_real_outbound_connection(tmp_path: Path) -> None:
    """End-to-end: bind a TCP server on this machine's real
    non-loopback IP (never actual internet -- fully offline), connect
    to it from another socket, and confirm the monitor detects it as
    an outbound connection distinct from our own loopback traffic."""
    engine = create_db_engine(tmp_path / "test.db")
    Base.metadata.create_all(engine)
    session_factory = create_session_factory(engine)

    bind_ip = _local_non_loopback_ip()

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((bind_ip, 0))
    server.listen(1)
    server_port = server.getsockname()[1]

    accepted_conns = []

    def _accept_loop():
        try:
            conn, _addr = server.accept()
            accepted_conns.append(conn)
        except OSError:
            pass

    accept_thread = threading.Thread(target=_accept_loop, daemon=True)
    accept_thread.start()

    config = MonitoringConfig(network_poll_interval_seconds=0.3)
    monitor = NetworkMonitor(session_factory, config, RiskConfig())
    monitor.start()
    # Wait for the initial seed snapshot to finish before connecting:
    # a connection made in the same instant as the seed can be folded
    # into it and never produce a "new connection" event -- the same
    # known trade-off of polling documented in process_monitor.py.
    seed_deadline = time.monotonic() + 5.0
    while not monitor._known and time.monotonic() < seed_deadline:
        time.sleep(0.05)
    client = None
    try:
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.connect((bind_ip, server_port))

        deadline = time.monotonic() + 6.0
        found = False
        while time.monotonic() < deadline:
            with session_factory() as session:
                match = session.execute(
                    select(NetworkConnection).where(NetworkConnection.remote_address == bind_ip)
                ).scalars().first()
                if match is not None:
                    found = True
                    break
            time.sleep(0.2)
        assert found, "expected the outbound connection to be recorded"
    finally:
        monitor.stop()
        if client is not None:
            client.close()
        for c in accepted_conns:
            c.close()
        server.close()
        accept_thread.join(timeout=2)
