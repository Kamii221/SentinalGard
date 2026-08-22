"""Outbound network connection monitoring via psutil polling.

Like process monitoring, there's no lightweight OS-level connection
event API without WFP (Windows Filtering Platform) or ETW that stays
within the dependency budget, so polling ``psutil.net_connections()``
at a configurable interval and diffing against the previous snapshot
is the practical approach here -- same pattern as
monitors/process_monitor.py.

Only NEW established outbound connections are recorded, never
closures: unlike process termination, "a connection closed" isn't a
meaningful security signal on its own and would be pure noise at the
volume real traffic generates. SentinelGuard's own loopback traffic
(the GUI/extensions talking to the agent on 127.0.0.1) is filtered
out entirely so it never pollutes this table.

DNS activity: psutil has no visibility into DNS queries themselves --
that needs ETW (Windows) or packet capture, both out of scope for a
dependency-light v1 (Phase 10's log analyzer is the right place for
ETW-based DNS visibility later). As a practical "where available"
approximation, each new connection's destination IP gets a
best-effort, cached, timeout-bounded reverse DNS lookup to attach a
human-readable domain for correlation/display. This is not equivalent
to seeing the actual DNS query, and many legitimate destinations have
no PTR record, so "no reverse DNS" is deliberately never scored as
suspicious (see detection/network_analysis.py).

Listing all users' connections may require Administrator/root
privileges on some platforms; this degrades to "no data" rather than
crashing if access is denied.
"""

from __future__ import annotations

import concurrent.futures
import socket
import threading
from dataclasses import dataclass

import psutil
from sqlalchemy import select
from sqlalchemy.orm import sessionmaker

from agent.logging_setup import get_logger
from config.settings import MonitoringConfig, RiskConfig
from database.models import BlocklistEntry, Event, NetworkConnection
from detection.network_analysis import analyze_connection
from monitors.queue_worker import QueueWriter

_log = get_logger("monitors.network")

_LOOPBACK_IPS = frozenset({"127.0.0.1", "::1"})


@dataclass(frozen=True)
class _ConnInfo:
    pid: int | None
    process_name: str | None
    laddr_ip: str | None
    laddr_port: int | None
    raddr_ip: str
    raddr_port: int
    protocol: str


class _ReverseDnsResolver:
    """Best-effort, cached, timeout-bounded reverse DNS.

    Uses a small persistent thread pool rather than blocking the
    caller indefinitely or mutating the process-global socket
    timeout (which would affect unrelated sockets, e.g. the agent's
    own HTTP traffic).
    """

    def __init__(self, timeout: float = 1.5, max_cache_entries: int = 2048) -> None:
        self._timeout = timeout
        self._max_cache_entries = max_cache_entries
        self._executor = concurrent.futures.ThreadPoolExecutor(max_workers=2, thread_name_prefix="sg-rdns")
        self._cache: dict[str, str | None] = {}

    def resolve(self, ip: str) -> str | None:
        if ip in self._cache:
            return self._cache[ip]
        future = self._executor.submit(self._lookup, ip)
        try:
            result = future.result(timeout=self._timeout)
        except Exception:
            result = None

        if len(self._cache) >= self._max_cache_entries:
            self._cache.clear()
        self._cache[ip] = result
        return result

    @staticmethod
    def _lookup(ip: str) -> str | None:
        try:
            hostname, _aliases, _addrs = socket.gethostbyaddr(ip)
            return hostname
        except (socket.herror, socket.gaierror, OSError):
            return None

    def shutdown(self) -> None:
        self._executor.shutdown(wait=False, cancel_futures=True)


def _snapshot() -> dict[tuple, _ConnInfo]:
    result: dict[tuple, _ConnInfo] = {}
    try:
        connections = psutil.net_connections(kind="inet")
    except (psutil.AccessDenied, PermissionError):
        # Full system-wide visibility can require elevated privileges
        # on some platforms; fail closed to "no data" rather than
        # crashing the monitor.
        return result

    for c in connections:
        if c.status != psutil.CONN_ESTABLISHED or not c.raddr:
            continue
        raddr_ip, raddr_port = c.raddr.ip, c.raddr.port
        if raddr_ip in _LOOPBACK_IPS:
            continue

        process_name = None
        if c.pid is not None:
            try:
                process_name = psutil.Process(c.pid).name()
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                process_name = None

        protocol = "tcp" if c.type == socket.SOCK_STREAM else "udp"
        laddr_ip = c.laddr.ip if c.laddr else None
        laddr_port = c.laddr.port if c.laddr else None
        key = (c.pid, laddr_ip, laddr_port, raddr_ip, raddr_port)
        result[key] = _ConnInfo(
            pid=c.pid,
            process_name=process_name,
            laddr_ip=laddr_ip,
            laddr_port=laddr_port,
            raddr_ip=raddr_ip,
            raddr_port=raddr_port,
            protocol=protocol,
        )
    return result


class NetworkMonitor:
    """Polls established outbound connections on a background thread
    and records newly seen ones, batched through a QueueWriter."""

    def __init__(
        self,
        session_factory: sessionmaker,
        monitoring_config: MonitoringConfig,
        risk_config: RiskConfig,
    ) -> None:
        self._session_factory = session_factory
        self._config = monitoring_config
        self._risk_config = risk_config
        self._stop_event = threading.Event()
        self._thread = threading.Thread(target=self._run, name="sentinelguard-network-monitor", daemon=True)
        self._writer: QueueWriter[_ConnInfo] = QueueWriter("sentinelguard-network-writer", self._write_batch)
        self._resolver = _ReverseDnsResolver(timeout=monitoring_config.network_reverse_dns_timeout_seconds)
        self._known: dict[tuple, _ConnInfo] = {}

    def start(self) -> None:
        self._writer.start()
        self._thread.start()
        _log.info("Network monitor started (poll interval %.1fs)", self._config.network_poll_interval_seconds)

    def stop(self, timeout: float = 5.0) -> None:
        self._stop_event.set()
        self._thread.join(timeout=timeout)
        self._writer.stop(timeout=timeout)
        self._resolver.shutdown()
        _log.info("Network monitor stopped")

    def _run(self) -> None:
        # Seed without emitting events for connections that already
        # existed before we started watching.
        self._known = _snapshot()

        while not self._stop_event.wait(self._config.network_poll_interval_seconds):
            self._poll_once()

    def _poll_once(self) -> None:
        current = _snapshot()
        for key, info in current.items():
            if key not in self._known:
                self._writer.put(info)
        self._known = current

    def _write_batch(self, batch: list[_ConnInfo]) -> None:
        session = self._session_factory()
        try:
            for info in batch:
                self._write_one(session, info)
            session.commit()
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()

    def _write_one(self, session, info: _ConnInfo) -> None:
        domain = self._resolver.resolve(info.raddr_ip)

        known_malicious = (
            session.execute(
                select(BlocklistEntry).where(
                    BlocklistEntry.entry_type == "ip", BlocklistEntry.value == info.raddr_ip
                )
            ).scalars().first()
            is not None
        )

        analysis = analyze_connection(
            process_name=info.process_name,
            remote_port=info.raddr_port,
            domain=domain,
            known_malicious_ip=known_malicious,
            risk_config=self._risk_config,
        )

        session.add(
            NetworkConnection(
                pid=info.pid,
                process_name=info.process_name,
                local_address=info.laddr_ip,
                local_port=info.laddr_port,
                remote_address=info.raddr_ip,
                remote_port=info.raddr_port,
                protocol=info.protocol,
                domain=domain,
                direction="outbound",
                severity=analysis.severity,
                risk_score=analysis.risk,
            )
        )
        session.add(
            Event(
                event_type="network_connection",
                source="network_monitor",
                process=info.process_name,
                user=None,
                severity=analysis.severity,
                risk_score=analysis.risk,
                details={
                    "pid": info.pid,
                    "remote_address": info.raddr_ip,
                    "remote_port": info.raddr_port,
                    "domain": domain,
                    "protocol": info.protocol,
                    "known_malicious": known_malicious,
                    "reasons": analysis.reasons,
                },
            )
        )
