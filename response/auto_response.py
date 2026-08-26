"""Opt-in automatic remediation for condition-rule matches.

response/actions.py's functions have never been triggered by anything
but an explicit, confirmed API call (Phase 12's "avoid aggressive
automatic remediation in v1"). This adds a policy engine on top without
weakening that default: nothing here fires unless *both*
``settings.response.auto_response_enabled`` is true (a global kill
switch, off by default) *and* the specific rule that matched carries
its own ``auto_response`` block (detection/rules_loader.py) naming an
action and a minimum severity. A rule file alone, even with
auto_response configured, does nothing until the global switch is on.

Every attempt -- success or failure -- is logged the same way a manual
response action is (agent/audit.py + an Event), tagged
``source="auto_response"`` so it's distinguishable from a human-driven
action in the audit trail. A failure (missing pid, file already gone,
access denied, ...) is logged and swallowed: this runs inside the
correlation monitor's poll loop, and one bad match must never take the
whole monitor down.
"""

from __future__ import annotations

from typing import Any

from sqlalchemy.orm import Session

from agent.audit import log_admin_action
from agent.logging_setup import get_logger
from config.settings import Settings, resolved_quarantine_dir
from database.models import Event
from detection.rules_loader import ConditionRule
from response.actions import (
    ResponseActionError,
    disable_persistence_entry,
    kill_process,
    quarantine_file,
)

_log = get_logger("response.auto_response")

_SEVERITY_RANK = {"informational": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def _meets_severity(actual: str, minimum: str) -> bool:
    return _SEVERITY_RANK.get(actual, 0) >= _SEVERITY_RANK.get(minimum, 0)


def maybe_auto_respond(
    session: Session,
    *,
    rule: ConditionRule,
    event: Event,
    alert_severity: str,
    settings: Settings | None,
) -> None:
    """No-op unless the global switch is on, the rule opted in, and
    the matched alert's severity clears the rule's own bar."""
    if settings is None or not settings.response.auto_response_enabled:
        return
    policy = rule.auto_response
    if policy is None:
        return
    if not _meets_severity(alert_severity, policy.min_severity):
        return

    details = event.details or {}
    try:
        result = _dispatch(policy.action, event, details, settings)
    except ResponseActionError as exc:
        _log.warning("Auto-response '%s' for rule '%s' failed: %s", policy.action, rule.name, exc)
        log_admin_action(
            session,
            f"auto_{policy.action}_failed",
            user="auto_response",
            details={"rule": rule.name, "event_id": event.id, "error": str(exc)},
        )
        return
    except Exception:
        _log.exception("Auto-response '%s' for rule '%s' raised unexpectedly", policy.action, rule.name)
        return

    _log.warning("Auto-response '%s' for rule '%s': %s", policy.action, rule.name, result)
    log_admin_action(
        session,
        f"auto_{policy.action}",
        user="auto_response",
        details={"rule": rule.name, "event_id": event.id, **result},
    )
    session.add(
        Event(
            event_type=f"auto_response_{policy.action}",
            source="auto_response",
            process=event.process,
            severity="informational",
            risk_score=0,
            details={"rule": rule.name, "event_id": event.id, **result},
        )
    )


def _dispatch(action: str, event: Event, details: dict[str, Any], settings: Settings) -> dict:
    if action == "kill_process":
        pid = details.get("pid")
        if not isinstance(pid, int):
            raise ResponseActionError(f"Event {event.id} has no pid in details; cannot auto-kill")
        return kill_process(pid)

    if action == "quarantine_file":
        path = details.get("path")
        if not path:
            raise ResponseActionError(f"Event {event.id} has no path in details; cannot auto-quarantine")
        return quarantine_file(
            path,
            f"Auto-quarantined by rule match (event {event.id})",
            resolved_quarantine_dir(settings),
            settings.monitoring.file_hash_max_bytes,
        )

    if action == "disable_persistence":
        source_type = details.get("source_type")
        location = details.get("location")
        name = details.get("name")
        if not (source_type and location and name):
            raise ResponseActionError(
                f"Event {event.id} is missing source_type/location/name; cannot auto-disable persistence"
            )
        return disable_persistence_entry(
            source_type,
            location,
            name,
            quarantine_dir=resolved_quarantine_dir(settings),
            hash_max_bytes=settings.monitoring.file_hash_max_bytes,
        )

    raise ResponseActionError(f"Unknown auto_response action: {action}")
