"""Administrative action logging.

Every privileged/administrative action taken through the agent (token
rotation, future rule changes, quarantine actions, etc.) is written both
to the application log and to the ``events`` table, so it shows up
alongside other activity for correlation and history.
"""

from __future__ import annotations

from typing import Any

from sqlalchemy.orm import Session

from agent.logging_setup import get_logger
from database.models import Event

_audit_logger = get_logger("audit")


def log_admin_action(
    session: Session,
    action: str,
    *,
    user: str = "local_user",
    details: dict[str, Any] | None = None,
) -> None:
    """Record an administrative action to the log file and the events table."""
    details = details or {}
    _audit_logger.warning("ADMIN_ACTION action=%s user=%s details=%s", action, user, details)

    session.add(
        Event(
            event_type="admin_action",
            source="agent",
            process=None,
            user=user,
            severity="informational",
            risk_score=0,
            details={"action": action, **details},
        )
    )
    session.commit()
