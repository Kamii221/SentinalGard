"""Website navigation checks and manual allow/block decisions.

``check``/``lookup`` share the same decision logic: an exact-match
list lookup against ``allowlist``/``blocklist`` takes priority (the
user's explicit word is final), and otherwise falls through to the
local URL heuristic engine (detection/url_analysis.py). A URL that
scores High/Critical is auto-blocked -- unlike system-level response
actions (kill process, quarantine, etc.), a URL block here is cheap
and instantly reversible (Allow Once / Always Allow from the blocked
page), so it doesn't need the same "avoid aggressive automatic
remediation" caution the spec asks for elsewhere.
"""

from __future__ import annotations

import datetime as dt
from urllib.parse import urlparse

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from agent.audit import log_admin_action
from api.deps import get_db, get_settings_dep
from api.schemas import (
    MAX_URL_LENGTH,
    WebsiteCheckRequest,
    WebsiteCheckResponse,
    WebsiteDecisionRequest,
    WebsiteDecisionResponse,
    extract_domain,
    normalize_url,
)
from api.security import require_agent_token
from config.settings import RiskConfig, Settings
from database.models import AllowlistEntry, BlocklistEntry, Event, Website
from detection.risk import Severity, severity_for_risk
from detection.url_analysis import analyze_url

router = APIRouter(prefix="/websites", tags=["websites"], dependencies=[Depends(require_agent_token)])

_ALLOW_ONCE_DURATION = dt.timedelta(hours=1)
_AUTO_BLOCK_SEVERITIES = frozenset({"high", "critical"})


def _now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc).replace(tzinfo=None)


def _find_list_entry(session: Session, model, domain: str):
    return session.execute(
        select(model).where(model.entry_type == "domain", model.value == domain)
    ).scalars().first()


def _upsert_list_entry(
    session: Session, model, domain: str, reason: str, expires_at: dt.datetime | None = None
) -> None:
    existing = _find_list_entry(session, model, domain)
    if existing is not None:
        existing.reason = reason
        if hasattr(existing, "expires_at"):
            existing.expires_at = expires_at
    else:
        kwargs = {"entry_type": "domain", "value": domain, "reason": reason}
        if hasattr(model, "expires_at"):
            kwargs["expires_at"] = expires_at
        session.add(model(**kwargs))
    session.commit()


def _remove_list_entry(session: Session, model, domain: str) -> None:
    session.execute(delete(model).where(model.entry_type == "domain", model.value == domain))
    session.commit()


def _decide(session: Session, url: str, domain: str, risk_config: RiskConfig) -> tuple[str, int, str, Severity]:
    blocked = _find_list_entry(session, BlocklistEntry, domain)
    if blocked is not None:
        risk = 95
        reason = f"Domain is on your blocklist ({blocked.reason or 'no reason given'})"
        return "block", risk, reason, severity_for_risk(risk, risk_config)

    allowed = _find_list_entry(session, AllowlistEntry, domain)
    if allowed is not None:
        if allowed.expires_at is not None and allowed.expires_at < _now():
            session.delete(allowed)
            session.commit()
        else:
            action = "allow_once" if allowed.expires_at is not None else "allow"
            risk = 0
            reason = f"Domain is on your allowlist ({allowed.reason or 'user approved'})"
            return action, risk, reason, severity_for_risk(risk, risk_config)

    analysis = analyze_url(url, risk_config)
    action = "block" if analysis.severity in _AUTO_BLOCK_SEVERITIES else "allow"
    reason = "; ".join(analysis.reasons)
    return action, analysis.risk, reason, analysis.severity


@router.post("/check", response_model=WebsiteCheckResponse)
def check_website(
    payload: WebsiteCheckRequest,
    session: Session = Depends(get_db),
    settings: Settings = Depends(get_settings_dep),
) -> WebsiteCheckResponse:
    domain = extract_domain(payload.url)
    action, risk, reason, severity = _decide(session, payload.url, domain, settings.risk)

    session.add(
        Website(
            url=payload.url,
            domain=domain,
            browser=payload.browser,
            scheme=urlparse(payload.url).scheme,
            risk_score=risk,
            severity=severity,
            reason=reason,
            action=action,
        )
    )
    # Also feed the unified events stream (websites/check previously
    # only wrote to the `websites` table), so the rule engine and
    # correlation (Phase 11) can see URL/website activity like every
    # other monitor's events.
    session.add(
        Event(
            event_type="website_check",
            source="url_detection",
            process=None,
            user=None,
            severity=severity,
            risk_score=risk,
            details={
                "url": payload.url,
                "domain": domain,
                "browser": payload.browser,
                "action": action,
                "reason": reason,
            },
        )
    )
    session.commit()

    return WebsiteCheckResponse(action=action, risk=risk, reason=reason)


@router.get("/lookup", response_model=WebsiteCheckResponse)
def lookup_website(
    url: str = Query(..., max_length=MAX_URL_LENGTH),
    session: Session = Depends(get_db),
    settings: Settings = Depends(get_settings_dep),
) -> WebsiteCheckResponse:
    """Read-only version of /check used by the popup UI; does not log a Website row."""
    try:
        clean_url = normalize_url(url)
        domain = extract_domain(clean_url)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    action, risk, reason, _severity = _decide(session, clean_url, domain, settings.risk)
    return WebsiteCheckResponse(action=action, risk=risk, reason=reason)


@router.post("/decision", response_model=WebsiteDecisionResponse)
def record_decision(
    payload: WebsiteDecisionRequest, session: Session = Depends(get_db)
) -> WebsiteDecisionResponse:
    domain = extract_domain(payload.url)

    if payload.decision == "always_allow":
        _remove_list_entry(session, BlocklistEntry, domain)
        _upsert_list_entry(session, AllowlistEntry, domain, reason="User: always allow")
        applied = f"{domain} added to your allowlist"
    elif payload.decision == "always_block":
        _remove_list_entry(session, AllowlistEntry, domain)
        _upsert_list_entry(session, BlocklistEntry, domain, reason="User: always block")
        applied = f"{domain} added to your blocklist"
    elif payload.decision == "allow_once":
        _upsert_list_entry(
            session,
            AllowlistEntry,
            domain,
            reason="User: allow once",
            expires_at=_now() + _ALLOW_ONCE_DURATION,
        )
        applied = f"{domain} allowed for the next hour"
    elif payload.decision == "block":
        applied = f"{domain} blocked for this visit"
    else:  # pragma: no cover - Literal type already restricts this
        raise HTTPException(status_code=400, detail="Unknown decision")

    log_admin_action(session, "website_decision", details={"domain": domain, "decision": payload.decision})
    return WebsiteDecisionResponse(status="ok", applied=applied)
