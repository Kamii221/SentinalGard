"""Pydantic request/response models for the agent API."""

from __future__ import annotations

import datetime as dt
import ipaddress
import re
from typing import Literal
from urllib.parse import urlparse

from pydantic import BaseModel, Field, field_validator

MAX_URL_LENGTH = 4096
_MAX_DOMAIN_LENGTH = 253
_DOMAIN_RE = re.compile(r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))+$")


def normalize_url(value: str) -> str:
    """Validate a navigation URL: http(s) only, bounded length, no control chars."""
    value = value.strip()
    if not value or len(value) > MAX_URL_LENGTH:
        raise ValueError("URL is empty or too long")
    if any(ord(c) < 0x20 for c in value):
        raise ValueError("URL contains control characters")
    parsed = urlparse(value)
    if parsed.scheme not in ("http", "https"):
        raise ValueError("Only http/https URLs are supported")
    if not parsed.hostname:
        raise ValueError("URL has no host")
    return value


def normalize_domain(value: str) -> str:
    """Validate a bare domain/host (DNS name or IP literal)."""
    value = value.strip().lower()
    if not value or len(value) > _MAX_DOMAIN_LENGTH:
        raise ValueError("Invalid domain/host")
    try:
        ipaddress.ip_address(value)
        return value
    except ValueError:
        pass
    if not _DOMAIN_RE.match(value):
        raise ValueError("Invalid domain/host")
    return value


def extract_domain(url: str) -> str:
    """Derive and validate the domain from a URL server-side.

    The domain is never trusted from client input directly — it's
    always re-derived from the validated URL, so a caller can't send a
    URL/domain pair that disagree.
    """
    hostname = urlparse(url).hostname or ""
    return normalize_domain(hostname)


BrowserName = Literal["chrome", "edge", "firefox"]
WebsiteAction = Literal["allow", "block", "allow_once"]
WebsiteDecision = Literal["allow_once", "always_allow", "always_block", "block"]


class HealthResponse(BaseModel):
    status: str
    app: str
    version: str


class StatusResponse(BaseModel):
    protection_status: str
    uptime_seconds: float
    websites_scanned: int
    websites_blocked: int
    threats_detected: int
    suspicious_processes: int
    network_events: int
    recent_alerts: int


class TokenRotateResponse(BaseModel):
    rotated_at: dt.datetime
    new_token: str
    message: str = "Token rotated. Update all clients with the new value."


class WebsiteCheckRequest(BaseModel):
    """Sent by a browser extension for every top-level navigation.

    Only the URL and which browser sent it — no domain/scheme fields:
    both are derived server-side from the validated URL so a client
    can't send mismatched metadata.
    """

    url: str = Field(..., max_length=MAX_URL_LENGTH)
    browser: BrowserName

    @field_validator("url")
    @classmethod
    def _validate_url(cls, v: str) -> str:
        return normalize_url(v)


class WebsiteCheckResponse(BaseModel):
    action: WebsiteAction
    risk: int = Field(ge=0, le=100)
    reason: str


class WebsiteDecisionRequest(BaseModel):
    """Sent by the popup or the blocked page when the user makes a manual call."""

    url: str = Field(..., max_length=MAX_URL_LENGTH)
    browser: BrowserName
    decision: WebsiteDecision

    @field_validator("url")
    @classmethod
    def _validate_url(cls, v: str) -> str:
        return normalize_url(v)


class WebsiteDecisionResponse(BaseModel):
    status: str
    applied: str


PersistenceSourceType = Literal["registry_run", "registry_runonce", "startup_folder", "scheduled_task", "service"]


class KillProcessRequest(BaseModel):
    pid: int = Field(..., gt=0)
    confirm: bool = False


class KillProcessResponse(BaseModel):
    status: str
    pid: int
    name: str


class QuarantineFileRequest(BaseModel):
    path: str = Field(..., max_length=4096)
    reason: str = Field(default="", max_length=1000)
    confirm: bool = False


class QuarantineFileResponse(BaseModel):
    status: str
    quarantine_id: int
    original_path: str
    quarantine_path: str


class RestoreQuarantineRequest(BaseModel):
    quarantine_id: int
    confirm: bool = False


class RestoreQuarantineResponse(BaseModel):
    status: str
    original_path: str


class DisablePersistenceRequest(BaseModel):
    source_type: PersistenceSourceType
    location: str = Field(..., max_length=1024)
    name: str = Field(..., max_length=512)
    confirm: bool = False


class DisablePersistenceResponse(BaseModel):
    status: str
    action: str
    details: dict


class FalsePositiveResponse(BaseModel):
    status: str
    id: int
