"""Pydantic response models for the agent API."""

from __future__ import annotations

import datetime as dt

from pydantic import BaseModel


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
