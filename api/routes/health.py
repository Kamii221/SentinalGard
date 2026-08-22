"""Unauthenticated liveness check.

No token is required here so clients (GUI, extensions, install scripts)
can distinguish "agent not running" from "agent running but I have the
wrong token" without needing credentials first. It reveals nothing
beyond the app name/version and still passes through the loopback-only
middleware.
"""

from __future__ import annotations

from fastapi import APIRouter, Request

from api.schemas import HealthResponse

router = APIRouter(tags=["health"])


@router.get("/health", response_model=HealthResponse)
def health(request: Request) -> HealthResponse:
    settings = request.app.state.settings
    return HealthResponse(status="ok", app=settings.app.name, version=settings.app.version)
