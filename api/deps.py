"""Shared FastAPI dependencies."""

from __future__ import annotations

from typing import Iterator

from fastapi import Request
from sqlalchemy.orm import Session

from config.settings import Settings


def get_settings_dep(request: Request) -> Settings:
    return request.app.state.settings


def get_db(request: Request) -> Iterator[Session]:
    session_factory = request.app.state.session_factory
    session = session_factory()
    try:
        yield session
    finally:
        session.close()
