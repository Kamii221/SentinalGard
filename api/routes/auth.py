"""Administrative token management."""

from __future__ import annotations

import datetime as dt

from fastapi import APIRouter, Depends, Request
from sqlalchemy.orm import Session

from agent.audit import log_admin_action
from api.deps import get_db
from api.schemas import TokenRotateResponse
from api.security import get_token_store, require_agent_token, TokenStore

router = APIRouter(prefix="/auth", tags=["auth"], dependencies=[Depends(require_agent_token)])


@router.post("/rotate-token", response_model=TokenRotateResponse)
def rotate_token(
    request: Request,
    session: Session = Depends(get_db),
    token_store: TokenStore = Depends(get_token_store),
) -> TokenRotateResponse:
    """Rotate the agent's shared secret.

    Requires presenting the *current* valid token (enforced by the router
    dependency) so an unauthenticated caller cannot lock out the real
    owner. The new token is returned once in the response body — it is
    the caller's responsibility to update every client (extensions, GUI).
    """
    new_token = token_store.rotate()
    now = dt.datetime.now(dt.timezone.utc)
    log_admin_action(
        session,
        "rotate_token",
        details={"client_host": request.client.host if request.client else None},
    )
    return TokenRotateResponse(rotated_at=now, new_token=new_token)
