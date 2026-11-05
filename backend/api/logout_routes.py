from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, HTTPException, Response, status
from pydantic import BaseModel, ConfigDict, Field

from backend.api.auth_routes import (
    _enforce,
    get_client_ip,
    get_rate_limit_store,
)
from backend.api.database import get_database_dsn
from backend.database.logout_store import PostgresLogoutStore
from backend.security.rate_limit import RateLimitPolicy, RateLimitStore
from backend.security.session_logout import LogoutStore, logout_session

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/auth", tags=["auth"])

LOGOUT_PER_IP = RateLimitPolicy("logout_ip", 60, 900)


class LogoutRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    refresh_token: str = Field(min_length=1, max_length=256)


def get_logout_store() -> LogoutStore:
    return PostgresLogoutStore(get_database_dsn())


@router.post(
    "/logout",
    status_code=status.HTTP_204_NO_CONTENT,
    response_class=Response,
)
def logout(
    payload: LogoutRequest,
    client_ip: str = Depends(get_client_ip),
    store: LogoutStore = Depends(get_logout_store),
    limits: RateLimitStore = Depends(get_rate_limit_store),
) -> Response:
    _enforce(limits, LOGOUT_PER_IP, client_ip)

    try:
        logout_session(store, payload.refresh_token)
    except Exception:
        logger.exception("logout failed")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Service temporarily unavailable",
        ) from None

    return Response(
        status_code=status.HTTP_204_NO_CONTENT,
        headers={"Cache-Control": "no-store"},
    )