from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field

from backend.api.auth_routes import (
    _enforce,
    get_client_ip,
    get_rate_limit_store,
)
from backend.api.database import get_database_dsn
from backend.api.login_routes import ACCESS_TOKEN_EXPIRES_IN
from backend.database.refresh_store import PostgresRefreshStore
from backend.security.rate_limit import RateLimitPolicy, RateLimitStore
from backend.security.session_refresh import RefreshStore, refresh_session

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/auth", tags=["auth"])

REFRESH_PER_IP = RateLimitPolicy("refresh_ip", 60, 900)

_INVALID_REFRESH = {"detail": "Invalid refresh token"}


class RefreshRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    refresh_token: str = Field(min_length=1, max_length=256)


def get_refresh_store() -> RefreshStore:
    return PostgresRefreshStore(get_database_dsn())


@router.post("/refresh")
def refresh(
    payload: RefreshRequest,
    client_ip: str = Depends(get_client_ip),
    store: RefreshStore = Depends(get_refresh_store),
    limits: RateLimitStore = Depends(get_rate_limit_store),
) -> JSONResponse:
    _enforce(limits, REFRESH_PER_IP, client_ip)

    try:
        issued = refresh_session(store, payload.refresh_token)
    except Exception:
        logger.exception("refresh failed")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Service temporarily unavailable",
        ) from None

    if issued is None:
        return JSONResponse(
            status_code=status.HTTP_401_UNAUTHORIZED,
            content=_INVALID_REFRESH,
            headers={"WWW-Authenticate": "Bearer"},
        )

    return JSONResponse(
        status_code=status.HTTP_200_OK,
        content={
            "token_type": "bearer",
            "access_token": issued.access_token,
            "expires_in": ACCESS_TOKEN_EXPIRES_IN,
            "refresh_token": issued.refresh_token,
            "refresh_expires_at": issued.refresh_expires_at.isoformat(),
        },
        headers={
            "Cache-Control": "no-store",
            "Pragma": "no-cache",
        },
    )