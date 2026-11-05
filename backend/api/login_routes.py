from __future__ import annotations

import logging
from typing import Callable
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field

from backend.api.auth_routes import (
    get_client_ip,
    get_rate_limit_store,
)
from backend.api.database import get_database_dsn
from backend.database.connection import DatabaseConnection
from backend.database.login_store import PostgresCredentialStore
from backend.repositories.postgres_session_repository import (
    PostgresSessionRepository,
)
from backend.repositories.session_repository import SessionRepository
from backend.security.login import CredentialStore, authenticate_password
from backend.security.rate_limit import (
    LOGIN_PER_ACCOUNT,
    LOGIN_PER_IP,
    RateLimitPolicy,
    RateLimitStore,
    check_rate_limit,
)
from backend.security.registration import (
    RegistrationInputError,
    normalize_email,
)
from backend.security.session_issuance import issue_session

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/auth", tags=["auth"])

# Matches the 15-minute access token lifetime configured in jwt.py.
ACCESS_TOKEN_EXPIRES_IN = 900

SessionRepositoryFactory = Callable[[UUID], SessionRepository]

_INVALID_CREDENTIALS = {"detail": "Invalid email or password"}


class LoginRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    email: str = Field(max_length=320)
    password: str = Field(max_length=1024)


def get_credential_store() -> CredentialStore:
    return PostgresCredentialStore(get_database_dsn())


def get_session_repository_factory() -> SessionRepositoryFactory:
    dsn = get_database_dsn()

    def factory(user_id: UUID) -> SessionRepository:
        return PostgresSessionRepository(DatabaseConnection(dsn), user_id)

    return factory


def _enforce(
    store: RateLimitStore,
    policy: RateLimitPolicy,
    identifier: str,
) -> None:
    try:
        allowed = check_rate_limit(store, policy, identifier)
    except Exception:
        logger.exception("rate limit check failed")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Service temporarily unavailable",
        ) from None

    if not allowed:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many requests",
            headers={"Retry-After": str(policy.window_seconds)},
        )


def _invalid_credentials() -> JSONResponse:
    return JSONResponse(
        status_code=status.HTTP_401_UNAUTHORIZED,
        content=_INVALID_CREDENTIALS,
        headers={"WWW-Authenticate": "Bearer"},
    )


@router.post("/login")
def login(
    payload: LoginRequest,
    client_ip: str = Depends(get_client_ip),
    credentials: CredentialStore = Depends(get_credential_store),
    limits: RateLimitStore = Depends(get_rate_limit_store),
    session_repositories: SessionRepositoryFactory = Depends(
        get_session_repository_factory
    ),
) -> JSONResponse:
    _enforce(limits, LOGIN_PER_IP, client_ip)

    try:
        email = normalize_email(payload.email)
    except RegistrationInputError:
        return _invalid_credentials()

    _enforce(limits, LOGIN_PER_ACCOUNT, email)

    try:
        result = authenticate_password(credentials, email, payload.password)
    except Exception:
        logger.exception("credential check failed")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Service temporarily unavailable",
        ) from None

    if result is None:
        return _invalid_credentials()

    try:
        issued = issue_session(
            session_repositories(result.user_id),
            result.user_id,
        )
    except Exception:
        logger.exception("session issuance failed")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Service temporarily unavailable",
        ) from None

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