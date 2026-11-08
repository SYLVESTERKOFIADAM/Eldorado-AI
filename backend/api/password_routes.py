from __future__ import annotations

import logging
import os

from fastapi import (
    APIRouter,
    BackgroundTasks,
    Depends,
    HTTPException,
    status,
)
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field

from backend.api.auth import require_authenticated_user
from backend.api.auth_routes import (
    _enforce,
    get_client_ip,
    get_rate_limit_store,
)
from backend.api.database import get_database_dsn
from backend.database.password_stores import (
    PostgresPasswordChangeStore,
    PostgresPasswordResetStore,
)
from backend.security.authenticated_user import AuthenticatedUser
from backend.security.password_change import (
    ChangeOutcome,
    PasswordChangeStore,
    change_password,
)
from backend.security.password_reset import (
    PasswordResetStore,
    complete_password_reset,
    request_password_reset,
)
from backend.security.rate_limit import RateLimitPolicy, RateLimitStore
from backend.security.registration import (
    RegistrationInputError,
    normalize_email,
)
from backend.services.password_reset_email import (
    ConsolePasswordResetEmailSender,
    PasswordResetEmailSender,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/auth", tags=["auth"])

FORGOT_PER_IP = RateLimitPolicy("forgot_ip", 5, 3600)
FORGOT_PER_EMAIL = RateLimitPolicy("forgot_email", 3, 3600)
RESET_PER_IP = RateLimitPolicy("reset_ip", 20, 3600)
CHANGE_PER_USER = RateLimitPolicy("chpass_user", 5, 900)
CHANGE_PER_IP = RateLimitPolicy("chpass_ip", 30, 900)

_FORGOT_ACCEPTED = {
    "status": "pending",
    "detail": (
        "If the address can be reset, "
        "a password reset email will be sent."
    ),
}

_NO_STORE = {"Cache-Control": "no-store", "Pragma": "no-cache"}


class ForgotPasswordRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    email: str = Field(max_length=320)


class ResetPasswordRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    token: str = Field(min_length=1, max_length=256)
    new_password: str = Field(max_length=1024)


class ChangePasswordRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    current_password: str = Field(min_length=1, max_length=1024)
    new_password: str = Field(max_length=1024)


def get_password_reset_store() -> PasswordResetStore:
    return PostgresPasswordResetStore(get_database_dsn())


def get_password_change_store() -> PasswordChangeStore:
    return PostgresPasswordChangeStore(get_database_dsn())


def get_password_reset_sender() -> PasswordResetEmailSender:
    environment = os.environ.get("ELDORADO_ENV", "").strip().lower()
    console_enabled = (
        os.environ.get("ELDORADO_ENABLE_CONSOLE_RESET_EMAIL", "")
        .strip()
        .lower()
        == "true"
    )

    if environment != "development" or not console_enabled:
        raise RuntimeError(
            "Password reset email delivery is not configured. "
            "Console delivery requires explicit development-only opt-in."
        )

    return ConsolePasswordResetEmailSender()


def _deliver_reset(
    sender: PasswordResetEmailSender,
    email: str,
    raw_token: str,
) -> None:
    try:
        sender.send_password_reset(email, raw_token)
    except Exception:
        # Never log the token. Delivery failures must not change the
        # outward response.
        logger.error("password reset email delivery failed")


def _unavailable() -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        detail="Service temporarily unavailable",
    )


@router.post("/forgot-password", status_code=status.HTTP_202_ACCEPTED)
def forgot_password(
    payload: ForgotPasswordRequest,
    background_tasks: BackgroundTasks,
    client_ip: str = Depends(get_client_ip),
    store: PasswordResetStore = Depends(get_password_reset_store),
    limits: RateLimitStore = Depends(get_rate_limit_store),
    sender: PasswordResetEmailSender = Depends(get_password_reset_sender),
) -> dict[str, str]:
    _enforce(limits, FORGOT_PER_IP, client_ip)

    try:
        email = normalize_email(payload.email)
    except RegistrationInputError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail=str(exc),
        ) from None

    _enforce(limits, FORGOT_PER_EMAIL, email)

    try:
        result = request_password_reset(store, email)
    except Exception:
        logger.exception("password reset request failed")
        raise _unavailable() from None

    if result.reset_token is not None:
        background_tasks.add_task(
            _deliver_reset,
            sender,
            email,
            result.reset_token,
        )

    return dict(_FORGOT_ACCEPTED)


@router.post("/reset-password")
def reset_password_endpoint(
    payload: ResetPasswordRequest,
    client_ip: str = Depends(get_client_ip),
    store: PasswordResetStore = Depends(get_password_reset_store),
    limits: RateLimitStore = Depends(get_rate_limit_store),
) -> JSONResponse:
    _enforce(limits, RESET_PER_IP, client_ip)

    try:
        done = complete_password_reset(
            store,
            payload.token,
            payload.new_password,
        )
    except RegistrationInputError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail=str(exc),
        ) from None
    except Exception:
        logger.exception("password reset failed")
        raise _unavailable() from None

    if not done:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired reset token",
        )

    return JSONResponse(
        status_code=status.HTTP_200_OK,
        content={"status": "reset"},
        headers=_NO_STORE,
    )


@router.post("/change-password")
def change_password_endpoint(
    payload: ChangePasswordRequest,
    user: AuthenticatedUser = Depends(require_authenticated_user),
    client_ip: str = Depends(get_client_ip),
    store: PasswordChangeStore = Depends(get_password_change_store),
    limits: RateLimitStore = Depends(get_rate_limit_store),
) -> JSONResponse:
    _enforce(limits, CHANGE_PER_IP, client_ip)
    _enforce(limits, CHANGE_PER_USER, str(user.user_id))

    try:
        outcome = change_password(
            store,
            user.user_id,
            payload.current_password,
            payload.new_password,
        )
    except RegistrationInputError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail=str(exc),
        ) from None
    except Exception:
        logger.exception("password change failed")
        raise _unavailable() from None

    if outcome is ChangeOutcome.WRONG_CURRENT:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Current password is incorrect",
        )

    if outcome is ChangeOutcome.CONFLICT:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Password could not be changed. Try again.",
        )

    return JSONResponse(
        status_code=status.HTTP_200_OK,
        content={
            "status": "changed",
            "detail": "All sessions were signed out. Log in again.",
        },
        headers=_NO_STORE,
    )