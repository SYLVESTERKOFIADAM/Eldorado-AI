from __future__ import annotations

import logging
import os

from fastapi import (
    APIRouter,
    BackgroundTasks,
    Depends,
    HTTPException,
    Request,
    status,
)
from pydantic import BaseModel, ConfigDict, Field

from backend.api.database import get_database_dsn
from backend.database.account_store import PostgresAccountStore
from backend.database.rate_limit_store import PostgresRateLimitStore
from backend.security.client_ip import (
    resolve_client_ip,
    trusted_proxies_from_env,
)
from backend.security.rate_limit import (
    REGISTER_PER_EMAIL,
    REGISTER_PER_IP,
    VERIFY_PER_IP,
    RateLimitPolicy,
    RateLimitStore,
    check_rate_limit,
)
from backend.security.registration import (
    AccountStore,
    RegistrationInputError,
    normalize_email,
    register_account,
    verify_email,
)
from backend.services.smtp_email import SmtpEmailSender
from backend.services.verification_email import (
    ConsoleVerificationEmailSender,
    VerificationEmailSender,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/auth", tags=["auth"])

_REGISTER_ACCEPTED = {
    "status": "pending",
    "detail": (
        "If the address can be registered, "
        "a verification email will be sent."
    ),
}


class RegisterRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    email: str = Field(max_length=320)
    password: str = Field(max_length=1024)


class VerifyEmailRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    token: str = Field(min_length=1, max_length=256)


def get_account_store() -> AccountStore:
    return PostgresAccountStore(get_database_dsn())


def get_rate_limit_store() -> RateLimitStore:
    return PostgresRateLimitStore(get_database_dsn())


def get_email_sender() -> VerificationEmailSender:
    if os.environ.get("ELDORADO_EMAIL_BACKEND", "").strip().lower() == "smtp":
        return SmtpEmailSender.from_environment()
    environment = os.environ.get("ELDORADO_ENV", "").strip().lower()
    console_enabled = (
        os.environ.get("ELDORADO_ENABLE_CONSOLE_VERIFICATION_EMAIL", "")
        .strip()
        .lower()
        == "true"
    )

    if environment != "development" or not console_enabled:
        raise RuntimeError(
            "Verification email delivery is not configured. "
            "Console delivery requires explicit development-only opt-in."
        )

    return ConsoleVerificationEmailSender()


def get_client_ip(request: Request) -> str:
    """
    Client address used as the rate-limit identity.

    X-Forwarded-For is honoured only when the direct peer is a proxy
    listed in ELDORADO_TRUSTED_PROXIES. With the variable unset, only
    the direct connection address is used.
    """
    peer = request.client.host if request.client else None

    return resolve_client_ip(
        peer,
        request.headers.get("x-forwarded-for"),
        trusted_proxies_from_env(),
    )


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


def _deliver_verification(
    sender: VerificationEmailSender,
    email: str,
    raw_token: str,
) -> None:
    try:
        sender.send_verification(email, raw_token)
    except Exception:
        # Never log the token. Delivery failures must not change the
        # outward response (that would reveal the account is new).
        logger.error("verification email delivery failed")


@router.post("/register", status_code=status.HTTP_202_ACCEPTED)
def register(
    payload: RegisterRequest,
    background_tasks: BackgroundTasks,
    client_ip: str = Depends(get_client_ip),
    accounts: AccountStore = Depends(get_account_store),
    limits: RateLimitStore = Depends(get_rate_limit_store),
    sender: VerificationEmailSender = Depends(get_email_sender),
) -> dict[str, str]:
    _enforce(limits, REGISTER_PER_IP, client_ip)

    try:
        email = normalize_email(payload.email)
    except RegistrationInputError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail=str(exc),
        ) from None

    _enforce(limits, REGISTER_PER_EMAIL, email)

    try:
        result = register_account(accounts, email, payload.password)
    except RegistrationInputError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail=str(exc),
        ) from None

    if result.verification_token is not None:
        background_tasks.add_task(
            _deliver_verification,
            sender,
            email,
            result.verification_token,
        )

    return dict(_REGISTER_ACCEPTED)


@router.post("/verify-email")
def verify_email_endpoint(
    payload: VerifyEmailRequest,
    client_ip: str = Depends(get_client_ip),
    accounts: AccountStore = Depends(get_account_store),
    limits: RateLimitStore = Depends(get_rate_limit_store),
) -> dict[str, str]:
    _enforce(limits, VERIFY_PER_IP, client_ip)

    if not verify_email(accounts, payload.token):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired verification token",
        )

    return {"status": "verified"}