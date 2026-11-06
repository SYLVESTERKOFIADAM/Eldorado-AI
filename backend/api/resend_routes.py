from __future__ import annotations

import logging

from fastapi import (
    APIRouter,
    BackgroundTasks,
    Depends,
    HTTPException,
    status,
)
from pydantic import BaseModel, ConfigDict, Field

from backend.api.auth_routes import (
    _deliver_verification,
    _enforce,
    get_client_ip,
    get_email_sender,
    get_rate_limit_store,
)
from backend.api.database import get_database_dsn
from backend.database.verification_resend_store import (
    PostgresVerificationResendStore,
)
from backend.security.rate_limit import RateLimitPolicy, RateLimitStore
from backend.security.registration import (
    RegistrationInputError,
    normalize_email,
)
from backend.security.verification_resend import (
    VerificationResendStore,
    resend_verification,
)
from backend.services.verification_email import VerificationEmailSender

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/auth", tags=["auth"])

RESEND_PER_IP = RateLimitPolicy("resend_ip", 5, 3600)
RESEND_PER_EMAIL = RateLimitPolicy("resend_email", 3, 3600)

_RESEND_ACCEPTED = {
    "status": "pending",
    "detail": (
        "If the address has a pending verification, "
        "a new email will be sent."
    ),
}


class ResendRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    email: str = Field(max_length=320)


def get_resend_store() -> VerificationResendStore:
    return PostgresVerificationResendStore(get_database_dsn())


@router.post("/resend-verification", status_code=status.HTTP_202_ACCEPTED)
def resend(
    payload: ResendRequest,
    background_tasks: BackgroundTasks,
    client_ip: str = Depends(get_client_ip),
    store: VerificationResendStore = Depends(get_resend_store),
    limits: RateLimitStore = Depends(get_rate_limit_store),
    sender: VerificationEmailSender = Depends(get_email_sender),
) -> dict[str, str]:
    _enforce(limits, RESEND_PER_IP, client_ip)

    try:
        email = normalize_email(payload.email)
    except RegistrationInputError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail=str(exc),
        ) from None

    _enforce(limits, RESEND_PER_EMAIL, email)

    try:
        result = resend_verification(store, email)
    except Exception:
        logger.exception("verification resend failed")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Service temporarily unavailable",
        ) from None

    if result.verification_token is not None:
        background_tasks.add_task(
            _deliver_verification,
            sender,
            email,
            result.verification_token,
        )

    return dict(_RESEND_ACCEPTED)