from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol

from backend.security.email_verification import (
    generate_email_verification_token,
)
from backend.security.registration import normalize_email


class VerificationResendStore(Protocol):
    def issue_verification_token(
        self,
        email: str,
        token_hash: str,
    ) -> bool:
        """
        Store a new verification token for a pending account.

        Returns True only when a token was stored. Returns False for an
        unknown, already verified, inactive or cooling-down account.
        """


@dataclass(frozen=True)
class ResendResult:
    """
    verification_token is set only when a new token was stored, and
    exists solely for email delivery. Never log or persist it. Callers
    must give the same outward response whether or not it is set.
    """

    verification_token: str | None = field(default=None, repr=False)


def resend_verification(
    store: VerificationResendStore,
    email: str,
) -> ResendResult:
    normalized_email = normalize_email(email)
    token = generate_email_verification_token()

    if store.issue_verification_token(normalized_email, token.token_hash):
        return ResendResult(verification_token=token.raw_token)

    return ResendResult()