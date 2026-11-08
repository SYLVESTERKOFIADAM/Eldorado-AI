from __future__ import annotations

import hashlib
import secrets
from dataclasses import dataclass, field
from typing import Protocol

from backend.security.passwords import hash_password
from backend.security.registration import normalize_email, validate_password


@dataclass(frozen=True)
class PasswordResetToken:
    """Raw reset credential for delivery and its hash for storage."""

    raw_token: str = field(repr=False)
    token_hash: str


def hash_password_reset_token(raw_token: str) -> str:
    if not isinstance(raw_token, str) or not raw_token:
        raise ValueError("reset token must not be empty")

    try:
        encoded = raw_token.encode("ascii")
    except UnicodeEncodeError as exc:
        raise ValueError("reset token is invalid") from exc

    return hashlib.sha256(encoded).hexdigest()


def generate_password_reset_token() -> PasswordResetToken:
    """
    Generate a 256-bit reset credential.

    Deliver raw_token to the account owner. Persist only token_hash.
    Never log or persist raw_token.
    """
    raw_token = secrets.token_urlsafe(32)

    return PasswordResetToken(
        raw_token=raw_token,
        token_hash=hash_password_reset_token(raw_token),
    )


class PasswordResetStore(Protocol):
    def issue_reset_token(self, email: str, token_hash: str) -> bool:
        """True only when a token was stored for an eligible account."""

    def reset_password(self, token_hash: str, new_password_hash: str) -> bool:
        """True only when a valid token was consumed and the password set."""


@dataclass(frozen=True)
class ResetRequestResult:
    """
    reset_token is set only when a token was stored, and exists solely for
    email delivery. Never log or persist it. Callers must give the same
    outward response whether or not it is set.
    """

    reset_token: str | None = field(default=None, repr=False)


def request_password_reset(
    store: PasswordResetStore,
    email: str,
) -> ResetRequestResult:
    normalized_email = normalize_email(email)
    token = generate_password_reset_token()

    if store.issue_reset_token(normalized_email, token.token_hash):
        return ResetRequestResult(reset_token=token.raw_token)

    return ResetRequestResult()


def complete_password_reset(
    store: PasswordResetStore,
    raw_token: str,
    new_password: str,
) -> bool:
    """
    Reset a password using an emailed token.

    Raises RegistrationInputError when the new password breaks policy.
    Returns False for every invalid token so callers cannot distinguish
    the cause. Store errors propagate, and callers must fail closed.
    """
    # The token does not carry the account email, so the
    # password-equals-email check is not applied here.
    validate_password(new_password, "")

    try:
        token_hash = hash_password_reset_token(raw_token)
    except ValueError:
        return False

    return store.reset_password(token_hash, hash_password(new_password))