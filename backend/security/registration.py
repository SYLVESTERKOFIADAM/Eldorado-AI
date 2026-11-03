from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Protocol
from uuid import UUID

from backend.security.email_verification import (
    generate_email_verification_token,
    hash_email_verification_token,
)
from backend.security.passwords import hash_password

MAX_EMAIL_LENGTH = 320
MIN_PASSWORD_LENGTH = 12
MAX_PASSWORD_LENGTH = 1024

_EMAIL_PATTERN = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


class RegistrationInputError(ValueError):
    """Invalid registration input. Messages are safe to show to users."""


class AccountStore(Protocol):
    def create_pending_account(
        self,
        email: str,
        password_hash: str,
        token_hash: str,
    ) -> UUID | None:
        """Return the new user id, or None if the email is registered."""

    def verify_email_token(self, token_hash: str) -> bool:
        """Return True only when a valid token was consumed."""


@dataclass(frozen=True)
class RegistrationResult:
    """
    Outcome of a registration attempt.

    verification_token is set only when a new account was created, and
    exists solely for email delivery. Never log or persist it. Callers
    must give the same outward response whether or not it is set.
    """

    verification_token: str | None = field(default=None, repr=False)


def normalize_email(email: str) -> str:
    if not isinstance(email, str):
        raise RegistrationInputError("Enter a valid email address.")

    normalized = email.strip().lower()

    if (
        not normalized
        or len(normalized) > MAX_EMAIL_LENGTH
        or not normalized.isascii()
        or not normalized.isprintable()
        or _EMAIL_PATTERN.fullmatch(normalized) is None
    ):
        raise RegistrationInputError("Enter a valid email address.")

    return normalized


def validate_password(password: str, normalized_email: str) -> None:
    if not isinstance(password, str):
        raise RegistrationInputError("Enter a valid password.")

    if len(password) < MIN_PASSWORD_LENGTH:
        raise RegistrationInputError(
            f"Password must be at least {MIN_PASSWORD_LENGTH} characters."
        )

    if len(password) > MAX_PASSWORD_LENGTH:
        raise RegistrationInputError(
            f"Password must be at most {MAX_PASSWORD_LENGTH} characters."
        )

    if not password.strip():
        raise RegistrationInputError("Password must not be blank.")

    if password.strip().lower() == normalized_email:
        raise RegistrationInputError(
            "Password must not be the same as the email address."
        )


def register_account(
    store: AccountStore,
    email: str,
    password: str,
) -> RegistrationResult:
    normalized_email = normalize_email(email)
    validate_password(password, normalized_email)

    # Hash before touching the database so a duplicate registration
    # costs the same time as a new one.
    password_hash = hash_password(password)
    token = generate_email_verification_token()

    user_id = store.create_pending_account(
        normalized_email,
        password_hash,
        token.token_hash,
    )

    if user_id is None:
        return RegistrationResult()

    return RegistrationResult(verification_token=token.raw_token)


def verify_email(store: AccountStore, raw_token: str) -> bool:
    try:
        token_hash = hash_email_verification_token(raw_token)
    except ValueError:
        return False

    return store.verify_email_token(token_hash)