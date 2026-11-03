from __future__ import annotations

import hashlib
import secrets
from dataclasses import dataclass


@dataclass(frozen=True)
class EmailVerificationToken:
    """Raw token for delivery and its hash for database storage."""

    raw_token: str
    token_hash: str


def generate_email_verification_token() -> EmailVerificationToken:
    """
    Generate a 256-bit verification token.

    Deliver raw_token to the account owner. Persist only token_hash.
    Never log or persist raw_token.
    """
    raw_token = secrets.token_urlsafe(32)
    token_hash = hashlib.sha256(
        raw_token.encode("ascii")
    ).hexdigest()

    return EmailVerificationToken(
        raw_token=raw_token,
        token_hash=token_hash,
    )


def hash_email_verification_token(raw_token: str) -> str:
    """
    Hash a received verification token for database lookup.

    Invalid input is rejected. This function does not verify whether
    a token exists, is unexpired, or has already been consumed.
    Those checks belong to the database verification function.
    """
    if not isinstance(raw_token, str) or not raw_token:
        raise ValueError("verification token must not be empty")

    try:
        encoded_token = raw_token.encode("ascii")
    except UnicodeEncodeError as exc:
        raise ValueError("verification token is invalid") from exc

    return hashlib.sha256(encoded_token).hexdigest()
