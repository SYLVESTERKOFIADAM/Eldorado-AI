from __future__ import annotations

import hashlib
import secrets
from dataclasses import dataclass, field


@dataclass(frozen=True)
class RefreshToken:
    """Raw refresh credential for the client and its hash for storage."""

    raw_token: str = field(repr=False)
    token_hash: str


def hash_refresh_token(raw_token: str) -> str:
    """
    Hash a refresh credential for storage or lookup.

    Does not check whether the token exists, is unexpired, or has been
    consumed. Those checks belong to the database.
    """
    if not isinstance(raw_token, str) or not raw_token:
        raise ValueError("refresh token must not be empty")

    try:
        encoded = raw_token.encode("ascii")
    except UnicodeEncodeError as exc:
        raise ValueError("refresh token is invalid") from exc

    return hashlib.sha256(encoded).hexdigest()


def generate_refresh_token() -> RefreshToken:
    """
    Generate a 256-bit refresh credential.

    Deliver raw_token to the client once. Persist only token_hash.
    Never log or persist raw_token.
    """
    raw_token = secrets.token_urlsafe(32)

    return RefreshToken(
        raw_token=raw_token,
        token_hash=hash_refresh_token(raw_token),
    )