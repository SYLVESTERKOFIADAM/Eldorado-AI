from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Callable, Protocol
from uuid import UUID

from backend.security.jwt import create_access_token
from backend.security.refresh_token import (
    generate_refresh_token,
    hash_refresh_token,
)
from backend.security.session_issuance import IssuedSession


class RotationStatus(str, Enum):
    ROTATED = "ROTATED"
    REPLAY = "REPLAY"
    INVALID = "INVALID"


@dataclass(frozen=True)
class RotationOutcome:
    status: RotationStatus
    user_id: UUID | None = None
    session_id: UUID | None = None
    refresh_expires_at: datetime | None = None
    access_token: str | None = field(default=None, repr=False)


class RefreshStore(Protocol):
    def rotate(
        self,
        presented_token_hash: str,
        replacement_token_hash: str,
        now: datetime,
        mint_access_token: Callable[[UUID], str],
    ) -> RotationOutcome:
        """
        Authenticate a refresh credential and rotate it atomically.

        REPLAY means the credential was already used: the implementation
        must have revoked the token family and committed that revocation.
        INVALID carries no identity.
        """


def refresh_session(
    store: RefreshStore,
    raw_refresh_token: str,
    *,
    now: datetime | None = None,
) -> IssuedSession | None:
    """
    Exchange a refresh token for a new access token and refresh token.

    Returns None for every failure (malformed, unknown, expired, revoked,
    replayed) so callers cannot distinguish the cause. Store errors
    propagate, and callers must fail closed.
    """
    if now is None:
        now = datetime.now(timezone.utc)

    if now.tzinfo is None:
        raise ValueError("now must be timezone-aware.")

    try:
        presented_hash = hash_refresh_token(raw_refresh_token)
    except ValueError:
        return None

    replacement = generate_refresh_token()

    outcome = store.rotate(
        presented_hash,
        replacement.token_hash,
        now,
        create_access_token,
    )

    if outcome.status is not RotationStatus.ROTATED:
        return None

    if (
        outcome.user_id is None
        or outcome.session_id is None
        or outcome.refresh_expires_at is None
        or outcome.access_token is None
    ):
        raise RuntimeError("Rotation outcome is incomplete.")

    return IssuedSession(
        user_id=outcome.user_id,
        session_id=outcome.session_id,
        refresh_expires_at=outcome.refresh_expires_at,
        access_token=outcome.access_token,
        refresh_token=replacement.raw_token,
    )