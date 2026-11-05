from __future__ import annotations

from datetime import datetime, timezone
from typing import Protocol

from backend.security.refresh_token import hash_refresh_token


class LogoutStore(Protocol):
    def revoke(
        self,
        presented_token_hash: str,
        now: datetime,
    ) -> bool:
        """
        Revoke the session that owns a refresh credential.

        Returns True when a session was revoked. Returns False for an
        unknown, expired or already revoked credential. A replayed
        credential revokes its whole token family.
        """


def logout_session(
    store: LogoutStore,
    raw_refresh_token: str,
    *,
    now: datetime | None = None,
) -> bool:
    """
    Revoke the session identified by a refresh token.

    Callers must give the same outward response whether or not a session
    was revoked. Store errors propagate, and callers must fail closed.
    """
    if now is None:
        now = datetime.now(timezone.utc)

    if now.tzinfo is None:
        raise ValueError("now must be timezone-aware.")

    try:
        presented_hash = hash_refresh_token(raw_refresh_token)
    except ValueError:
        return False

    return store.revoke(presented_hash, now)