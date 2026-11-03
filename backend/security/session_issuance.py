from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from uuid import UUID, uuid4

from backend.models.session import RefreshTokenRecord, SessionRecord
from backend.repositories.session_repository import SessionRepository
from backend.security.jwt import create_access_token
from backend.security.refresh_token import generate_refresh_token

SESSION_LIFETIME = timedelta(days=30)


@dataclass(frozen=True)
class IssuedSession:
    """
    Credentials for a newly created session.

    access_token and refresh_token exist only for delivery to the
    client. Never log or persist them.
    """

    user_id: UUID
    session_id: UUID
    refresh_expires_at: datetime
    access_token: str = field(repr=False)
    refresh_token: str = field(repr=False)


def issue_session(
    repository: SessionRepository,
    user_id: UUID,
    *,
    now: datetime | None = None,
    lifetime: timedelta = SESSION_LIFETIME,
) -> IssuedSession:
    """
    Create a session with a first refresh token and an access token.

    The caller must already have authenticated user_id (for example via
    authenticate_password). Only the refresh token hash is persisted.
    """
    if not isinstance(user_id, UUID):
        raise TypeError("user_id must be a UUID.")

    if now is None:
        now = datetime.now(timezone.utc)

    if now.tzinfo is None:
        raise ValueError("now must be timezone-aware.")

    if lifetime <= timedelta(0):
        raise ValueError("lifetime must be positive.")

    # Mint first: a misconfigured signing secret must not leave a
    # persisted session behind.
    access_token = create_access_token(user_id)
    refresh = generate_refresh_token()
    expires_at = now + lifetime

    session = repository.create_session(
        SessionRecord(
            user_id=user_id,
            token_family_id=uuid4(),
            created_at=now,
            expires_at=expires_at,
        )
    )

    try:
        repository.create_refresh_token(
            RefreshTokenRecord(
                session_id=session.id,
                token_hash=refresh.token_hash,
                issued_at=now,
                expires_at=expires_at,
            )
        )
    except Exception:
        # Session and token are separate transactions, so clean up the
        # half-created session. Cleanup must never mask the original error.
        try:
            repository.revoke_session(
                session.id,
                max(now, datetime.now(timezone.utc)),
            )
        except Exception:
            pass

        raise

    return IssuedSession(
        user_id=user_id,
        session_id=session.id,
        refresh_expires_at=expires_at,
        access_token=access_token,
        refresh_token=refresh.raw_token,
    )