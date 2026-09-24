from __future__ import annotations

from abc import ABC, abstractmethod
from datetime import datetime
from uuid import UUID

from backend.models.session import (
    RefreshTokenRecord,
    SessionRecord,
)


class SessionRepository(ABC):
    """
    Persistence boundary for authenticated Eldorado sessions.

    Security rules:
    - Repository methods operate within the authenticated user's
      PostgreSQL RLS boundary.
    - Plaintext refresh tokens must never be persisted.
    - Refresh-token lifecycle transitions must be atomic.
    - Authorization remains enforced by the database RLS boundary;
      repository methods must not replace that boundary with
      caller-supplied ownership checks.
    """

    @abstractmethod
    def create_session(
        self,
        session: SessionRecord,
    ) -> SessionRecord:
        """Persist a new authenticated session."""
        raise NotImplementedError

    @abstractmethod
    def get_session(
        self,
        session_id: UUID,
    ) -> SessionRecord | None:
        """Return a session by ID, or None if it does not exist."""
        raise NotImplementedError

    @abstractmethod
    def touch_session(
        self,
        session_id: UUID,
        last_used_at: datetime,
    ) -> SessionRecord:
        """
        Update the session's last-used timestamp.

        The concrete repository must preserve the database transaction
        and RLS ownership boundary.
        """
        raise NotImplementedError

    @abstractmethod
    def revoke_session(
        self,
        session_id: UUID,
        revoked_at: datetime,
    ) -> SessionRecord:
        """Revoke one authenticated session."""
        raise NotImplementedError

    @abstractmethod
    def revoke_token_family(
        self,
        token_family_id: UUID,
        revoked_at: datetime,
        reuse_detected_at: datetime,
    ) -> int:
        """
        Revoke all sessions belonging to a token family.

        Returns the number of sessions affected.
        """
        raise NotImplementedError

    @abstractmethod
    def create_refresh_token(
        self,
        token: RefreshTokenRecord,
    ) -> RefreshTokenRecord:
        """
        Persist a refresh-token record.

        Only the token hash may be persisted; plaintext credentials
        must never reach this repository.
        """
        raise NotImplementedError

    @abstractmethod
    def get_refresh_token_by_hash(
        self,
        token_hash: str,
    ) -> RefreshTokenRecord | None:
        """
        Find a refresh token by its cryptographic hash.

        The concrete repository must rely on PostgreSQL RLS to enforce
        ownership through the associated session.
        """
        raise NotImplementedError

    @abstractmethod
    def rotate_refresh_token(
        self,
        current_token_id: UUID,
        replacement: RefreshTokenRecord,
        consumed_at: datetime,
    ) -> RefreshTokenRecord:
        """
        Atomically consume a refresh token and create its replacement.

        The concrete implementation must ensure that concurrent use
        cannot successfully rotate the same refresh token more than
        once.
        """
        raise NotImplementedError
