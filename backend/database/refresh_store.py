from __future__ import annotations

from datetime import datetime
from typing import Callable
from uuid import UUID

from backend.database.connection import DatabaseConnection
from backend.models.session import RefreshTokenRecord
from backend.repositories.postgres_refresh_authentication_repository import (
    PostgresRefreshAuthenticationRepository,
)
from backend.repositories.postgres_session_repository import (
    PostgresSessionRepository,
)
from backend.repositories.refresh_authentication_repository import (
    RefreshAuthenticationState,
)
from backend.security.session_refresh import (
    RotationOutcome,
    RotationStatus,
)


class PostgresRefreshStore:
    """
    PostgreSQL refresh-token rotation.

    Authentication, replay handling and rotation share the single
    transaction opened by the refresh authentication boundary.

    On REPLAY the token family is revoked and the transaction is left
    normally so the revocation commits. Raising there would roll it back.
    """

    def __init__(self, dsn: str) -> None:
        if not dsn.strip():
            raise ValueError("Database DSN must not be empty.")

        self._database = DatabaseConnection(dsn)

    def rotate(
        self,
        presented_token_hash: str,
        replacement_token_hash: str,
        now: datetime,
        mint_access_token: Callable[[UUID], str],
    ) -> RotationOutcome:
        authentication_repository = PostgresRefreshAuthenticationRepository(
            self._database
        )

        try:
            with authentication_repository.refresh_transaction(
                presented_token_hash
            ) as context:
                connection = context.connection
                authentication = context.authentication
                sessions = PostgresSessionRepository(
                    self._database,
                    authentication.user_id,
                )

                if authentication.state is RefreshAuthenticationState.REPLAY:
                    sessions.revoke_token_family_in_transaction(
                        connection,
                        authentication.token_family_id,
                        now,
                        now,
                    )
                    return RotationOutcome(RotationStatus.REPLAY)

                row = connection.execute(
                    """
                    SELECT out_expires_at, out_is_active
                    FROM public.get_refresh_session_state(%s)
                    """,
                    (authentication.session_id,),
                ).fetchone()

                if row is None:
                    return RotationOutcome(RotationStatus.INVALID)

                session_expires_at, is_active = row

                if not is_active or session_expires_at <= now:
                    return RotationOutcome(RotationStatus.INVALID)

                # Minted before any write: a signing failure rolls the
                # whole transaction back and the token is not consumed.
                access_token = mint_access_token(authentication.user_id)

                replacement = RefreshTokenRecord(
                    session_id=authentication.session_id,
                    token_hash=replacement_token_hash,
                    issued_at=now,
                    expires_at=session_expires_at,
                )

                sessions.rotate_refresh_token_in_transaction(
                    connection,
                    authentication.refresh_token_id,
                    replacement,
                    now,
                )

                return RotationOutcome(
                    RotationStatus.ROTATED,
                    user_id=authentication.user_id,
                    session_id=authentication.session_id,
                    refresh_expires_at=session_expires_at,
                    access_token=access_token,
                )
        except PermissionError:
            return RotationOutcome(RotationStatus.INVALID)