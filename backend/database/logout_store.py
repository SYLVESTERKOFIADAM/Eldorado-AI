from __future__ import annotations

from datetime import datetime

from backend.database.connection import DatabaseConnection
from backend.repositories.postgres_refresh_authentication_repository import (
    PostgresRefreshAuthenticationRepository,
)
from backend.repositories.postgres_session_repository import (
    PostgresSessionRepository,
)
from backend.repositories.refresh_authentication_repository import (
    RefreshAuthenticationState,
)


class PostgresLogoutStore:
    """
    PostgreSQL session revocation for logout.

    Authentication and revocation share the single transaction opened by
    the refresh authentication boundary. A replayed credential revokes
    its whole token family and the transaction is left normally so the
    revocation commits.
    """

    def __init__(self, dsn: str) -> None:
        if not dsn.strip():
            raise ValueError("Database DSN must not be empty.")

        self._database = DatabaseConnection(dsn)

    def revoke(
        self,
        presented_token_hash: str,
        now: datetime,
    ) -> bool:
        repository = PostgresRefreshAuthenticationRepository(self._database)

        try:
            with repository.refresh_transaction(
                presented_token_hash
            ) as context:
                connection = context.connection
                authentication = context.authentication

                if authentication.state is RefreshAuthenticationState.REPLAY:
                    sessions = PostgresSessionRepository(
                        self._database,
                        authentication.user_id,
                    )
                    sessions.revoke_token_family_in_transaction(
                        connection,
                        authentication.token_family_id,
                        now,
                        now,
                    )
                    return True

                cursor = connection.execute(
                    """
                    UPDATE sessions
                    SET revoked_at = %s
                    WHERE id = %s
                      AND revoked_at IS NULL
                    """,
                    (now, authentication.session_id),
                )

                return cursor.rowcount == 1
        except PermissionError:
            return False