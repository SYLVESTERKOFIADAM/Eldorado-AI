from __future__ import annotations

from datetime import datetime
from uuid import UUID

from backend.database.connection import DatabaseConnection
from backend.models.session import (
    RefreshTokenRecord,
    SessionRecord,
)
from backend.repositories.session_repository import SessionRepository


class PostgresSessionRepository(SessionRepository):
    """
    PostgreSQL-backed authentication session repository.

    Security boundary:
    - DatabaseConnection establishes the authenticated user identity
      transaction-locally.
    - PostgreSQL RLS enforces ownership.
    - Refresh-token plaintext is never accepted or persisted.
    - Refresh-token rotation is performed atomically in one transaction.
    """

    def __init__(
        self,
        database: DatabaseConnection,
        authenticated_user_id: UUID,
    ) -> None:
        self._database = database
        self._authenticated_user_id = authenticated_user_id

    def create_session(
        self,
        session: SessionRecord,
    ) -> SessionRecord:
        with self._database.transaction(
            self._authenticated_user_id
        ) as connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    """
                    INSERT INTO sessions (
                        id,
                        user_id,
                        token_family_id,
                        created_at,
                        last_used_at,
                        expires_at,
                        revoked_at,
                        reuse_detected_at
                    )
                    VALUES (
                        %s, %s, %s, %s, %s, %s, %s, %s
                    )
                    RETURNING
                        id,
                        user_id,
                        token_family_id,
                        created_at,
                        last_used_at,
                        expires_at,
                        revoked_at,
                        reuse_detected_at
                    """,
                    (
                        session.id,
                        session.user_id,
                        session.token_family_id,
                        session.created_at,
                        session.last_used_at,
                        session.expires_at,
                        session.revoked_at,
                        session.reuse_detected_at,
                    ),
                )

                row = cursor.fetchone()

        if row is None:
            raise RuntimeError(
                "Session INSERT returned no row."
            )

        return self._row_to_session(row)

    def get_session(
        self,
        session_id: UUID,
    ) -> SessionRecord | None:
        with self._database.transaction(
            self._authenticated_user_id
        ) as connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    """
                    SELECT
                        id,
                        user_id,
                        token_family_id,
                        created_at,
                        last_used_at,
                        expires_at,
                        revoked_at,
                        reuse_detected_at
                    FROM sessions
                    WHERE id = %s
                    """,
                    (session_id,),
                )

                row = cursor.fetchone()

        if row is None:
            return None

        return self._row_to_session(row)

    def touch_session(
        self,
        session_id: UUID,
        last_used_at: datetime,
    ) -> SessionRecord:
        with self._database.transaction(
            self._authenticated_user_id
        ) as connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    """
                    UPDATE sessions
                    SET last_used_at = %s
                    WHERE id = %s
                    RETURNING
                        id,
                        user_id,
                        token_family_id,
                        created_at,
                        last_used_at,
                        expires_at,
                        revoked_at,
                        reuse_detected_at
                    """,
                    (
                        last_used_at,
                        session_id,
                    ),
                )

                row = cursor.fetchone()

        if row is None:
            raise LookupError("Session was not found.")

        return self._row_to_session(row)

    def revoke_session(
        self,
        session_id: UUID,
        revoked_at: datetime,
    ) -> SessionRecord:
        with self._database.transaction(
            self._authenticated_user_id
        ) as connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    """
                    UPDATE sessions
                    SET revoked_at = %s
                    WHERE id = %s
                    RETURNING
                        id,
                        user_id,
                        token_family_id,
                        created_at,
                        last_used_at,
                        expires_at,
                        revoked_at,
                        reuse_detected_at
                    """,
                    (
                        revoked_at,
                        session_id,
                    ),
                )

                row = cursor.fetchone()

        if row is None:
            raise LookupError("Session was not found.")

        return self._row_to_session(row)

    def revoke_token_family(
        self,
        token_family_id: UUID,
        revoked_at: datetime,
        reuse_detected_at: datetime,
    ) -> int:
        with self._database.transaction(
            self._authenticated_user_id
        ) as connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    """
                    UPDATE sessions
                    SET
                        revoked_at = %s,
                        reuse_detected_at = %s
                    WHERE token_family_id = %s
                    """,
                    (
                        revoked_at,
                        reuse_detected_at,
                        token_family_id,
                    ),
                )

                return cursor.rowcount

    def create_refresh_token(
        self,
        token: RefreshTokenRecord,
    ) -> RefreshTokenRecord:
        with self._database.transaction(
            self._authenticated_user_id
        ) as connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    """
                    INSERT INTO refresh_tokens (
                        id,
                        session_id,
                        token_hash,
                        issued_at,
                        expires_at,
                        consumed_at,
                        replaced_by_id
                    )
                    VALUES (
                        %s, %s, %s, %s, %s, %s, %s
                    )
                    RETURNING
                        id,
                        session_id,
                        token_hash,
                        issued_at,
                        expires_at,
                        consumed_at,
                        replaced_by_id
                    """,
                    (
                        token.id,
                        token.session_id,
                        token.token_hash,
                        token.issued_at,
                        token.expires_at,
                        token.consumed_at,
                        token.replaced_by_id,
                    ),
                )

                row = cursor.fetchone()

        if row is None:
            raise RuntimeError(
                "Refresh-token INSERT returned no row."
            )

        return self._row_to_refresh_token(row)

    def get_refresh_token_by_hash(
        self,
        token_hash: str,
    ) -> RefreshTokenRecord | None:
        with self._database.transaction(
            self._authenticated_user_id
        ) as connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    """
                    SELECT
                        id,
                        session_id,
                        token_hash,
                        issued_at,
                        expires_at,
                        consumed_at,
                        replaced_by_id
                    FROM refresh_tokens
                    WHERE token_hash = %s
                    """,
                    (token_hash,),
                )

                row = cursor.fetchone()

        if row is None:
            return None

        return self._row_to_refresh_token(row)

    def rotate_refresh_token(
        self,
        current_token_id: UUID,
        replacement: RefreshTokenRecord,
        consumed_at: datetime,
    ) -> RefreshTokenRecord:
        with self._database.transaction(
            self._authenticated_user_id
        ) as connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    """
                    SELECT
                        rt.id,
                        rt.session_id,
                        rt.token_hash,
                        rt.issued_at,
                        rt.expires_at,
                        rt.consumed_at,
                        rt.replaced_by_id
                    FROM refresh_tokens AS rt
                    INNER JOIN sessions AS s
                        ON s.id = rt.session_id
                    WHERE rt.id = %s
                    FOR UPDATE OF rt, s
                    """,
                    (current_token_id,),
                )

                current_row = cursor.fetchone()

                if current_row is None:
                    raise LookupError(
                        "Refresh token was not found."
                    )

                current_token = self._row_to_refresh_token(
                    current_row
                )

                if current_token.consumed_at is not None:
                    raise ValueError(
                        "Refresh token has already been consumed."
                    )

                if current_token.session_id != replacement.session_id:
                    raise ValueError(
                        "Replacement token must belong to the "
                        "same session."
                    )

                cursor.execute(
                    """
                    INSERT INTO refresh_tokens (
                        id,
                        session_id,
                        token_hash,
                        issued_at,
                        expires_at,
                        consumed_at,
                        replaced_by_id
                    )
                    VALUES (
                        %s, %s, %s, %s, %s, %s, %s
                    )
                    RETURNING
                        id,
                        session_id,
                        token_hash,
                        issued_at,
                        expires_at,
                        consumed_at,
                        replaced_by_id
                    """,
                    (
                        replacement.id,
                        replacement.session_id,
                        replacement.token_hash,
                        replacement.issued_at,
                        replacement.expires_at,
                        replacement.consumed_at,
                        None,
                    ),
                )

                replacement_row = cursor.fetchone()

                if replacement_row is None:
                    raise RuntimeError(
                        "Replacement refresh-token INSERT "
                        "returned no row."
                    )

                cursor.execute(
                    """
                    UPDATE refresh_tokens
                    SET
                        consumed_at = %s,
                        replaced_by_id = %s
                    WHERE id = %s
                      AND consumed_at IS NULL
                    RETURNING id
                    """,
                    (
                        consumed_at,
                        replacement.id,
                        current_token.id,
                    ),
                )

                consumed_row = cursor.fetchone()

                if consumed_row is None:
                    raise RuntimeError(
                        "Refresh-token consumption failed."
                    )

                cursor.execute(
                    """
                    UPDATE sessions
                    SET last_used_at = %s
                    WHERE id = %s
                    """,
                    (
                        consumed_at,
                        current_token.session_id,
                    ),
                )

        return self._row_to_refresh_token(
            replacement_row
        )

    @staticmethod
    def _row_to_session(
        row: tuple,
    ) -> SessionRecord:
        return SessionRecord(
            id=row[0],
            user_id=row[1],
            token_family_id=row[2],
            created_at=row[3],
            last_used_at=row[4],
            expires_at=row[5],
            revoked_at=row[6],
            reuse_detected_at=row[7],
        )

    @staticmethod
    def _row_to_refresh_token(
        row: tuple,
    ) -> RefreshTokenRecord:
        return RefreshTokenRecord(
            id=row[0],
            session_id=row[1],
            token_hash=row[2],
            issued_at=row[3],
            expires_at=row[4],
            consumed_at=row[5],
            replaced_by_id=row[6],
        )
