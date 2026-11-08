from __future__ import annotations

from uuid import UUID

import psycopg

from backend.database.connection import DatabaseConnection


class PostgresPasswordResetStore:
    """
    PostgreSQL-backed password reset.

    Calls only the SECURITY DEFINER functions from migration 0012, using
    parameterized SQL, as the restricted application role. Database errors
    propagate so callers fail closed.
    """

    def __init__(self, dsn: str) -> None:
        if not dsn.strip():
            raise ValueError("Database DSN must not be empty.")

        self._dsn = dsn

    def issue_reset_token(self, email: str, token_hash: str) -> bool:
        with psycopg.connect(self._dsn) as connection:
            row = connection.execute(
                "SELECT public.issue_password_reset_token(%s, %s)",
                (email, token_hash),
            ).fetchone()

        if row is None or not isinstance(row[0], bool):
            raise RuntimeError("Reset token issue returned no result.")

        return row[0]

    def reset_password(
        self,
        token_hash: str,
        new_password_hash: str,
    ) -> bool:
        with psycopg.connect(self._dsn) as connection:
            row = connection.execute(
                "SELECT public.reset_password(%s, %s)",
                (token_hash, new_password_hash),
            ).fetchone()

        return row is not None and row[0] == "RESET"


class PostgresPasswordChangeStore:
    """
    PostgreSQL-backed password change for an authenticated user.

    Each call runs in a transaction bound to exactly one user through the
    existing authenticated-transaction boundary. Identity is never a SQL
    parameter.
    """

    def __init__(self, dsn: str) -> None:
        if not dsn.strip():
            raise ValueError("Database DSN must not be empty.")

        self._database = DatabaseConnection(dsn)

    def get_password_hash(self, user_id: UUID) -> str | None:
        with self._database.transaction(user_id) as connection:
            row = connection.execute(
                "SELECT public.get_own_password_hash()"
            ).fetchone()

        if row is None or row[0] is None:
            return None

        return str(row[0])

    def replace_password_hash(
        self,
        user_id: UUID,
        expected_hash: str,
        new_hash: str,
    ) -> bool:
        with self._database.transaction(user_id) as connection:
            row = connection.execute(
                "SELECT public.change_own_password(%s, %s)",
                (expected_hash, new_hash),
            ).fetchone()

        return row is not None and row[0] is True