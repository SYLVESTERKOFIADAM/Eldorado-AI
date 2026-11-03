from __future__ import annotations

from uuid import UUID

import psycopg

from backend.security.login import LoginCredential


class PostgresCredentialStore:
    """
    PostgreSQL-backed credential lookup for password login.

    Security properties:
    - Calls the SECURITY DEFINER get_login_credential function only.
    - Uses parameterized SQL.
    - The database returns a credential only for verified, active
      accounts, so unverified accounts never reach password checking.
    - Intended to connect as the restricted application role.
    """

    def __init__(self, dsn: str) -> None:
        if not dsn.strip():
            raise ValueError("Database DSN must not be empty.")

        self._dsn = dsn

    def get_login_credential(
        self,
        email: str,
    ) -> LoginCredential | None:
        with psycopg.connect(self._dsn) as connection:
            row = connection.execute(
                """
                SELECT out_user_id, out_password_hash
                FROM public.get_login_credential(%s)
                """,
                (email,),
            ).fetchone()

        if row is None:
            return None

        user_id, password_hash = row

        if not isinstance(user_id, UUID):
            user_id = UUID(str(user_id))

        return LoginCredential(
            user_id=user_id,
            password_hash=str(password_hash),
        )