from __future__ import annotations

from uuid import UUID

import psycopg
from psycopg import errors


class PostgresAccountStore:
    """
    PostgreSQL-backed account creation and email verification.

    Calls only the SECURITY DEFINER functions from migration 0007, using
    parameterized SQL. Intended to connect as the restricted application
    role. A duplicate email surfaces as a unique violation, which is the
    race-safe signal that the address is already registered.
    """

    def __init__(self, dsn: str) -> None:
        if not dsn.strip():
            raise ValueError("Database DSN must not be empty.")

        self._dsn = dsn

    def create_pending_account(
        self,
        email: str,
        password_hash: str,
        token_hash: str,
    ) -> UUID | None:
        try:
            with psycopg.connect(self._dsn) as connection:
                row = connection.execute(
                    "SELECT public.create_pending_email_account(%s, %s, %s)",
                    (email, password_hash, token_hash),
                ).fetchone()
        except errors.UniqueViolation:
            return None

        if row is None or row[0] is None:
            raise RuntimeError("Account creation returned no identity.")

        user_id = row[0]

        return user_id if isinstance(user_id, UUID) else UUID(str(user_id))

    def verify_email_token(self, token_hash: str) -> bool:
        with psycopg.connect(self._dsn) as connection:
            row = connection.execute(
                "SELECT public.verify_email_token(%s)",
                (token_hash,),
            ).fetchone()

        return row is not None and row[0] == "VERIFIED"