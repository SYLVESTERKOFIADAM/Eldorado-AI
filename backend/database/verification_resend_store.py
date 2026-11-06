from __future__ import annotations

import psycopg


class PostgresVerificationResendStore:
    """
    PostgreSQL-backed verification token reissue.

    Calls only the SECURITY DEFINER issue_email_verification_token
    function from migration 0011, using parameterized SQL, as the
    restricted application role. Database errors propagate so callers
    fail closed.
    """

    def __init__(self, dsn: str) -> None:
        if not dsn.strip():
            raise ValueError("Database DSN must not be empty.")

        self._dsn = dsn

    def issue_verification_token(
        self,
        email: str,
        token_hash: str,
    ) -> bool:
        with psycopg.connect(self._dsn) as connection:
            row = connection.execute(
                "SELECT public.issue_email_verification_token(%s, %s)",
                (email, token_hash),
            ).fetchone()

        if row is None or not isinstance(row[0], bool):
            raise RuntimeError("Token issue returned no result.")

        return row[0]