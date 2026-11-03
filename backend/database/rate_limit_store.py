from __future__ import annotations

import psycopg


class PostgresRateLimitStore:
    """
    PostgreSQL-backed rate limit counters.

    Calls only the SECURITY DEFINER check_rate_limit function using
    parameterized SQL, as the restricted application role. Database
    errors propagate so callers fail closed.
    """

    def __init__(self, dsn: str) -> None:
        if not dsn.strip():
            raise ValueError("Database DSN must not be empty.")

        self._dsn = dsn

    def hit(
        self,
        bucket: str,
        key_hash: str,
        limit: int,
        window_seconds: int,
    ) -> bool:
        with psycopg.connect(self._dsn) as connection:
            row = connection.execute(
                "SELECT public.check_rate_limit(%s, %s, %s, %s)",
                (bucket, key_hash, limit, window_seconds),
            ).fetchone()

        if row is None or not isinstance(row[0], bool):
            raise RuntimeError("Rate limit check returned no result.")

        return row[0]