from __future__ import annotations

import psycopg


class PostgresAccountCounter:
    """
    Counts accounts using a database-owner connection.

    Row-level security would hide other accounts from the restricted
    application role and make an existing owner look like an empty
    database, so this refuses to run unless the connecting role bypasses
    row-level security.
    """

    def __init__(self, dsn: str) -> None:
        if not dsn.strip():
            raise ValueError("Database DSN must not be empty.")

        self._dsn = dsn

    def count_accounts(self) -> int:
        with psycopg.connect(self._dsn) as connection:
            role = connection.execute(
                "SELECT rolsuper OR rolbypassrls "
                "FROM pg_roles WHERE rolname = current_user"
            ).fetchone()

            if role is None or not role[0]:
                raise RuntimeError(
                    "Owner bootstrap requires the database owner role, "
                    "not the restricted application role."
                )

            row = connection.execute(
                "SELECT count(*) FROM public.users"
            ).fetchone()

        if row is None:
            raise RuntimeError("Account count returned no result.")

        return int(row[0])