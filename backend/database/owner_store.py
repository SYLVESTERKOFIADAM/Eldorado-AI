from __future__ import annotations

from uuid import UUID

import psycopg
from psycopg import errors


class PostgresAccountCounter:
    """
    Counts login-capable accounts using a database-owner connection.

    Only accounts with an email can authenticate, so credential-less rows
    such as the RLS test fixtures do not count: they cannot log in and
    cannot become a second owner.

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
                "SELECT count(*) FROM public.users WHERE email IS NOT NULL"
            ).fetchone()

        if row is None:
            raise RuntimeError("Account count returned no result.")

        return int(row[0])


class PostgresOwnerStore:
    """
    Creates the single owner through bootstrap_owner_account (migration 0013).

    The function is not executable by the restricted application role, so
    this must connect as the database owner. It runs under an advisory
    lock and refuses when any email account exists, which this reports as
    None.
    """

    def __init__(self, dsn: str) -> None:
        if not dsn.strip():
            raise ValueError("Database DSN must not be empty.")

        self._dsn = dsn

    def create_owner_account(
        self,
        email: str,
        password_hash: str,
    ) -> UUID | None:
        try:
            with psycopg.connect(self._dsn) as connection:
                row = connection.execute(
                    "SELECT public.bootstrap_owner_account("
                    "%s::text, %s::text)",
                    (email, password_hash),
                ).fetchone()
        except errors.ObjectNotInPrerequisiteState:
            return None

        if row is None or row[0] is None:
            raise RuntimeError("Owner creation returned no identity.")

        owner_id = row[0]

        return owner_id if isinstance(owner_id, UUID) else UUID(str(owner_id))