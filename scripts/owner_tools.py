"""
Local owner tooling. Run through scripts/owner_tools.ps1, which supplies
the database-owner connection string in ELDORADO_MIGRATION_DSN.

Modes:
  bootstrap     create the single verified owner account
  purge-dry     list dev smoke-test accounts that would be deleted
  purge-apply   delete dev smoke-test accounts (dev databases only)
"""

from __future__ import annotations

import getpass
import os
import sys

import psycopg

from backend.database.owner_store import PostgresOwnerStore
from backend.security.dev_safeguards import purge_refusal
from backend.security.owner_bootstrap import (
    OWNER_MIN_PASSWORD_LENGTH,
    OwnerBootstrapError,
    bootstrap_owner,
)

# Matches only the accounts created by scripts/smoke_auth.ps1.
_SMOKE_ACCOUNT_PATTERN = r"^dev-smoke-[0-9]+@example\.com$"


def _dsn() -> str:
    dsn = os.environ.get("ELDORADO_MIGRATION_DSN", "")

    if not dsn.strip():
        raise SystemExit("ELDORADO_MIGRATION_DSN is not set.")

    return dsn


def bootstrap() -> int:
    email = input("Owner email address: ").strip()
    print(f"Using email: {email}")
    password = getpass.getpass(
        f"Owner password (hidden, at least {OWNER_MIN_PASSWORD_LENGTH} characters): "
    )
    repeated = getpass.getpass("Repeat owner password: ")
    print(f"Received {len(password)} and {len(repeated)} characters.")

    if password != repeated:
        print("FAILED: passwords do not match.")
        return 1

    dsn = _dsn()

    try:
        owner = bootstrap_owner(
            PostgresOwnerStore(dsn),
            email,
            password,
        )
    except (OwnerBootstrapError, RuntimeError, psycopg.Error) as exc:
        print(f"FAILED: {exc}")
        return 1

    print(f"Owner account created and verified: {owner}")
    return 0


def purge(apply: bool) -> int:
    try:
        with psycopg.connect(_dsn()) as connection:
            total = connection.execute(
                "SELECT count(*) FROM public.users"
            ).fetchone()[0]
            matching = connection.execute(
                "SELECT email FROM public.users WHERE email ~ %s ORDER BY email",
                (_SMOKE_ACCOUNT_PATTERN,),
            ).fetchall()

            print(
                f"Accounts in database: {total}. "
                f"Dev smoke accounts: {len(matching)}."
            )

            if not apply:
                print("Dry run. Nothing was deleted.")
                return 0

            database = connection.execute(
                "SELECT current_database()"
            ).fetchone()[0]
            typed = input(
                f"Connected to database '{database}'. "
                "Type its name to confirm deletion: "
            ).strip()
            reason = purge_refusal(
                os.environ.get("ELDORADO_ENV"),
                database,
                typed,
            )

            if reason is not None:
                print(f"FAILED, nothing was deleted: {reason}")
                return 1
            if not matching:
                print("Nothing to delete.")
                return 0

            deleted = connection.execute(
                "DELETE FROM public.users WHERE email ~ %s",
                (_SMOKE_ACCOUNT_PATTERN,),
            ).rowcount

            print(f"Deleted {deleted} dev smoke accounts.")
    except psycopg.Error as exc:
        print(f"FAILED, nothing was deleted: {exc}")
        return 1

    return 0


def main() -> int:
    modes = {
        "bootstrap": bootstrap,
        "purge-dry": lambda: purge(False),
        "purge-apply": lambda: purge(True),
    }

    if len(sys.argv) != 2 or sys.argv[1] not in modes:
        print("usage: owner_tools.py [bootstrap|purge-dry|purge-apply]")
        return 2

    return modes[sys.argv[1]]()


if __name__ == "__main__":
    raise SystemExit(main())