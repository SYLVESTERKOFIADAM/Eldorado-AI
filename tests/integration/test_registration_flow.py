from __future__ import annotations

import uuid
from pathlib import Path

import psycopg
import pytest

from backend.database.account_store import PostgresAccountStore
from backend.database.login_store import PostgresCredentialStore
from backend.database.migration_runner import MigrationRunner
from backend.security.login import authenticate_password
from backend.security.registration import register_account, verify_email

ADMIN_DSN = "dbname=postgres user=postgres host=localhost port=5432"

MIGRATIONS_DIR = (
    Path(__file__).resolve().parents[2]
    / "backend"
    / "database"
    / "migrations"
)

PASSWORD = "correct horse battery staple"
OTHER_PASSWORD = "a completely different passphrase"


def _dsn(database_name: str, user: str) -> str:
    return (
        f"dbname={database_name} "
        f"user={user} "
        "host=localhost "
        "port=5432"
    )


@pytest.fixture(scope="module")
def database_name():
    name = f"eldorado_register_test_{uuid.uuid4().hex[:12]}"

    with psycopg.connect(ADMIN_DSN, autocommit=True) as connection:
        connection.execute(f'CREATE DATABASE "{name}"')

    try:
        MigrationRunner(_dsn(name, "postgres"), MIGRATIONS_DIR).migrate()
        yield name
    finally:
        with psycopg.connect(ADMIN_DSN, autocommit=True) as connection:
            connection.execute(
                """
                SELECT pg_terminate_backend(pid)
                FROM pg_stat_activity
                WHERE datname = %s
                  AND pid <> pg_backend_pid()
                """,
                (name,),
            )
            connection.execute(f'DROP DATABASE IF EXISTS "{name}"')


@pytest.fixture(scope="module")
def admin_dsn(database_name: str) -> str:
    return _dsn(database_name, "postgres")


@pytest.fixture(scope="module")
def app_dsn(database_name: str) -> str:
    # Run the whole session as the restricted application role.
    return (
        _dsn(database_name, "postgres")
        + " options='-c role=eldorado_app'"
    )


def _new_email() -> str:
    return f"user-{uuid.uuid4().hex}@example.com"


def _rows(admin_dsn: str, email: str) -> list[tuple]:
    with psycopg.connect(admin_dsn) as connection:
        return connection.execute(
            """
            SELECT email_verified_at, password_hash
            FROM public.users
            WHERE email = %s
            """,
            (email,),
        ).fetchall()


def test_register_verify_and_login(admin_dsn: str, app_dsn: str) -> None:
    accounts = PostgresAccountStore(app_dsn)
    credentials = PostgresCredentialStore(app_dsn)
    email = _new_email()

    result = register_account(accounts, email, PASSWORD)

    assert result.verification_token is not None

    rows = _rows(admin_dsn, email)
    assert len(rows) == 1
    assert rows[0][0] is None
    assert rows[0][1].startswith("$argon2id$")
    assert PASSWORD not in rows[0][1]

    assert authenticate_password(credentials, email, PASSWORD) is None

    assert verify_email(accounts, result.verification_token) is True
    assert authenticate_password(credentials, email, PASSWORD) is not None

    assert verify_email(accounts, result.verification_token) is False


def test_duplicate_registration_is_indistinguishable_and_harmless(
    admin_dsn: str,
    app_dsn: str,
) -> None:
    accounts = PostgresAccountStore(app_dsn)
    credentials = PostgresCredentialStore(app_dsn)
    email = _new_email()

    first = register_account(accounts, email, PASSWORD)
    second = register_account(accounts, email.upper(), OTHER_PASSWORD)

    assert first.verification_token is not None
    assert second.verification_token is None
    assert len(_rows(admin_dsn, email)) == 1

    # The original owner's token and password still work; the
    # duplicate attempt's password never became valid.
    assert verify_email(accounts, first.verification_token) is True
    assert authenticate_password(credentials, email, PASSWORD) is not None
    assert authenticate_password(credentials, email, OTHER_PASSWORD) is None


def test_unknown_verification_token_is_rejected(app_dsn: str) -> None:
    accounts = PostgresAccountStore(app_dsn)

    assert verify_email(accounts, "not-a-real-token") is False