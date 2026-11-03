from __future__ import annotations

import uuid
from datetime import datetime, timezone
from pathlib import Path

import psycopg
import pytest

from backend.database.login_store import PostgresCredentialStore
from backend.database.migration_runner import MigrationRunner
from backend.security.email_verification import (
    generate_email_verification_token,
)
from backend.security.login import authenticate_password
from backend.security.passwords import hash_password

ADMIN_DSN = "dbname=postgres user=postgres host=localhost port=5432"

MIGRATIONS_DIR = (
    Path(__file__).resolve().parents[2]
    / "backend"
    / "database"
    / "migrations"
)

PASSWORD = "correct horse battery staple"
PASSWORD_HASH = hash_password(PASSWORD)

LOGIN_FUNCTION = "public.get_login_credential(text)"


def _dsn(database_name: str, user: str) -> str:
    return (
        f"dbname={database_name} "
        f"user={user} "
        "host=localhost "
        "port=5432"
    )


@pytest.fixture(scope="module")
def database_name():
    name = f"eldorado_login_test_{uuid.uuid4().hex[:12]}"

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
    # Connect as the admin user, then run the whole session as the
    # restricted application role. Same privileges and RLS behavior as
    # eldorado_app, without needing a password for a throwaway database.
    return (
        _dsn(database_name, "postgres")
        + " options='-c role=eldorado_app'"
    )


def _new_email() -> str:
    return f"user-{uuid.uuid4().hex}@example.com"


def _insert_user(
    admin_dsn: str,
    *,
    verified: bool,
    active: bool = True,
) -> str:
    email = _new_email()
    verified_at = datetime.now(timezone.utc) if verified else None

    with psycopg.connect(admin_dsn) as connection:
        connection.execute(
            """
            INSERT INTO public.users (
                email,
                password_hash,
                email_verified_at,
                is_active
            )
            VALUES (%s, %s, %s, %s)
            """,
            (email, PASSWORD_HASH, verified_at, active),
        )

    return email


def _lookup(app_dsn: str, email: str) -> list[tuple]:
    with psycopg.connect(app_dsn) as connection:
        return connection.execute(
            """
            SELECT out_user_id, out_password_hash
            FROM public.get_login_credential(%s)
            """,
            (email,),
        ).fetchall()


def test_unverified_account_returns_no_credential(
    admin_dsn: str,
    app_dsn: str,
) -> None:
    email = _insert_user(admin_dsn, verified=False)

    assert _lookup(app_dsn, email) == []


def test_verified_account_returns_credential(
    admin_dsn: str,
    app_dsn: str,
) -> None:
    email = _insert_user(admin_dsn, verified=True)

    rows = _lookup(app_dsn, email)

    assert len(rows) == 1
    assert rows[0][1] == PASSWORD_HASH


def test_inactive_verified_account_returns_no_credential(
    admin_dsn: str,
    app_dsn: str,
) -> None:
    email = _insert_user(admin_dsn, verified=True, active=False)

    assert _lookup(app_dsn, email) == []


def test_unknown_email_returns_no_credential(app_dsn: str) -> None:
    assert _lookup(app_dsn, _new_email()) == []


def test_lookup_normalizes_case_and_whitespace(
    admin_dsn: str,
    app_dsn: str,
) -> None:
    email = _insert_user(admin_dsn, verified=True)

    rows = _lookup(app_dsn, f"  {email.upper()}  ")

    assert len(rows) == 1


def test_only_application_role_may_execute_login_lookup(
    admin_dsn: str,
) -> None:
    with psycopg.connect(admin_dsn) as connection:
        grantees = {
            row[0]
            for row in connection.execute(
                """
                SELECT acl.grantee
                FROM pg_proc AS proc,
                     aclexplode(proc.proacl) AS acl
                WHERE proc.oid = %s::regprocedure
                  AND acl.privilege_type = 'EXECUTE'
                """,
                (LOGIN_FUNCTION,),
            ).fetchall()
        }

        app_role = connection.execute(
            "SELECT 'eldorado_app'::regrole::oid"
        ).fetchone()[0]

        owner = connection.execute(
            "SELECT proowner FROM pg_proc WHERE oid = %s::regprocedure",
            (LOGIN_FUNCTION,),
        ).fetchone()[0]

    assert 0 not in grantees  # 0 is PUBLIC
    assert app_role in grantees
    assert grantees <= {app_role, owner}


@pytest.mark.parametrize(
    "function",
    [
        "public.get_login_credential(text)",
        "public.create_pending_email_account(text, text, text)",
        "public.verify_email_token(text)",
    ],
)
def test_definer_functions_exclude_public_from_search_path(
    admin_dsn: str,
    function: str,
) -> None:
    with psycopg.connect(admin_dsn) as connection:
        settings = connection.execute(
            "SELECT proconfig FROM pg_proc WHERE oid = %s::regprocedure",
            (function,),
        ).fetchone()[0] or []

    search_paths = [
        setting
        for setting in settings
        if setting.startswith("search_path=")
    ]

    assert len(search_paths) == 1
    assert "public" not in search_paths[0]


def test_registration_verification_and_login_flow(app_dsn: str) -> None:
    email = _new_email()
    token = generate_email_verification_token()
    store = PostgresCredentialStore(app_dsn)

    with psycopg.connect(app_dsn) as connection:
        user_id = connection.execute(
            "SELECT public.create_pending_email_account(%s, %s, %s)",
            (email, PASSWORD_HASH, token.token_hash),
        ).fetchone()[0]

    # Pending account cannot log in, even with the correct password.
    assert authenticate_password(store, email, PASSWORD) is None

    with psycopg.connect(app_dsn) as connection:
        outcome = connection.execute(
            "SELECT public.verify_email_token(%s)",
            (token.token_hash,),
        ).fetchone()[0]

    assert outcome == "VERIFIED"

    login = authenticate_password(store, email, PASSWORD)

    assert login is not None
    assert login.user_id == user_id
    assert login.needs_rehash is False
    assert authenticate_password(store, email, "wrong password") is None

    # The token cannot be replayed.
    with psycopg.connect(app_dsn) as connection:
        replay = connection.execute(
            "SELECT public.verify_email_token(%s)",
            (token.token_hash,),
        ).fetchone()[0]

    assert replay == "INVALID"

def test_app_dsn_runs_as_restricted_application_role(app_dsn: str) -> None:
    with psycopg.connect(app_dsn) as connection:
        current_user, is_superuser = connection.execute(
            "SELECT current_user, current_setting('is_superuser')"
        ).fetchone()

        can_bypass_rls = connection.execute(
            "SELECT rolbypassrls FROM pg_roles WHERE rolname = current_user"
        ).fetchone()[0]

    assert current_user == "eldorado_app"
    assert can_bypass_rls is False