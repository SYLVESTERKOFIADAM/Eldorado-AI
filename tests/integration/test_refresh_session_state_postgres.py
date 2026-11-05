from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

import psycopg
import pytest
from psycopg import errors

from backend.database.migration_runner import MigrationRunner

ADMIN_DSN = "dbname=postgres user=postgres host=localhost port=5432"

MIGRATIONS_DIR = (
    Path(__file__).resolve().parents[2]
    / "backend"
    / "database"
    / "migrations"
)


def _dsn(database_name: str, user: str) -> str:
    return (
        f"dbname={database_name} "
        f"user={user} "
        "host=localhost "
        "port=5432"
    )


@pytest.fixture(scope="module")
def database_name():
    name = f"eldorado_sessionstate_test_{uuid.uuid4().hex[:12]}"

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


def _user(admin_dsn: str, active: bool = True) -> uuid.UUID:
    with psycopg.connect(admin_dsn) as connection:
        return connection.execute(
            "INSERT INTO public.users (is_active) VALUES (%s) RETURNING id",
            (active,),
        ).fetchone()[0]


def _session(admin_dsn: str, user_id: uuid.UUID) -> tuple[uuid.UUID, datetime]:
    session_id = uuid.uuid4()
    created_at = datetime.now(timezone.utc)
    expires_at = created_at + timedelta(days=1)

    with psycopg.connect(admin_dsn) as connection:
        connection.execute(
            """
            INSERT INTO public.sessions
                (id, user_id, token_family_id, created_at, expires_at)
            VALUES (%s, %s, %s, %s, %s)
            """,
            (session_id, user_id, uuid.uuid4(), created_at, expires_at),
        )

    return session_id, expires_at


def _state(
    app_dsn: str,
    session_id: uuid.UUID,
    identity: uuid.UUID | None,
) -> list[tuple]:
    with psycopg.connect(app_dsn) as connection:
        if identity is not None:
            connection.execute(
                "SELECT set_config('app.current_user_id', %s, true)",
                (str(identity),),
            )

        return connection.execute(
            """
            SELECT out_expires_at, out_is_active
            FROM public.get_refresh_session_state(%s)
            """,
            (session_id,),
        ).fetchall()


def test_owner_sees_their_session_state(
    admin_dsn: str, app_dsn: str
) -> None:
    user_id = _user(admin_dsn)
    session_id, expires_at = _session(admin_dsn, user_id)

    rows = _state(app_dsn, session_id, user_id)

    assert len(rows) == 1
    assert rows[0][0] == expires_at
    assert rows[0][1] is True


def test_inactive_user_is_reported_inactive(
    admin_dsn: str, app_dsn: str
) -> None:
    user_id = _user(admin_dsn, active=False)
    session_id, _ = _session(admin_dsn, user_id)

    rows = _state(app_dsn, session_id, user_id)

    assert [row[1] for row in rows] == [False]


def test_other_users_session_returns_nothing(
    admin_dsn: str, app_dsn: str
) -> None:
    owner = _user(admin_dsn)
    other = _user(admin_dsn)
    session_id, _ = _session(admin_dsn, owner)

    assert _state(app_dsn, session_id, other) == []


def test_missing_identity_returns_nothing(
    admin_dsn: str, app_dsn: str
) -> None:
    user_id = _user(admin_dsn)
    session_id, _ = _session(admin_dsn, user_id)

    try:
        rows = _state(app_dsn, session_id, None)
    except psycopg.Error:
        rows = []

    assert rows == []


def test_application_role_still_cannot_read_users_directly(
    app_dsn: str,
) -> None:
    with pytest.raises(errors.InsufficientPrivilege):
        with psycopg.connect(app_dsn) as connection:
            connection.execute("SELECT is_active FROM public.users")