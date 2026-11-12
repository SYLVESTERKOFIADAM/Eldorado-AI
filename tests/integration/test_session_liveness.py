from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

import psycopg
import pytest

from backend.database.migration_runner import MigrationRunner

ADMIN_DSN = "dbname=postgres user=postgres host=localhost port=5432"


def _find_migrations_dir() -> Path:
    for parent in Path(__file__).resolve().parents:
        candidate = parent / "backend" / "database" / "migrations"
        if candidate.is_dir():
            return candidate
    raise RuntimeError("Could not locate backend/database/migrations")


MIGRATIONS_DIR = _find_migrations_dir()


def _dsn(database_name: str) -> str:
    return f"dbname={database_name} user=postgres host=localhost port=5432"


@pytest.fixture
def database_name():
    name = f"eldorado_session_test_{uuid.uuid4().hex}"
    with psycopg.connect(ADMIN_DSN, autocommit=True) as connection:
        connection.execute(f'CREATE DATABASE "{name}"')
    try:
        MigrationRunner(_dsn(name), MIGRATIONS_DIR).migrate()
        yield name
    finally:
        with psycopg.connect(ADMIN_DSN, autocommit=True) as connection:
            connection.execute(f'DROP DATABASE IF EXISTS "{name}" WITH (FORCE)')


@pytest.fixture
def admin_dsn(database_name: str) -> str:
    return _dsn(database_name)


@pytest.fixture
def app_dsn(database_name: str) -> str:
    return _dsn(database_name) + " options='-c role=eldorado_app'"


def _user(admin_dsn: str, *, active: bool = True) -> uuid.UUID:
    with psycopg.connect(admin_dsn) as connection:
        return connection.execute(
            "INSERT INTO public.users (is_active) VALUES (%s) RETURNING id",
            (active,),
        ).fetchone()[0]


def _session(
    admin_dsn: str,
    user_id: uuid.UUID,
    *,
    created_ago: timedelta = timedelta(minutes=1),
    lifetime: timedelta = timedelta(days=30),
    revoked: bool = False,
) -> uuid.UUID:
    now = datetime.now(timezone.utc)
    created_at = now - created_ago
    with psycopg.connect(admin_dsn) as connection:
        return connection.execute(
            "INSERT INTO public.sessions "
            "(user_id, token_family_id, created_at, expires_at, revoked_at) "
            "VALUES (%s, %s, %s, %s, %s) RETURNING id",
            (
                user_id,
                uuid.uuid4(),
                created_at,
                created_at + lifetime,
                now if revoked else None,
            ),
        ).fetchone()[0]


def _is_active(
    app_dsn: str,
    session_id: uuid.UUID | None,
    user_id: uuid.UUID | None,
) -> bool:
    with psycopg.connect(app_dsn) as connection:
        return connection.execute(
            "SELECT public.is_session_active(%s::uuid, %s::uuid)",
            (session_id, user_id),
        ).fetchone()[0]


def test_live_session_is_active(admin_dsn: str, app_dsn: str) -> None:
    user_id = _user(admin_dsn)
    session_id = _session(admin_dsn, user_id)

    assert _is_active(app_dsn, session_id, user_id) is True


def test_session_of_another_user_is_not_active(
    admin_dsn: str,
    app_dsn: str,
) -> None:
    owner = _user(admin_dsn)
    other = _user(admin_dsn)
    session_id = _session(admin_dsn, owner)

    assert _is_active(app_dsn, session_id, other) is False


def test_unknown_session_is_not_active(admin_dsn: str, app_dsn: str) -> None:
    user_id = _user(admin_dsn)

    assert _is_active(app_dsn, uuid.uuid4(), user_id) is False


def test_revoked_session_is_not_active(admin_dsn: str, app_dsn: str) -> None:
    user_id = _user(admin_dsn)
    session_id = _session(admin_dsn, user_id, revoked=True)

    assert _is_active(app_dsn, session_id, user_id) is False


def test_expired_session_is_not_active(admin_dsn: str, app_dsn: str) -> None:
    user_id = _user(admin_dsn)
    session_id = _session(
        admin_dsn,
        user_id,
        created_ago=timedelta(days=2),
        lifetime=timedelta(days=1),
    )

    assert _is_active(app_dsn, session_id, user_id) is False


def test_session_of_an_inactive_user_is_not_active(
    admin_dsn: str,
    app_dsn: str,
) -> None:
    user_id = _user(admin_dsn, active=False)
    session_id = _session(admin_dsn, user_id)

    assert _is_active(app_dsn, session_id, user_id) is False


def test_revocation_takes_effect_immediately(
    admin_dsn: str,
    app_dsn: str,
) -> None:
    user_id = _user(admin_dsn)
    session_id = _session(admin_dsn, user_id)
    assert _is_active(app_dsn, session_id, user_id) is True

    with psycopg.connect(admin_dsn) as connection:
        connection.execute(
            "UPDATE public.sessions SET revoked_at = clock_timestamp() "
            "WHERE id = %s",
            (session_id,),
        )

    assert _is_active(app_dsn, session_id, user_id) is False


@pytest.mark.parametrize(
    ("use_session", "use_user"),
    [(False, True), (True, False), (False, False)],
)
def test_null_arguments_are_not_active(
    admin_dsn: str,
    app_dsn: str,
    use_session: bool,
    use_user: bool,
) -> None:
    user_id = _user(admin_dsn)
    session_id = _session(admin_dsn, user_id)

    assert (
        _is_active(
            app_dsn,
            session_id if use_session else None,
            user_id if use_user else None,
        )
        is False
    )


def test_function_is_hardened(admin_dsn: str) -> None:
    with psycopg.connect(admin_dsn) as connection:
        row = connection.execute(
            "SELECT p.prosecdef, pg_get_userbyid(p.proowner), p.proconfig "
            "FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace "
            "WHERE n.nspname = 'public' AND p.proname = 'is_session_active'"
        ).fetchone()

    assert row is not None
    security_definer, owner, config = row
    assert security_definer is True
    assert owner == "postgres"
    settings = [c for c in (config or []) if c.startswith("search_path=")]
    assert settings, "search_path must be pinned"
    assert "public" not in settings[0]


def test_execution_is_not_granted_to_public(admin_dsn: str) -> None:
    with psycopg.connect(admin_dsn) as connection:
        acl = connection.execute(
            "SELECT p.proacl::text "
            "FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace "
            "WHERE n.nspname = 'public' AND p.proname = 'is_session_active'"
        ).fetchone()[0]

    assert acl is not None
    assert "{=" not in acl and ",=" not in acl
    assert "eldorado_app=X" in acl