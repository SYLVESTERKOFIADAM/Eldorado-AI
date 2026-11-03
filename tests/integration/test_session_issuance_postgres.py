from __future__ import annotations

import uuid
from pathlib import Path

import psycopg
import pytest

from backend.database.connection import DatabaseConnection
from backend.database.migration_runner import MigrationRunner
from backend.repositories.postgres_session_repository import (
    PostgresSessionRepository,
)
from backend.security.jwt import verify_access_token
from backend.security.refresh_token import hash_refresh_token
from backend.security.session_issuance import issue_session

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


@pytest.fixture(autouse=True)
def jwt_secret(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ELDORADO_JWT_SECRET", "itest-secret-" + "x" * 32)


@pytest.fixture(scope="module")
def database_name():
    name = f"eldorado_issuance_test_{uuid.uuid4().hex[:12]}"

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


@pytest.fixture
def user_id(admin_dsn: str) -> uuid.UUID:
    with psycopg.connect(admin_dsn) as connection:
        return connection.execute(
            "INSERT INTO public.users DEFAULT VALUES RETURNING id"
        ).fetchone()[0]


def test_issued_refresh_token_is_stored_hashed_only(
    admin_dsn: str,
    app_dsn: str,
    user_id: uuid.UUID,
) -> None:
    database = DatabaseConnection(app_dsn)
    repository = PostgresSessionRepository(database, user_id)

    issued = issue_session(repository, user_id)

    with psycopg.connect(admin_dsn) as connection:
        stored = connection.execute(
            "SELECT token_hash FROM public.refresh_tokens WHERE session_id = %s",
            (issued.session_id,),
        ).fetchall()
        everything = str(
            connection.execute(
                "SELECT * FROM public.refresh_tokens"
            ).fetchall()
        )

    assert stored == [(hash_refresh_token(issued.refresh_token),)]
    assert issued.refresh_token not in everything


def test_issued_refresh_token_authenticates_through_the_database(
    app_dsn: str,
    user_id: uuid.UUID,
) -> None:
    database = DatabaseConnection(app_dsn)
    repository = PostgresSessionRepository(database, user_id)

    issued = issue_session(repository, user_id)

    with database.refresh_transaction(
        hash_refresh_token(issued.refresh_token)
    ) as (_, authentication):
        assert authentication.state == "VALID"
        assert authentication.user_id == user_id
        assert authentication.session_id == issued.session_id

    assert verify_access_token(issued.access_token).user.user_id == user_id


def test_unissued_refresh_token_is_rejected(
    app_dsn: str,
    user_id: uuid.UUID,
) -> None:
    database = DatabaseConnection(app_dsn)

    with pytest.raises(PermissionError):
        with database.refresh_transaction(
            hash_refresh_token("never-issued-token")
        ):
            pass