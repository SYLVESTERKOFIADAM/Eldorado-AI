from __future__ import annotations

import uuid
from pathlib import Path
from types import SimpleNamespace

import psycopg
import pytest
from fastapi.testclient import TestClient

from backend.api import auth_routes, login_routes
from backend.api.app import create_app
from backend.database.account_store import PostgresAccountStore
from backend.database.connection import DatabaseConnection
from backend.database.login_store import PostgresCredentialStore
from backend.database.migration_runner import MigrationRunner
from backend.database.rate_limit_store import PostgresRateLimitStore
from backend.repositories.postgres_session_repository import (
    PostgresSessionRepository,
)
from backend.security.jwt import verify_access_token
from backend.security.refresh_token import hash_refresh_token

ADMIN_DSN = "dbname=postgres user=postgres host=localhost port=5432"

MIGRATIONS_DIR = (
    Path(__file__).resolve().parents[2]
    / "backend"
    / "database"
    / "migrations"
)

PASSWORD = "correct horse battery staple"


def _dsn(database_name: str, user: str) -> str:
    return (
        f"dbname={database_name} "
        f"user={user} "
        "host=localhost "
        "port=5432"
    )


class CapturingSender:
    def __init__(self) -> None:
        self.sent: list[tuple[str, str]] = []

    def send_verification(self, email: str, raw_token: str) -> None:
        self.sent.append((email, raw_token))


@pytest.fixture(scope="module")
def database_name():
    name = f"eldorado_loginapi_test_{uuid.uuid4().hex[:12]}"

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
def api(app_dsn: str, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.delenv("ELDORADO_ENABLE_DOCS", raising=False)
    monkeypatch.setenv("ELDORADO_JWT_SECRET", "itest-secret-" + "x" * 32)

    app = create_app()
    sender = CapturingSender()
    client_ip = f"test-{uuid.uuid4().hex}"

    app.dependency_overrides[auth_routes.get_account_store] = (
        lambda: PostgresAccountStore(app_dsn)
    )
    app.dependency_overrides[auth_routes.get_rate_limit_store] = (
        lambda: PostgresRateLimitStore(app_dsn)
    )
    app.dependency_overrides[auth_routes.get_email_sender] = lambda: sender
    app.dependency_overrides[auth_routes.get_client_ip] = lambda: client_ip
    app.dependency_overrides[login_routes.get_credential_store] = (
        lambda: PostgresCredentialStore(app_dsn)
    )
    app.dependency_overrides[
        login_routes.get_session_repository_factory
    ] = lambda: (
        lambda user_id: PostgresSessionRepository(
            DatabaseConnection(app_dsn), user_id
        )
    )

    return SimpleNamespace(client=TestClient(app), sender=sender)


def _email() -> str:
    return f"user-{uuid.uuid4().hex}@example.com"


def _register(api, email: str) -> str:
    response = api.client.post(
        "/auth/register", json={"email": email, "password": PASSWORD}
    )
    assert response.status_code == 202
    return api.sender.sent[-1][1]


def _register_and_verify(api, email: str) -> None:
    raw_token = _register(api, email)
    verify = api.client.post(
        "/auth/verify-email", json={"token": raw_token}
    )
    assert verify.status_code == 200


def _login(api, email: str, password: str = PASSWORD):
    return api.client.post(
        "/auth/login", json={"email": email, "password": password}
    )


def test_login_requires_verification_then_issues_working_tokens(
    api,
    app_dsn: str,
    admin_dsn: str,
) -> None:
    email = _email()
    raw_token = _register(api, email)

    assert _login(api, email).status_code == 401

    api.client.post("/auth/verify-email", json={"token": raw_token})
    response = _login(api, email)
    body = response.json()

    assert response.status_code == 200

    user_id = verify_access_token(body["access_token"]).user.user_id

    with psycopg.connect(admin_dsn) as connection:
        owner = connection.execute(
            "SELECT id FROM public.users WHERE email = %s", (email,)
        ).fetchone()[0]
        session_count = connection.execute(
            "SELECT count(*) FROM public.sessions WHERE user_id = %s",
            (owner,),
        ).fetchone()[0]

    assert user_id == owner
    assert session_count == 1

    # The issued refresh token must authenticate through the real
    # database refresh boundary that /auth/refresh will use.
    database = DatabaseConnection(app_dsn)
    with database.refresh_transaction(
        hash_refresh_token(body["refresh_token"])
    ) as (_, authentication):
        assert authentication.state == "VALID"
        assert authentication.user_id == owner


def test_all_failures_return_the_same_response(api) -> None:
    verified = _email()
    unverified = _email()
    _register_and_verify(api, verified)
    _register(api, unverified)

    wrong_password = _login(api, verified, "not the right password")
    unknown = _login(api, _email())
    pending = _login(api, unverified)

    assert (
        wrong_password.status_code
        == unknown.status_code
        == pending.status_code
        == 401
    )
    assert wrong_password.json() == unknown.json() == pending.json()


def test_account_limit_blocks_even_the_correct_password(api) -> None:
    email = _email()
    _register_and_verify(api, email)

    codes = [
        _login(api, email, "wrong password number").status_code
        for _ in range(10)
    ]

    assert codes == [401] * 10
    assert _login(api, email).status_code == 429


def test_each_login_creates_its_own_session(
    api,
    admin_dsn: str,
) -> None:
    email = _email()
    _register_and_verify(api, email)

    first = _login(api, email).json()
    second = _login(api, email).json()

    assert first["refresh_token"] != second["refresh_token"]

    with psycopg.connect(admin_dsn) as connection:
        families = connection.execute(
            """
            SELECT count(DISTINCT token_family_id)
            FROM public.sessions
            WHERE user_id = (
                SELECT id FROM public.users WHERE email = %s
            )
            """,
            (email,),
        ).fetchone()[0]

    assert families == 2