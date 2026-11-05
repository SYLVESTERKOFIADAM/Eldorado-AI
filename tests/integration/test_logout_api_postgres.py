from __future__ import annotations

import uuid
from pathlib import Path
from types import SimpleNamespace

import psycopg
import pytest
from fastapi.testclient import TestClient

from backend.api import (
    auth_routes,
    login_routes,
    logout_routes,
    refresh_routes,
)
from backend.api.app import create_app
from backend.database.account_store import PostgresAccountStore
from backend.database.connection import DatabaseConnection
from backend.database.login_store import PostgresCredentialStore
from backend.database.logout_store import PostgresLogoutStore
from backend.database.migration_runner import MigrationRunner
from backend.database.rate_limit_store import PostgresRateLimitStore
from backend.database.refresh_store import PostgresRefreshStore
from backend.repositories.postgres_session_repository import (
    PostgresSessionRepository,
)
from backend.security.jwt import verify_access_token

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
    name = f"eldorado_logoutapi_test_{uuid.uuid4().hex[:12]}"

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
    app.dependency_overrides[refresh_routes.get_refresh_store] = (
        lambda: PostgresRefreshStore(app_dsn)
    )
    app.dependency_overrides[logout_routes.get_logout_store] = (
        lambda: PostgresLogoutStore(app_dsn)
    )

    return SimpleNamespace(client=TestClient(app), sender=sender)


def _signup(api) -> str:
    email = f"user-{uuid.uuid4().hex}@example.com"

    register = api.client.post(
        "/auth/register", json={"email": email, "password": PASSWORD}
    )
    assert register.status_code == 202

    verify = api.client.post(
        "/auth/verify-email", json={"token": api.sender.sent[-1][1]}
    )
    assert verify.status_code == 200

    return email


def _login_as(api, email: str) -> dict:
    response = api.client.post(
        "/auth/login", json={"email": email, "password": PASSWORD}
    )
    assert response.status_code == 200

    return response.json()


def _refresh(api, token: str):
    return api.client.post("/auth/refresh", json={"refresh_token": token})


def _logout(api, token: str):
    return api.client.post("/auth/logout", json={"refresh_token": token})


def _session_state(admin_dsn: str, email: str) -> list[tuple]:
    with psycopg.connect(admin_dsn) as connection:
        return connection.execute(
            """
            SELECT revoked_at, reuse_detected_at
            FROM public.sessions
            WHERE user_id = (
                SELECT id FROM public.users WHERE email = %s
            )
            ORDER BY created_at
            """,
            (email,),
        ).fetchall()


def test_logout_revokes_the_session_and_blocks_refresh(
    api,
    admin_dsn: str,
) -> None:
    email = _signup(api)
    tokens = _login_as(api, email)

    response = _logout(api, tokens["refresh_token"])

    assert response.status_code == 204
    assert response.content == b""
    assert _refresh(api, tokens["refresh_token"]).status_code == 401

    revoked_at, reuse_detected_at = _session_state(admin_dsn, email)[0]
    assert revoked_at is not None
    assert reuse_detected_at is None

    # Known limit: the access token is a stateless JWT, so it stays
    # valid until it expires (15 minutes). Logout stops new refreshes.
    assert verify_access_token(tokens["access_token"]).user.user_id


def test_logout_is_idempotent_and_never_reveals_token_validity(api) -> None:
    email = _signup(api)
    tokens = _login_as(api, email)

    first = _logout(api, tokens["refresh_token"])
    again = _logout(api, tokens["refresh_token"])
    garbage = _logout(api, "never-issued-token")

    assert first.status_code == again.status_code == garbage.status_code == 204
    assert first.content == again.content == garbage.content == b""


def test_logout_only_affects_its_own_session(api, admin_dsn: str) -> None:
    email = _signup(api)
    phone = _login_as(api, email)
    laptop = _login_as(api, email)

    assert _logout(api, phone["refresh_token"]).status_code == 204

    assert _refresh(api, phone["refresh_token"]).status_code == 401
    assert _refresh(api, laptop["refresh_token"]).status_code == 200

    states = _session_state(admin_dsn, email)
    assert states[0][0] is not None
    assert states[1][0] is None


def test_logout_with_a_replayed_token_revokes_the_whole_family(
    api,
    admin_dsn: str,
) -> None:
    email = _signup(api)
    tokens = _login_as(api, email)

    rotated = _refresh(api, tokens["refresh_token"])
    assert rotated.status_code == 200
    successor = rotated.json()["refresh_token"]

    assert _logout(api, tokens["refresh_token"]).status_code == 204
    assert _refresh(api, successor).status_code == 401

    revoked_at, reuse_detected_at = _session_state(admin_dsn, email)[0]
    assert revoked_at is not None
    assert reuse_detected_at is not None