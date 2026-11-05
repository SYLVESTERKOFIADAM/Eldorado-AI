from __future__ import annotations

import uuid
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from types import SimpleNamespace

import psycopg
import pytest
from fastapi.testclient import TestClient

from backend.api import auth_routes, login_routes, refresh_routes
from backend.api.app import create_app
from backend.database.account_store import PostgresAccountStore
from backend.database.connection import DatabaseConnection
from backend.database.login_store import PostgresCredentialStore
from backend.database.migration_runner import MigrationRunner
from backend.database.rate_limit_store import PostgresRateLimitStore
from backend.database.refresh_store import PostgresRefreshStore
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
    name = f"eldorado_refreshapi_test_{uuid.uuid4().hex[:12]}"

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

    return SimpleNamespace(
        app=app, client=TestClient(app), sender=sender
    )


def _login(api) -> tuple[str, dict]:
    email = f"user-{uuid.uuid4().hex}@example.com"

    register = api.client.post(
        "/auth/register", json={"email": email, "password": PASSWORD}
    )
    assert register.status_code == 202

    verify = api.client.post(
        "/auth/verify-email", json={"token": api.sender.sent[-1][1]}
    )
    assert verify.status_code == 200

    response = api.client.post(
        "/auth/login", json={"email": email, "password": PASSWORD}
    )
    assert response.status_code == 200

    return email, response.json()


def _refresh(client: TestClient, token: str):
    return client.post("/auth/refresh", json={"refresh_token": token})


def test_refresh_rotates_the_token_and_the_chain_continues(
    api,
    admin_dsn: str,
) -> None:
    email, tokens = _login(api)

    first = _refresh(api.client, tokens["refresh_token"])
    first_body = first.json()

    assert first.status_code == 200
    assert first_body["refresh_token"] != tokens["refresh_token"]

    with psycopg.connect(admin_dsn) as connection:
        owner = connection.execute(
            "SELECT id FROM public.users WHERE email = %s", (email,)
        ).fetchone()[0]
        old = connection.execute(
            """
            SELECT consumed_at, replaced_by_id
            FROM public.refresh_tokens
            WHERE token_hash = %s
            """,
            (hash_refresh_token(tokens["refresh_token"]),),
        ).fetchone()
        new_id = connection.execute(
            "SELECT id FROM public.refresh_tokens WHERE token_hash = %s",
            (hash_refresh_token(first_body["refresh_token"]),),
        ).fetchone()[0]

    assert verify_access_token(first_body["access_token"]).user.user_id == owner
    assert old[0] is not None
    assert old[1] == new_id

    second = _refresh(api.client, first_body["refresh_token"])

    assert second.status_code == 200


def test_replaying_a_rotated_token_revokes_the_whole_family(
    api,
    admin_dsn: str,
) -> None:
    email, tokens = _login(api)

    rotated = _refresh(api.client, tokens["refresh_token"])
    assert rotated.status_code == 200
    successor = rotated.json()["refresh_token"]

    replay = _refresh(api.client, tokens["refresh_token"])
    assert replay.status_code == 401

    # The legitimate successor is dead too: the family was revoked.
    assert _refresh(api.client, successor).status_code == 401

    with psycopg.connect(admin_dsn) as connection:
        revoked_at, reuse_detected_at = connection.execute(
            """
            SELECT revoked_at, reuse_detected_at
            FROM public.sessions
            WHERE user_id = (
                SELECT id FROM public.users WHERE email = %s
            )
            """,
            (email,),
        ).fetchone()

    assert revoked_at is not None
    assert reuse_detected_at is not None


def test_garbage_token_looks_identical_to_a_replay(api) -> None:
    _, tokens = _login(api)
    _refresh(api.client, tokens["refresh_token"])

    replay = _refresh(api.client, tokens["refresh_token"])
    garbage = _refresh(api.client, "never-issued-token")

    assert replay.status_code == garbage.status_code == 401
    assert replay.json() == garbage.json()


def test_deactivated_account_cannot_refresh(
    api,
    admin_dsn: str,
) -> None:
    email, tokens = _login(api)

    with psycopg.connect(admin_dsn) as connection:
        connection.execute(
            "UPDATE public.users SET is_active = FALSE WHERE email = %s",
            (email,),
        )

    assert _refresh(api.client, tokens["refresh_token"]).status_code == 401


def test_expired_session_cannot_refresh(
    api,
    admin_dsn: str,
) -> None:
    email, tokens = _login(api)

    with psycopg.connect(admin_dsn) as connection:
        connection.execute(
            """
            UPDATE public.sessions
            SET created_at = now() - interval '2 days',
                expires_at = now() - interval '1 day'
            WHERE user_id = (
                SELECT id FROM public.users WHERE email = %s
            )
            """,
            (email,),
        )

    assert _refresh(api.client, tokens["refresh_token"]).status_code == 401


def test_concurrent_refresh_allows_exactly_one_winner(api) -> None:
    _, tokens = _login(api)
    clients = [TestClient(api.app), TestClient(api.app)]

    with ThreadPoolExecutor(max_workers=2) as pool:
        codes = list(
            pool.map(
                lambda client: _refresh(
                    client, tokens["refresh_token"]
                ).status_code,
                clients,
            )
        )

    assert sorted(codes) == [200, 401]