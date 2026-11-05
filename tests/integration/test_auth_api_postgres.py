from __future__ import annotations

import uuid
from pathlib import Path
from types import SimpleNamespace

import psycopg
import pytest
from fastapi.testclient import TestClient

from backend.api import auth_routes
from backend.api.app import create_app
from backend.database.account_store import PostgresAccountStore
from backend.database.login_store import PostgresCredentialStore
from backend.database.migration_runner import MigrationRunner
from backend.database.rate_limit_store import PostgresRateLimitStore
from backend.security.login import authenticate_password

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
    name = f"eldorado_authapi_test_{uuid.uuid4().hex[:12]}"

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
def app_dsn(database_name: str) -> str:
    # Run the whole session as the restricted application role.
    return (
        _dsn(database_name, "postgres")
        + " options='-c role=eldorado_app'"
    )


@pytest.fixture
def api(app_dsn: str, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.delenv("ELDORADO_ENABLE_DOCS", raising=False)

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

    return SimpleNamespace(client=TestClient(app), sender=sender)


def _email() -> str:
    return f"user-{uuid.uuid4().hex}@example.com"


def test_register_verify_and_login_through_the_api(
    api, app_dsn: str
) -> None:
    email = _email()
    credentials = PostgresCredentialStore(app_dsn)

    response = api.client.post(
        "/auth/register", json={"email": email, "password": PASSWORD}
    )

    assert response.status_code == 202
    assert len(api.sender.sent) == 1
    assert authenticate_password(credentials, email, PASSWORD) is None

    raw_token = api.sender.sent[0][1]
    verify = api.client.post(
        "/auth/verify-email", json={"token": raw_token}
    )

    assert verify.status_code == 200
    assert authenticate_password(credentials, email, PASSWORD) is not None

    replay = api.client.post(
        "/auth/verify-email", json={"token": raw_token}
    )

    assert replay.status_code == 400


def test_email_limit_applies_with_real_counters(api) -> None:
    email = _email()

    codes = [
        api.client.post(
            "/auth/register", json={"email": email, "password": PASSWORD}
        ).status_code
        for _ in range(4)
    ]

    assert codes == [202, 202, 202, 429]
    assert len(api.sender.sent) == 1


def test_ip_limit_applies_with_real_counters(api) -> None:
    codes = [
        api.client.post(
            "/auth/register",
            json={"email": _email(), "password": PASSWORD},
        ).status_code
        for _ in range(6)
    ]

    assert codes == [202, 202, 202, 202, 202, 429]