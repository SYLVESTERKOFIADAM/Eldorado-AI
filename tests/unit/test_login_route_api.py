from __future__ import annotations

from dataclasses import dataclass
from uuid import UUID, uuid4

import pytest
from fastapi.testclient import TestClient

from backend.api import auth_routes, login_routes
from backend.api.app import create_app
from backend.models.session import RefreshTokenRecord, SessionRecord
from backend.security.jwt import verify_access_token
from backend.security.login import LoginCredential
from backend.security.passwords import hash_password
from backend.security.rate_limit import hash_rate_limit_key
from backend.security.refresh_token import hash_refresh_token

PASSWORD = "correct horse battery staple"
USER_ID = uuid4()
PASSWORD_HASH = hash_password(PASSWORD)


class FakeCredentials:
    def __init__(self) -> None:
        self.credential: LoginCredential | None = LoginCredential(
            user_id=USER_ID, password_hash=PASSWORD_HASH
        )
        self.fail = False
        self.emails: list[str] = []

    def get_login_credential(self, email: str) -> LoginCredential | None:
        if self.fail:
            raise RuntimeError("database down")
        self.emails.append(email)
        return self.credential


class FakeLimits:
    def __init__(self) -> None:
        self.deny: set[str] = set()
        self.fail = False
        self.calls: list[tuple[str, str, int, int]] = []

    def hit(
        self, bucket: str, key_hash: str, limit: int, window_seconds: int
    ) -> bool:
        if self.fail:
            raise RuntimeError("database down")
        self.calls.append((bucket, key_hash, limit, window_seconds))
        return bucket not in self.deny


class FakeSessionRepository:
    def __init__(self) -> None:
        self.sessions: list[SessionRecord] = []
        self.tokens: list[RefreshTokenRecord] = []
        self.fail = False

    def create_session(self, session: SessionRecord) -> SessionRecord:
        if self.fail:
            raise RuntimeError("database down")
        self.sessions.append(session)
        return session

    def create_refresh_token(
        self, token: RefreshTokenRecord
    ) -> RefreshTokenRecord:
        self.tokens.append(token)
        return token

    def revoke_session(self, session_id, revoked_at):
        pass


@dataclass
class Env:
    client: TestClient
    credentials: FakeCredentials
    limits: FakeLimits
    repository: FakeSessionRepository


@pytest.fixture
def env(monkeypatch: pytest.MonkeyPatch) -> Env:
    monkeypatch.delenv("ELDORADO_ENABLE_DOCS", raising=False)
    monkeypatch.setenv("ELDORADO_JWT_SECRET", "unit-test-secret-" + "x" * 32)

    app = create_app()
    credentials = FakeCredentials()
    limits = FakeLimits()
    repository = FakeSessionRepository()

    app.dependency_overrides[login_routes.get_credential_store] = (
        lambda: credentials
    )
    app.dependency_overrides[auth_routes.get_rate_limit_store] = (
        lambda: limits
    )
    app.dependency_overrides[
        login_routes.get_session_repository_factory
    ] = lambda: (lambda user_id: repository)

    return Env(TestClient(app), credentials, limits, repository)


def _login(env: Env, email: str = "user@example.com", password: str = PASSWORD):
    return env.client.post(
        "/auth/login", json={"email": email, "password": password}
    )


def test_successful_login_returns_tokens(env: Env) -> None:
    response = _login(env, "  User@Example.COM ")
    body = response.json()

    assert response.status_code == 200
    assert body["token_type"] == "bearer"
    assert body["expires_in"] == 900
    assert verify_access_token(body["access_token"]).user.user_id == USER_ID
    assert env.credentials.emails == ["user@example.com"]


def test_login_stores_only_the_refresh_token_hash(env: Env) -> None:
    body = _login(env).json()

    assert len(env.repository.sessions) == 1
    assert env.repository.tokens[0].token_hash == hash_refresh_token(
        body["refresh_token"]
    )
    assert env.repository.tokens[0].token_hash != body["refresh_token"]


def test_token_response_is_not_cacheable(env: Env) -> None:
    response = _login(env)

    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers["Pragma"] == "no-cache"


def test_wrong_password_and_unknown_account_are_indistinguishable(
    env: Env,
) -> None:
    wrong_password = _login(env, password="not the right password")

    env.credentials.credential = None
    unknown_or_unverified = _login(env)

    assert wrong_password.status_code == 401
    assert unknown_or_unverified.status_code == 401
    assert wrong_password.json() == unknown_or_unverified.json()
    assert env.repository.sessions == []


def test_failure_response_does_not_echo_the_password(env: Env) -> None:
    response = _login(env, password="very-secret-wrong-password")

    assert "very-secret-wrong-password" not in response.text


def test_malformed_email_gets_the_generic_failure_without_lookup(
    env: Env,
) -> None:
    response = _login(env, email="not-an-email")

    assert response.status_code == 401
    assert response.json() == {"detail": "Invalid email or password"}
    assert env.credentials.emails == []
    assert [call[0] for call in env.limits.calls] == ["login_ip"]


def test_ip_limit_blocks_before_anything_else(env: Env) -> None:
    env.limits.deny.add("login_ip")

    response = _login(env)

    assert response.status_code == 429
    assert [call[0] for call in env.limits.calls] == ["login_ip"]
    assert env.credentials.emails == []


def test_account_limit_blocks_before_password_check(env: Env) -> None:
    env.limits.deny.add("login_account")

    response = _login(env)

    assert response.status_code == 429
    assert response.headers["Retry-After"] == "900"
    assert env.credentials.emails == []
    assert env.repository.sessions == []


def test_failed_attempts_count_toward_the_account_limit(env: Env) -> None:
    _login(env, password="wrong password here")

    buckets = [call[0] for call in env.limits.calls]
    assert buckets == ["login_ip", "login_account"]
    assert env.limits.calls[1][1] == hash_rate_limit_key(
        "login_account", "user@example.com"
    )


def test_rate_limit_failure_fails_closed(env: Env) -> None:
    env.limits.fail = True

    response = _login(env)

    assert response.status_code == 503
    assert env.credentials.emails == []
    assert env.repository.sessions == []


def test_credential_store_failure_fails_closed(env: Env) -> None:
    env.credentials.fail = True

    response = _login(env)

    assert response.status_code == 503
    assert "access_token" not in response.text


def test_session_failure_fails_closed_without_tokens(env: Env) -> None:
    env.repository.fail = True

    response = _login(env)

    assert response.status_code == 503
    assert "access_token" not in response.text
    assert "refresh_token" not in response.text


def test_validation_errors_are_generic(env: Env) -> None:
    response = env.client.post(
        "/auth/login",
        json={"email": "user@example.com", "password": "p" * 1025},
    )

    assert response.status_code == 422
    assert response.json() == {"detail": "Invalid request"}
    assert "ppppp" not in response.text


def test_unknown_fields_are_rejected(env: Env) -> None:
    response = env.client.post(
        "/auth/login",
        json={
            "email": "user@example.com",
            "password": PASSWORD,
            "is_admin": True,
        },
    )

    assert response.status_code == 422
    assert env.credentials.emails == []