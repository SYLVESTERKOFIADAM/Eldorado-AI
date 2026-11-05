from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient

from backend.api import auth_routes, refresh_routes
from backend.api.app import create_app
from backend.security.jwt import verify_access_token
from backend.security.refresh_token import hash_refresh_token
from backend.security.session_refresh import (
    RotationOutcome,
    RotationStatus,
)

USER_ID = uuid4()
SESSION_ID = uuid4()
PRESENTED = "A" * 43
EXPIRES = datetime(2026, 12, 1, tzinfo=timezone.utc)


class FakeRefreshStore:
    def __init__(self) -> None:
        self.status = RotationStatus.ROTATED
        self.fail = False
        self.calls: list[tuple[str, str]] = []

    def rotate(self, presented, replacement, now, mint_access_token):
        if self.fail:
            raise RuntimeError("database down")
        self.calls.append((presented, replacement))
        if self.status is RotationStatus.ROTATED:
            return RotationOutcome(
                RotationStatus.ROTATED,
                user_id=USER_ID,
                session_id=SESSION_ID,
                refresh_expires_at=EXPIRES,
                access_token=mint_access_token(USER_ID),
            )
        return RotationOutcome(self.status)


class FakeLimits:
    def __init__(self) -> None:
        self.deny: set[str] = set()
        self.fail = False
        self.calls: list[str] = []

    def hit(self, bucket, key_hash, limit, window_seconds) -> bool:
        if self.fail:
            raise RuntimeError("database down")
        self.calls.append(bucket)
        return bucket not in self.deny


@dataclass
class Env:
    client: TestClient
    store: FakeRefreshStore
    limits: FakeLimits


@pytest.fixture
def env(monkeypatch: pytest.MonkeyPatch) -> Env:
    monkeypatch.delenv("ELDORADO_ENABLE_DOCS", raising=False)
    monkeypatch.setenv("ELDORADO_JWT_SECRET", "unit-test-secret-" + "x" * 32)

    app = create_app()
    store, limits = FakeRefreshStore(), FakeLimits()

    app.dependency_overrides[refresh_routes.get_refresh_store] = lambda: store
    app.dependency_overrides[auth_routes.get_rate_limit_store] = lambda: limits

    return Env(TestClient(app), store, limits)


def _refresh(env: Env, token: str = PRESENTED):
    return env.client.post("/auth/refresh", json={"refresh_token": token})


def test_successful_refresh_returns_new_tokens(env: Env) -> None:
    response = _refresh(env)
    body = response.json()

    assert response.status_code == 200
    assert body["token_type"] == "bearer"
    assert body["expires_in"] == 900
    assert body["refresh_token"] != PRESENTED
    assert verify_access_token(body["access_token"]).user.user_id == USER_ID

    presented_hash, replacement_hash = env.store.calls[0]
    assert presented_hash == hash_refresh_token(PRESENTED)
    assert replacement_hash == hash_refresh_token(body["refresh_token"])


def test_token_response_is_not_cacheable(env: Env) -> None:
    response = _refresh(env)

    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers["Pragma"] == "no-cache"


def test_replay_and_invalid_are_indistinguishable(env: Env) -> None:
    env.store.status = RotationStatus.REPLAY
    replay = _refresh(env)

    env.store.status = RotationStatus.INVALID
    invalid = _refresh(env)

    assert replay.status_code == invalid.status_code == 401
    assert replay.json() == invalid.json() == {"detail": "Invalid refresh token"}


def test_failure_response_does_not_echo_the_token(env: Env) -> None:
    env.store.status = RotationStatus.INVALID

    response = _refresh(env, "B" * 43)

    assert "B" * 43 not in response.text


def test_malformed_token_gets_401_without_store_call(env: Env) -> None:
    response = _refresh(env, "tökén")

    assert response.status_code == 401
    assert env.store.calls == []


def test_ip_limit_blocks_before_the_store(env: Env) -> None:
    env.limits.deny.add("refresh_ip")

    response = _refresh(env)

    assert response.status_code == 429
    assert response.headers["Retry-After"] == "900"
    assert env.store.calls == []


def test_rate_limit_failure_fails_closed(env: Env) -> None:
    env.limits.fail = True

    response = _refresh(env)

    assert response.status_code == 503
    assert env.store.calls == []


def test_store_failure_fails_closed_without_tokens(env: Env) -> None:
    env.store.fail = True

    response = _refresh(env)

    assert response.status_code == 503
    assert "access_token" not in response.text
    assert "refresh_token" not in response.text


@pytest.mark.parametrize("token", ["", "x" * 257])
def test_validation_errors_are_generic(env: Env, token: str) -> None:
    response = _refresh(env, token)

    assert response.status_code == 422
    assert response.json() == {"detail": "Invalid request"}
    assert env.store.calls == []


def test_unknown_fields_are_rejected(env: Env) -> None:
    response = env.client.post(
        "/auth/refresh",
        json={"refresh_token": PRESENTED, "user_id": str(USER_ID)},
    )

    assert response.status_code == 422
    assert env.store.calls == []