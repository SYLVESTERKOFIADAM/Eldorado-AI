from __future__ import annotations

from dataclasses import dataclass

import pytest
from fastapi.testclient import TestClient

from backend.api import auth_routes, logout_routes
from backend.api.app import create_app
from backend.security.refresh_token import hash_refresh_token

PRESENTED = "A" * 43


class FakeLogoutStore:
    def __init__(self) -> None:
        self.result = True
        self.fail = False
        self.calls: list[str] = []

    def revoke(self, presented_token_hash: str, now) -> bool:
        if self.fail:
            raise RuntimeError("database down")
        self.calls.append(presented_token_hash)
        return self.result


class FakeLimits:
    def __init__(self) -> None:
        self.deny: set[str] = set()
        self.fail = False

    def hit(self, bucket, key_hash, limit, window_seconds) -> bool:
        if self.fail:
            raise RuntimeError("database down")
        return bucket not in self.deny


@dataclass
class Env:
    client: TestClient
    store: FakeLogoutStore
    limits: FakeLimits


@pytest.fixture
def env(monkeypatch: pytest.MonkeyPatch) -> Env:
    monkeypatch.delenv("ELDORADO_ENABLE_DOCS", raising=False)

    app = create_app()
    store, limits = FakeLogoutStore(), FakeLimits()

    app.dependency_overrides[logout_routes.get_logout_store] = lambda: store
    app.dependency_overrides[auth_routes.get_rate_limit_store] = lambda: limits

    return Env(TestClient(app), store, limits)


def _logout(env: Env, token: str = PRESENTED):
    return env.client.post("/auth/logout", json={"refresh_token": token})


def test_logout_returns_204_with_no_body(env: Env) -> None:
    response = _logout(env)

    assert response.status_code == 204
    assert response.content == b""
    assert response.headers["Cache-Control"] == "no-store"
    assert env.store.calls == [hash_refresh_token(PRESENTED)]


def test_revoked_and_unrevoked_responses_are_identical(env: Env) -> None:
    revoked = _logout(env)

    env.store.result = False
    nothing = _logout(env)

    assert revoked.status_code == nothing.status_code == 204
    assert revoked.content == nothing.content == b""
    assert (
        revoked.headers["Cache-Control"]
        == nothing.headers["Cache-Control"]
    )


def test_malformed_token_gets_204_without_store_call(env: Env) -> None:
    response = _logout(env, "tökén")

    assert response.status_code == 204
    assert env.store.calls == []


def test_ip_limit_blocks_before_the_store(env: Env) -> None:
    env.limits.deny.add("logout_ip")

    response = _logout(env)

    assert response.status_code == 429
    assert response.headers["Retry-After"] == "900"
    assert env.store.calls == []


def test_rate_limit_failure_fails_closed(env: Env) -> None:
    env.limits.fail = True

    response = _logout(env)

    assert response.status_code == 503
    assert env.store.calls == []


def test_store_failure_reports_503_so_clients_can_retry(env: Env) -> None:
    env.store.fail = True

    assert _logout(env).status_code == 503


@pytest.mark.parametrize("token", ["", "x" * 257])
def test_validation_errors_are_generic(env: Env, token: str) -> None:
    response = _logout(env, token)

    assert response.status_code == 422
    assert response.json() == {"detail": "Invalid request"}
    assert env.store.calls == []


def test_unknown_fields_are_rejected(env: Env) -> None:
    response = env.client.post(
        "/auth/logout",
        json={"refresh_token": PRESENTED, "all_sessions": True},
    )

    assert response.status_code == 422
    assert env.store.calls == []