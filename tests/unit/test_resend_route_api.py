from __future__ import annotations

from dataclasses import dataclass

import pytest
from fastapi.testclient import TestClient

from backend.api import auth_routes, resend_routes
from backend.api.app import create_app
from backend.security.email_verification import (
    hash_email_verification_token,
)
from backend.security.rate_limit import hash_rate_limit_key


class FakeStore:
    def __init__(self) -> None:
        self.result = True
        self.fail = False
        self.calls: list[tuple[str, str]] = []

    def issue_verification_token(self, email: str, token_hash: str) -> bool:
        if self.fail:
            raise RuntimeError("database down")
        self.calls.append((email, token_hash))
        return self.result


class FakeLimits:
    def __init__(self) -> None:
        self.deny: set[str] = set()
        self.fail = False
        self.calls: list[tuple[str, str]] = []

    def hit(self, bucket, key_hash, limit, window_seconds) -> bool:
        if self.fail:
            raise RuntimeError("database down")
        self.calls.append((bucket, key_hash))
        return bucket not in self.deny


class FakeSender:
    def __init__(self) -> None:
        self.sent: list[tuple[str, str]] = []
        self.fail = False

    def send_verification(self, email: str, raw_token: str) -> None:
        if self.fail:
            raise RuntimeError("mail provider down")
        self.sent.append((email, raw_token))


@dataclass
class Env:
    client: TestClient
    store: FakeStore
    limits: FakeLimits
    sender: FakeSender


@pytest.fixture
def env(monkeypatch: pytest.MonkeyPatch) -> Env:
    monkeypatch.delenv("ELDORADO_ENABLE_DOCS", raising=False)

    app = create_app()
    store, limits, sender = FakeStore(), FakeLimits(), FakeSender()

    app.dependency_overrides[resend_routes.get_resend_store] = lambda: store
    app.dependency_overrides[auth_routes.get_rate_limit_store] = lambda: limits
    app.dependency_overrides[auth_routes.get_email_sender] = lambda: sender

    return Env(TestClient(app), store, limits, sender)


def _resend(env: Env, email: str = "user@example.com"):
    return env.client.post("/auth/resend-verification", json={"email": email})


def test_resend_sends_a_new_token(env: Env) -> None:
    response = _resend(env, "  User@Example.COM ")

    assert response.status_code == 202
    assert len(env.sender.sent) == 1

    email, raw_token = env.sender.sent[0]
    assert email == "user@example.com"
    assert env.store.calls[0][1] == hash_email_verification_token(raw_token)


def test_issued_and_declined_responses_are_identical(env: Env) -> None:
    issued = _resend(env)

    env.store.result = False
    declined = _resend(env)

    assert issued.status_code == declined.status_code == 202
    assert issued.json() == declined.json()
    assert len(env.sender.sent) == 1


def test_response_never_contains_the_token(env: Env) -> None:
    response = _resend(env)

    assert env.sender.sent[0][1] not in response.text


def test_invalid_email_is_rejected(env: Env) -> None:
    response = _resend(env, "not-an-email")

    assert response.status_code == 422
    assert env.store.calls == []


def test_ip_limit_blocks_before_anything_else(env: Env) -> None:
    env.limits.deny.add("resend_ip")

    response = _resend(env)

    assert response.status_code == 429
    assert response.headers["Retry-After"] == "3600"
    assert env.store.calls == []


def test_email_limit_blocks_before_the_store(env: Env) -> None:
    env.limits.deny.add("resend_email")

    response = _resend(env)

    assert response.status_code == 429
    assert env.store.calls == []
    assert env.sender.sent == []


def test_rate_limit_failure_fails_closed(env: Env) -> None:
    env.limits.fail = True

    response = _resend(env)

    assert response.status_code == 503
    assert env.store.calls == []


def test_store_failure_fails_closed(env: Env) -> None:
    env.store.fail = True

    response = _resend(env)

    assert response.status_code == 503
    assert env.sender.sent == []


def test_sender_failure_does_not_change_the_response(env: Env) -> None:
    env.sender.fail = True

    response = _resend(env)

    assert response.status_code == 202
    assert len(env.store.calls) == 1


def test_rate_limit_keys_are_hashed_and_normalized(env: Env) -> None:
    _resend(env, "  User@Example.COM ")

    assert [call[0] for call in env.limits.calls] == [
        "resend_ip",
        "resend_email",
    ]
    assert env.limits.calls[1][1] == hash_rate_limit_key(
        "resend_email", "user@example.com"
    )


def test_unknown_fields_are_rejected(env: Env) -> None:
    response = env.client.post(
        "/auth/resend-verification",
        json={"email": "user@example.com", "is_admin": True},
    )

    assert response.status_code == 422
    assert env.store.calls == []


def test_validation_errors_are_generic(env: Env) -> None:
    response = _resend(env, "a" * 321)

    assert response.status_code == 422
    assert response.json() == {"detail": "Invalid request"}
    assert "aaaaa" not in response.text