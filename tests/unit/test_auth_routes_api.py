from __future__ import annotations

from dataclasses import dataclass
from uuid import UUID, uuid4

import pytest
from fastapi.testclient import TestClient

from backend.api import auth_routes
from backend.api.app import create_app
from backend.security.email_verification import (
    hash_email_verification_token,
)
from backend.security.rate_limit import hash_rate_limit_key

PASSWORD = "correct horse battery staple"


class FakeAccounts:
    def __init__(self) -> None:
        self.created: list[tuple[str, str, str]] = []
        self.existing: set[str] = set()
        self.verified_hashes: list[str] = []
        self.verify_result = True

    def create_pending_account(
        self, email: str, password_hash: str, token_hash: str
    ) -> UUID | None:
        if email in self.existing:
            return None
        self.existing.add(email)
        self.created.append((email, password_hash, token_hash))
        return uuid4()

    def verify_email_token(self, token_hash: str) -> bool:
        self.verified_hashes.append(token_hash)
        return self.verify_result


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
    accounts: FakeAccounts
    limits: FakeLimits
    sender: FakeSender


@pytest.fixture
def env(monkeypatch: pytest.MonkeyPatch) -> Env:
    monkeypatch.delenv("ELDORADO_ENABLE_DOCS", raising=False)

    app = create_app()
    accounts, limits, sender = FakeAccounts(), FakeLimits(), FakeSender()

    app.dependency_overrides[auth_routes.get_account_store] = lambda: accounts
    app.dependency_overrides[auth_routes.get_rate_limit_store] = lambda: limits
    app.dependency_overrides[auth_routes.get_email_sender] = lambda: sender

    return Env(TestClient(app), accounts, limits, sender)


def _register(env: Env, email: str = "user@example.com", password: str = PASSWORD):
    return env.client.post(
        "/auth/register", json={"email": email, "password": password}
    )


def test_register_new_account_sends_verification_email(env: Env) -> None:
    response = _register(env, "  User@Example.COM ")

    assert response.status_code == 202
    assert len(env.sender.sent) == 1

    email, raw_token = env.sender.sent[0]
    assert email == "user@example.com"
    assert env.accounts.created[0][2] == hash_email_verification_token(
        raw_token
    )


def test_duplicate_registration_is_identical_and_sends_nothing(
    env: Env,
) -> None:
    first = _register(env)
    second = _register(env)

    assert second.status_code == first.status_code == 202
    assert second.json() == first.json()
    assert len(env.accounts.created) == 1
    assert len(env.sender.sent) == 1


def test_register_response_never_contains_the_token(env: Env) -> None:
    response = _register(env)

    assert env.sender.sent[0][1] not in response.text


@pytest.mark.parametrize(
    ("email", "password"),
    [
        ("not-an-email", PASSWORD),
        ("us er@example.com", PASSWORD),
        ("user@example.com", "short"),
    ],
)
def test_register_rejects_invalid_input(
    env: Env, email: str, password: str
) -> None:
    response = _register(env, email, password)

    assert response.status_code == 422
    assert env.accounts.created == []
    assert env.sender.sent == []


def test_validation_errors_do_not_echo_submitted_values(env: Env) -> None:
    too_long = "p" * 1025

    response = _register(env, "user@example.com", too_long)

    assert response.status_code == 422
    assert response.json() == {"detail": "Invalid request"}
    assert "ppppp" not in response.text


def test_unknown_fields_are_rejected(env: Env) -> None:
    response = env.client.post(
        "/auth/register",
        json={
            "email": "user@example.com",
            "password": PASSWORD,
            "is_admin": True,
        },
    )

    assert response.status_code == 422
    assert env.accounts.created == []


def test_ip_limit_blocks_registration(env: Env) -> None:
    env.limits.deny.add("register_ip")

    response = _register(env)

    assert response.status_code == 429
    assert response.headers["Retry-After"] == "3600"
    assert env.accounts.created == []


def test_email_limit_blocks_registration(env: Env) -> None:
    env.limits.deny.add("register_email")

    response = _register(env)

    assert response.status_code == 429
    assert env.accounts.created == []


def test_rate_limit_failure_fails_closed(env: Env) -> None:
    env.limits.fail = True

    response = _register(env)

    assert response.status_code == 503
    assert env.accounts.created == []


def test_rate_limit_key_uses_the_connection_address(env: Env) -> None:
    _register(env)

    bucket, key_hash, _, _ = env.limits.calls[0]
    assert bucket == "register_ip"
    assert key_hash == hash_rate_limit_key("register_ip", "testclient")


def test_sender_failure_does_not_change_the_response(env: Env) -> None:
    env.sender.fail = True

    response = _register(env)

    assert response.status_code == 202
    assert len(env.accounts.created) == 1


def test_verify_valid_token(env: Env) -> None:
    response = env.client.post(
        "/auth/verify-email", json={"token": "some-raw-token"}
    )

    assert response.status_code == 200
    assert response.json() == {"status": "verified"}
    assert env.accounts.verified_hashes == [
        hash_email_verification_token("some-raw-token")
    ]


def test_verify_invalid_token(env: Env) -> None:
    env.accounts.verify_result = False

    response = env.client.post(
        "/auth/verify-email", json={"token": "some-raw-token"}
    )

    assert response.status_code == 400


def test_verify_is_rate_limited(env: Env) -> None:
    env.limits.deny.add("verify_ip")

    response = env.client.post(
        "/auth/verify-email", json={"token": "some-raw-token"}
    )

    assert response.status_code == 429
    assert env.accounts.verified_hashes == []


def test_verify_rejects_empty_token(env: Env) -> None:
    response = env.client.post("/auth/verify-email", json={"token": ""})

    assert response.status_code == 422


def test_api_docs_are_disabled_by_default(env: Env) -> None:
    assert env.client.get("/docs").status_code == 404
    assert env.client.get("/openapi.json").status_code == 404