from __future__ import annotations

from dataclasses import dataclass
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient

from backend.api import auth_routes, password_routes
from backend.api.app import create_app
from backend.security.jwt import create_access_token
from backend.security.password_reset import hash_password_reset_token
from backend.security.passwords import hash_password
from backend.security.rate_limit import hash_rate_limit_key

PASSWORD = "correct horse battery staple"
NEW_PASSWORD = "a completely different passphrase"
PASSWORD_HASH = hash_password(PASSWORD)
USER_ID = uuid4()


class FakeResetStore:
    def __init__(self) -> None:
        self.issue_result = True
        self.reset_result = True
        self.fail = False
        self.issued: list[tuple[str, str]] = []
        self.resets: list[tuple[str, str]] = []

    def issue_reset_token(self, email: str, token_hash: str) -> bool:
        if self.fail:
            raise RuntimeError("database down")
        self.issued.append((email, token_hash))
        return self.issue_result

    def reset_password(self, token_hash: str, new_password_hash: str) -> bool:
        if self.fail:
            raise RuntimeError("database down")
        self.resets.append((token_hash, new_password_hash))
        return self.reset_result


class FakeChangeStore:
    def __init__(self) -> None:
        self.stored_hash = PASSWORD_HASH
        self.replace_result = True
        self.fail = False
        self.get_calls = 0
        self.replaced: list[tuple] = []

    def get_password_hash(self, user_id):
        if self.fail:
            raise RuntimeError("database down")
        self.get_calls += 1
        return self.stored_hash

    def replace_password_hash(self, user_id, expected_hash, new_hash) -> bool:
        if self.fail:
            raise RuntimeError("database down")
        self.replaced.append((user_id, expected_hash, new_hash))
        return self.replace_result


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

    def send_password_reset(self, email: str, raw_token: str) -> None:
        if self.fail:
            raise RuntimeError("mail provider down")
        self.sent.append((email, raw_token))


@dataclass
class Env:
    client: TestClient
    reset: FakeResetStore
    change: FakeChangeStore
    limits: FakeLimits
    sender: FakeSender


@pytest.fixture
def env(monkeypatch: pytest.MonkeyPatch) -> Env:
    monkeypatch.delenv("ELDORADO_ENABLE_DOCS", raising=False)
    monkeypatch.setenv("ELDORADO_JWT_SECRET", "unit-test-secret-" + "x" * 32)

    app = create_app()
    reset, change = FakeResetStore(), FakeChangeStore()
    limits, sender = FakeLimits(), FakeSender()

    app.dependency_overrides[password_routes.get_password_reset_store] = (
        lambda: reset
    )
    app.dependency_overrides[password_routes.get_password_change_store] = (
        lambda: change
    )
    app.dependency_overrides[password_routes.get_password_reset_sender] = (
        lambda: sender
    )
    app.dependency_overrides[auth_routes.get_rate_limit_store] = lambda: limits

    return Env(TestClient(app), reset, change, limits, sender)


def _forgot(env: Env, email: str = "user@example.com"):
    return env.client.post("/auth/forgot-password", json={"email": email})


def _reset(env: Env, token: str = "T" * 43, password: str = NEW_PASSWORD):
    return env.client.post(
        "/auth/reset-password",
        json={"token": token, "new_password": password},
    )


def _change(
    env: Env,
    current: str = PASSWORD,
    new: str = NEW_PASSWORD,
    authenticated: bool = True,
):
    headers = {}
    if authenticated:
        headers["Authorization"] = f"Bearer {create_access_token(USER_ID)}"

    return env.client.post(
        "/auth/change-password",
        json={"current_password": current, "new_password": new},
        headers=headers,
    )


def test_forgot_sends_a_reset_token(env: Env) -> None:
    response = _forgot(env, "  User@Example.COM ")

    assert response.status_code == 202
    assert len(env.sender.sent) == 1

    email, raw_token = env.sender.sent[0]
    assert email == "user@example.com"
    assert env.reset.issued[0] == (
        "user@example.com",
        hash_password_reset_token(raw_token),
    )


def test_forgot_issued_and_declined_responses_are_identical(env: Env) -> None:
    issued = _forgot(env)

    env.reset.issue_result = False
    declined = _forgot(env)

    assert issued.status_code == declined.status_code == 202
    assert issued.json() == declined.json()
    assert len(env.sender.sent) == 1


def test_forgot_response_never_contains_the_token(env: Env) -> None:
    response = _forgot(env)

    assert env.sender.sent[0][1] not in response.text


def test_forgot_rejects_an_invalid_email(env: Env) -> None:
    response = _forgot(env, "not-an-email")

    assert response.status_code == 422
    assert env.reset.issued == []


def test_forgot_ip_limit_blocks_before_the_store(env: Env) -> None:
    env.limits.deny.add("forgot_ip")

    response = _forgot(env)

    assert response.status_code == 429
    assert response.headers["Retry-After"] == "3600"
    assert env.reset.issued == []


def test_forgot_email_limit_blocks_before_the_store(env: Env) -> None:
    env.limits.deny.add("forgot_email")

    response = _forgot(env)

    assert response.status_code == 429
    assert env.reset.issued == []
    assert env.sender.sent == []


def test_forgot_rate_limit_failure_fails_closed(env: Env) -> None:
    env.limits.fail = True

    response = _forgot(env)

    assert response.status_code == 503
    assert env.reset.issued == []


def test_forgot_store_failure_fails_closed(env: Env) -> None:
    env.reset.fail = True

    response = _forgot(env)

    assert response.status_code == 503
    assert env.sender.sent == []


def test_forgot_sender_failure_does_not_change_the_response(env: Env) -> None:
    env.sender.fail = True

    response = _forgot(env)

    assert response.status_code == 202
    assert len(env.reset.issued) == 1


def test_forgot_rate_limit_keys_are_hashed_and_normalized(env: Env) -> None:
    _forgot(env, "  User@Example.COM ")

    assert [call[0] for call in env.limits.calls] == [
        "forgot_ip",
        "forgot_email",
    ]
    assert env.limits.calls[1][1] == hash_rate_limit_key(
        "forgot_email", "user@example.com"
    )


def test_forgot_rejects_unknown_fields(env: Env) -> None:
    response = env.client.post(
        "/auth/forgot-password",
        json={"email": "user@example.com", "is_admin": True},
    )

    assert response.status_code == 422
    assert env.reset.issued == []


def test_reset_succeeds_and_stores_only_hashes(env: Env) -> None:
    response = _reset(env)

    assert response.status_code == 200
    assert response.json() == {"status": "reset"}
    assert response.headers["Cache-Control"] == "no-store"

    token_hash, new_hash = env.reset.resets[0]
    assert token_hash == hash_password_reset_token("T" * 43)
    assert new_hash.startswith("$argon2id$")
    assert NEW_PASSWORD not in new_hash


def test_reset_invalid_token_gets_a_generic_400(env: Env) -> None:
    env.reset.reset_result = False

    response = _reset(env)

    assert response.status_code == 400
    assert response.json() == {"detail": "Invalid or expired reset token"}


def test_reset_rejects_a_weak_password_without_a_store_call(env: Env) -> None:
    response = _reset(env, password="short")

    assert response.status_code == 422
    assert env.reset.resets == []


def test_reset_ip_limit_blocks_before_the_store(env: Env) -> None:
    env.limits.deny.add("reset_ip")

    response = _reset(env)

    assert response.status_code == 429
    assert env.reset.resets == []


def test_reset_store_failure_fails_closed(env: Env) -> None:
    env.reset.fail = True

    assert _reset(env).status_code == 503


def test_reset_validation_errors_are_generic(env: Env) -> None:
    response = _reset(env, password="p" * 1025)

    assert response.status_code == 422
    assert response.json() == {"detail": "Invalid request"}
    assert "ppppp" not in response.text


def test_reset_rejects_unknown_fields(env: Env) -> None:
    response = env.client.post(
        "/auth/reset-password",
        json={"token": "T" * 43, "new_password": NEW_PASSWORD, "email": "a@b.co"},
    )

    assert response.status_code == 422
    assert env.reset.resets == []


def test_change_requires_authentication(env: Env) -> None:
    response = _change(env, authenticated=False)

    assert response.status_code == 401
    assert env.limits.calls == []
    assert env.change.get_calls == 0


def test_change_succeeds_with_compare_and_swap(env: Env) -> None:
    response = _change(env)

    assert response.status_code == 200
    assert response.json()["status"] == "changed"
    assert response.headers["Cache-Control"] == "no-store"

    user_id, expected_hash, new_hash = env.change.replaced[0]
    assert user_id == USER_ID
    assert expected_hash == PASSWORD_HASH
    assert new_hash.startswith("$argon2id$")


def test_change_wrong_current_password_gets_400(env: Env) -> None:
    response = _change(env, current="not the right password")

    assert response.status_code == 400
    assert env.change.replaced == []


def test_change_conflict_gets_409(env: Env) -> None:
    env.change.replace_result = False

    assert _change(env).status_code == 409


def test_change_rejects_a_weak_new_password(env: Env) -> None:
    response = _change(env, new="short")

    assert response.status_code == 422
    assert env.change.get_calls == 0


def test_change_rejects_an_unchanged_password(env: Env) -> None:
    response = _change(env, new=PASSWORD)

    assert response.status_code == 422
    assert env.change.get_calls == 0


def test_change_user_limit_key_is_the_hashed_user_id(env: Env) -> None:
    _change(env)

    assert [call[0] for call in env.limits.calls] == [
        "chpass_ip",
        "chpass_user",
    ]
    assert env.limits.calls[1][1] == hash_rate_limit_key(
        "chpass_user", str(USER_ID)
    )


def test_change_ip_limit_blocks_first(env: Env) -> None:
    env.limits.deny.add("chpass_ip")

    response = _change(env)

    assert response.status_code == 429
    assert env.change.get_calls == 0


def test_change_user_limit_blocks_before_the_store(env: Env) -> None:
    env.limits.deny.add("chpass_user")

    response = _change(env)

    assert response.status_code == 429
    assert env.change.get_calls == 0


def test_change_store_failure_fails_closed(env: Env) -> None:
    env.change.fail = True

    response = _change(env)

    assert response.status_code == 503
    assert "changed" not in response.text