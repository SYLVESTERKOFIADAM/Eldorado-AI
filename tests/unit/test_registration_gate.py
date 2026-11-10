from __future__ import annotations

from uuid import UUID, uuid4

import pytest
from fastapi.testclient import TestClient

from backend.api.app import create_app
from backend.api.auth_routes import (
    get_account_store,
    get_email_sender,
    get_rate_limit_store,
)

REGISTER_BODY = {
    "email": "owner@example.com",
    "password": "a-long-enough-password",
}


class FakeAccounts:
    def __init__(self) -> None:
        self.created: list[str] = []

    def create_pending_account(
        self,
        email: str,
        password_hash: str,
        token_hash: str,
    ) -> UUID | None:
        self.created.append(email)
        return uuid4()

    def verify_email_token(self, token_hash: str) -> bool:
        return False


class AllowAllLimits:
    def hit(
        self,
        bucket: str,
        key_hash: str,
        limit: int,
        window_seconds: int,
    ) -> bool:
        return True


class NullSender:
    def send_verification(self, email: str, raw_token: str) -> None:
        return None


def _client(accounts: FakeAccounts) -> TestClient:
    app = create_app()
    app.dependency_overrides[get_account_store] = lambda: accounts
    app.dependency_overrides[get_rate_limit_store] = lambda: AllowAllLimits()
    app.dependency_overrides[get_email_sender] = lambda: NullSender()

    return TestClient(app)


def test_registration_is_closed_when_flag_is_unset(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("ELDORADO_ENABLE_REGISTRATION", raising=False)
    accounts = FakeAccounts()

    response = _client(accounts).post("/auth/register", json=REGISTER_BODY)

    assert response.status_code == 404
    assert accounts.created == []


@pytest.mark.parametrize("value", ["", "false", "0", "yes"])
def test_registration_is_closed_for_any_value_other_than_true(
    monkeypatch: pytest.MonkeyPatch,
    value: str,
) -> None:
    monkeypatch.setenv("ELDORADO_ENABLE_REGISTRATION", value)
    accounts = FakeAccounts()

    response = _client(accounts).post("/auth/register", json=REGISTER_BODY)

    assert response.status_code == 404
    assert accounts.created == []


@pytest.mark.parametrize("value", ["true", " TRUE "])
def test_registration_opens_only_when_flag_is_true(
    monkeypatch: pytest.MonkeyPatch,
    value: str,
) -> None:
    monkeypatch.setenv("ELDORADO_ENABLE_REGISTRATION", value)
    accounts = FakeAccounts()

    response = _client(accounts).post("/auth/register", json=REGISTER_BODY)

    assert response.status_code == 202
    assert accounts.created == ["owner@example.com"]


def test_verify_email_stays_available_while_registration_is_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("ELDORADO_ENABLE_REGISTRATION", raising=False)

    response = _client(FakeAccounts()).post(
        "/auth/verify-email",
        json={"token": "A" * 43},
    )

    assert response.status_code == 400