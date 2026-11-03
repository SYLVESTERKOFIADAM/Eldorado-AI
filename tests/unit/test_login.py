from __future__ import annotations

from uuid import uuid4

import pytest

from backend.security import login
from backend.security.login import (
    LoginCredential,
    authenticate_password,
)
from backend.security.passwords import hash_password

PASSWORD = "correct horse battery staple"


class FakeStore:
    def __init__(self, credential: LoginCredential | None) -> None:
        self.credential = credential
        self.requested_emails: list[str] = []

    def get_login_credential(self, email: str) -> LoginCredential | None:
        self.requested_emails.append(email)
        return self.credential


@pytest.fixture(scope="module")
def credential() -> LoginCredential:
    return LoginCredential(
        user_id=uuid4(),
        password_hash=hash_password(PASSWORD),
    )


def test_valid_login_succeeds(credential: LoginCredential) -> None:
    result = authenticate_password(
        FakeStore(credential), "user@example.com", PASSWORD
    )

    assert result is not None
    assert result.user_id == credential.user_id
    assert result.needs_rehash is False


def test_email_is_normalized_before_lookup(
    credential: LoginCredential,
) -> None:
    store = FakeStore(credential)

    authenticate_password(store, "  User@Example.COM ", PASSWORD)

    assert store.requested_emails == ["user@example.com"]


def test_wrong_password_fails(credential: LoginCredential) -> None:
    assert authenticate_password(
        FakeStore(credential), "user@example.com", "wrong password"
    ) is None


def test_unknown_or_unverified_account_fails_and_still_hashes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[str] = []
    real_verify = login.verify_password

    def spy(plain: str, stored: str) -> bool:
        calls.append(stored)
        return real_verify(plain, stored)

    monkeypatch.setattr(login, "verify_password", spy)

    result = authenticate_password(
        FakeStore(None), "nobody@example.com", PASSWORD
    )

    assert result is None
    assert calls == [login._DUMMY_HASH]


def test_corrupted_stored_hash_fails_closed() -> None:
    broken = LoginCredential(user_id=uuid4(), password_hash="not-a-hash")

    assert authenticate_password(
        FakeStore(broken), "user@example.com", PASSWORD
    ) is None


@pytest.mark.parametrize(
    ("email", "password"),
    [
        ("", PASSWORD),
        ("   ", PASSWORD),
        ("user@example.com", ""),
        ("a" * 321, PASSWORD),
        ("user@example.com", "p" * 1025),
        (None, PASSWORD),
        ("user@example.com", None),
    ],
)
def test_malformed_input_is_rejected_without_lookup(
    credential: LoginCredential,
    email: object,
    password: object,
) -> None:
    store = FakeStore(credential)

    result = authenticate_password(store, email, password)  # type: ignore[arg-type]

    assert result is None
    assert store.requested_emails == []