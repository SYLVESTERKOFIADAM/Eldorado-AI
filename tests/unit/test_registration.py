from __future__ import annotations

from uuid import UUID, uuid4

import pytest

from backend.security import registration
from backend.security.email_verification import (
    hash_email_verification_token,
)
from backend.security.registration import (
    RegistrationInputError,
    register_account,
    verify_email,
)

PASSWORD = "correct horse battery staple"


class FakeStore:
    def __init__(self, existing: set[str] | None = None) -> None:
        self.existing = existing or set()
        self.created: list[tuple[str, str, str]] = []
        self.verified_hashes: list[str] = []
        self.verify_result = True

    def create_pending_account(
        self, email: str, password_hash: str, token_hash: str
    ) -> UUID | None:
        if email in self.existing:
            return None
        self.created.append((email, password_hash, token_hash))
        return uuid4()

    def verify_email_token(self, token_hash: str) -> bool:
        self.verified_hashes.append(token_hash)
        return self.verify_result


def test_new_registration_creates_pending_account_and_token() -> None:
    store = FakeStore()

    result = register_account(store, "  User@Example.COM ", PASSWORD)

    assert result.verification_token is not None
    email, password_hash, token_hash = store.created[0]
    assert email == "user@example.com"
    assert password_hash.startswith("$argon2id$")
    assert PASSWORD not in password_hash
    assert token_hash == hash_email_verification_token(
        result.verification_token
    )


def test_duplicate_registration_returns_no_token_but_still_hashes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[str] = []
    real_hash = registration.hash_password

    def spy(plain: str) -> str:
        calls.append(plain)
        return real_hash(plain)

    monkeypatch.setattr(registration, "hash_password", spy)
    store = FakeStore(existing={"user@example.com"})

    result = register_account(store, "user@example.com", PASSWORD)

    assert result.verification_token is None
    assert store.created == []
    assert calls == [PASSWORD]


def test_raw_token_is_not_exposed_in_repr() -> None:
    result = register_account(FakeStore(), "user@example.com", PASSWORD)

    assert result.verification_token is not None
    assert result.verification_token not in repr(result)


@pytest.mark.parametrize(
    ("email", "password"),
    [
        ("", PASSWORD),
        ("not-an-email", PASSWORD),
        ("a@b", PASSWORD),
        ("us er@example.com", PASSWORD),
        ("user@@example.com", PASSWORD),
        ("usér@example.com", PASSWORD),
        ("a" * 320 + "@example.com", PASSWORD),
        (None, PASSWORD),
        ("user@example.com", "short"),
        ("user@example.com", " " * 20),
        ("user@example.com", "p" * 1025),
        ("user@example.com", "user@example.com"),
        ("user@example.com", None),
    ],
)
def test_invalid_input_is_rejected_without_touching_store(
    email: object,
    password: object,
) -> None:
    store = FakeStore()

    with pytest.raises(RegistrationInputError):
        register_account(store, email, password)  # type: ignore[arg-type]

    assert store.created == []


def test_verify_email_passes_hash_to_store() -> None:
    store = FakeStore()

    assert verify_email(store, "some-raw-token") is True
    assert store.verified_hashes == [
        hash_email_verification_token("some-raw-token")
    ]


def test_verify_email_returns_false_when_store_rejects() -> None:
    store = FakeStore()
    store.verify_result = False

    assert verify_email(store, "some-raw-token") is False


@pytest.mark.parametrize("raw_token", ["", None, "token-ñ", 123])
def test_verify_email_rejects_malformed_token_without_store_call(
    raw_token: object,
) -> None:
    store = FakeStore()

    assert verify_email(store, raw_token) is False  # type: ignore[arg-type]
    assert store.verified_hashes == []