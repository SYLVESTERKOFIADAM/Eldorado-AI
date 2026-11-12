from __future__ import annotations

from uuid import UUID, uuid4

import pytest

from backend.security.owner_bootstrap import (
    OWNER_MIN_PASSWORD_LENGTH,
    OwnerBootstrapError,
    bootstrap_owner,
)

PASSWORD = "correct-horse-battery-staple"


class FakeOwnerStore:
    def __init__(self, *, exists: bool = False) -> None:
        self.exists = exists
        self.created: list[tuple[str, str]] = []

    def create_owner_account(
        self,
        email: str,
        password_hash: str,
    ) -> UUID | None:
        if self.exists:
            return None

        self.created.append((email, password_hash))
        return uuid4()


def test_creates_an_owner_with_an_argon2id_hash() -> None:
    store = FakeOwnerStore()

    owner = bootstrap_owner(store, "owner@example.com", PASSWORD)

    assert owner == "owner@example.com"
    [(email, password_hash)] = store.created
    assert email == "owner@example.com"
    assert password_hash.startswith("$argon2id$")
    assert PASSWORD not in password_hash


def test_email_is_normalised() -> None:
    store = FakeOwnerStore()

    owner = bootstrap_owner(store, "  Owner@Example.COM ", PASSWORD)

    assert owner == "owner@example.com"
    assert store.created[0][0] == "owner@example.com"


def test_refuses_when_an_account_already_exists() -> None:
    store = FakeOwnerStore(exists=True)

    with pytest.raises(OwnerBootstrapError, match="already exists"):
        bootstrap_owner(store, "owner@example.com", PASSWORD)

    assert store.created == []


def test_rejects_a_short_owner_password() -> None:
    store = FakeOwnerStore()
    too_short = "x" * (OWNER_MIN_PASSWORD_LENGTH - 1)

    with pytest.raises(OwnerBootstrapError, match="at least"):
        bootstrap_owner(store, "owner@example.com", too_short)

    assert store.created == []


def test_rejects_an_invalid_email() -> None:
    store = FakeOwnerStore()

    with pytest.raises(OwnerBootstrapError):
        bootstrap_owner(store, "not-an-email", PASSWORD)

    assert store.created == []


def test_rejects_a_password_equal_to_the_email() -> None:
    store = FakeOwnerStore()
    email = "owner-owner@example.com"

    with pytest.raises(OwnerBootstrapError, match="same as the email"):
        bootstrap_owner(store, email, email)

    assert store.created == []


@pytest.mark.parametrize(
    "exists, email",
    [(True, "owner@example.com"), (False, "not-an-email")],
)
def test_error_messages_never_contain_the_password(
    exists: bool,
    email: str,
) -> None:
    with pytest.raises(OwnerBootstrapError) as caught:
        bootstrap_owner(FakeOwnerStore(exists=exists), email, PASSWORD)

    assert PASSWORD not in str(caught.value)