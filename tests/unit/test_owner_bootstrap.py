from __future__ import annotations

from uuid import UUID, uuid4

import pytest

from backend.security.owner_bootstrap import (
    OWNER_MIN_PASSWORD_LENGTH,
    OwnerBootstrapError,
    bootstrap_owner,
)

PASSWORD = "correct-horse-battery-staple"


class FakeAccounts:
    def __init__(self) -> None:
        self.accounts: dict[str, dict] = {}

    def create_pending_account(
        self,
        email: str,
        password_hash: str,
        token_hash: str,
    ) -> UUID | None:
        if email in self.accounts:
            return None

        self.accounts[email] = {
            "password_hash": password_hash,
            "token_hash": token_hash,
            "verified": False,
        }
        return uuid4()

    def verify_email_token(self, token_hash: str) -> bool:
        for account in self.accounts.values():
            if account["token_hash"] == token_hash and not account["verified"]:
                account["verified"] = True
                return True

        return False


class NeverVerifies(FakeAccounts):
    def verify_email_token(self, token_hash: str) -> bool:
        return False


class Counter:
    def __init__(self, count: int) -> None:
        self._count = count

    def count_accounts(self) -> int:
        return self._count


def test_creates_a_verified_owner_when_no_account_exists() -> None:
    accounts = FakeAccounts()

    owner = bootstrap_owner(accounts, Counter(0), "owner@example.com", PASSWORD)

    assert owner == "owner@example.com"
    stored = accounts.accounts["owner@example.com"]
    assert stored["verified"] is True
    assert stored["password_hash"].startswith("$argon2id$")
    assert PASSWORD not in stored["password_hash"]


def test_email_is_normalised() -> None:
    accounts = FakeAccounts()

    owner = bootstrap_owner(
        accounts,
        Counter(0),
        "  Owner@Example.COM ",
        PASSWORD,
    )

    assert owner == "owner@example.com"
    assert "owner@example.com" in accounts.accounts


def test_refuses_when_any_account_already_exists() -> None:
    accounts = FakeAccounts()

    with pytest.raises(OwnerBootstrapError, match="already exists"):
        bootstrap_owner(accounts, Counter(1), "owner@example.com", PASSWORD)

    assert accounts.accounts == {}


def test_rejects_a_short_owner_password() -> None:
    accounts = FakeAccounts()
    too_short = "x" * (OWNER_MIN_PASSWORD_LENGTH - 1)

    with pytest.raises(OwnerBootstrapError, match="at least"):
        bootstrap_owner(accounts, Counter(0), "owner@example.com", too_short)

    assert accounts.accounts == {}


def test_rejects_an_invalid_email() -> None:
    accounts = FakeAccounts()

    with pytest.raises(OwnerBootstrapError):
        bootstrap_owner(accounts, Counter(0), "not-an-email", PASSWORD)

    assert accounts.accounts == {}


def test_reports_a_failed_creation() -> None:
    accounts = FakeAccounts()
    accounts.accounts["owner@example.com"] = {
        "password_hash": "x",
        "token_hash": "y",
        "verified": True,
    }

    with pytest.raises(OwnerBootstrapError, match="could not be created"):
        bootstrap_owner(accounts, Counter(0), "owner@example.com", PASSWORD)


def test_reports_a_failed_verification() -> None:
    accounts = NeverVerifies()

    with pytest.raises(OwnerBootstrapError, match="could not be verified"):
        bootstrap_owner(accounts, Counter(0), "owner@example.com", PASSWORD)


@pytest.mark.parametrize(
    "count, email",
    [(1, "owner@example.com"), (0, "not-an-email")],
)
def test_error_messages_never_contain_the_password(
    count: int,
    email: str,
) -> None:
    with pytest.raises(OwnerBootstrapError) as caught:
        bootstrap_owner(FakeAccounts(), Counter(count), email, PASSWORD)

    assert PASSWORD not in str(caught.value)