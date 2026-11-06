from __future__ import annotations

import pytest

from backend.security.email_verification import (
    hash_email_verification_token,
)
from backend.security.registration import RegistrationInputError
from backend.security.verification_resend import resend_verification


class FakeStore:
    def __init__(self, result: bool = True) -> None:
        self.result = result
        self.fail = False
        self.calls: list[tuple[str, str]] = []

    def issue_verification_token(self, email: str, token_hash: str) -> bool:
        if self.fail:
            raise RuntimeError("database down")
        self.calls.append((email, token_hash))
        return self.result


def test_issues_a_token_for_the_normalized_email() -> None:
    store = FakeStore()

    result = resend_verification(store, "  User@Example.COM ")

    assert result.verification_token is not None
    email, token_hash = store.calls[0]
    assert email == "user@example.com"
    assert token_hash == hash_email_verification_token(
        result.verification_token
    )


def test_no_token_is_returned_when_the_store_declines() -> None:
    result = resend_verification(FakeStore(result=False), "user@example.com")

    assert result.verification_token is None


def test_invalid_email_is_rejected_without_a_store_call() -> None:
    store = FakeStore()

    with pytest.raises(RegistrationInputError):
        resend_verification(store, "not-an-email")

    assert store.calls == []


def test_store_errors_propagate_so_callers_fail_closed() -> None:
    store = FakeStore()
    store.fail = True

    with pytest.raises(RuntimeError):
        resend_verification(store, "user@example.com")


def test_each_call_generates_a_new_token() -> None:
    store = FakeStore()

    first = resend_verification(store, "user@example.com")
    second = resend_verification(store, "user@example.com")

    assert first.verification_token != second.verification_token


def test_token_is_not_in_repr() -> None:
    result = resend_verification(FakeStore(), "user@example.com")

    assert result.verification_token not in repr(result)