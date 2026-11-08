from __future__ import annotations

import re
from uuid import uuid4

import pytest

from backend.security.password_change import (
    ChangeOutcome,
    change_password,
)
from backend.security.password_reset import (
    complete_password_reset,
    generate_password_reset_token,
    hash_password_reset_token,
    request_password_reset,
)
from backend.security.passwords import hash_password, verify_password
from backend.security.registration import RegistrationInputError

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
    def __init__(self, stored_hash: str | None = PASSWORD_HASH) -> None:
        self.stored_hash = stored_hash
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


def test_generated_reset_token_hash_matches_the_raw_token() -> None:
    token = generate_password_reset_token()

    assert re.fullmatch(r"[0-9a-f]{64}", token.token_hash)
    assert hash_password_reset_token(token.raw_token) == token.token_hash


def test_generated_reset_tokens_are_unique() -> None:
    first = generate_password_reset_token()
    second = generate_password_reset_token()

    assert first.raw_token != second.raw_token
    assert first.token_hash != second.token_hash


def test_raw_reset_token_is_not_in_repr() -> None:
    token = generate_password_reset_token()

    assert token.raw_token not in repr(token)


@pytest.mark.parametrize("raw_token", ["", None, 123, b"token"])
def test_hashing_rejects_invalid_token_input(raw_token: object) -> None:
    with pytest.raises(ValueError):
        hash_password_reset_token(raw_token)  # type: ignore[arg-type]


def test_hashing_rejects_non_ascii_token() -> None:
    with pytest.raises(ValueError, match="reset token is invalid"):
        hash_password_reset_token("token-ñ")


def test_request_reset_issues_a_token_for_the_normalized_email() -> None:
    store = FakeResetStore()

    result = request_password_reset(store, "  User@Example.COM ")

    assert result.reset_token is not None
    email, token_hash = store.issued[0]
    assert email == "user@example.com"
    assert token_hash == hash_password_reset_token(result.reset_token)


def test_request_reset_returns_no_token_when_declined() -> None:
    store = FakeResetStore()
    store.issue_result = False

    assert request_password_reset(store, "user@example.com").reset_token is None


def test_request_reset_rejects_an_invalid_email_without_a_store_call() -> None:
    store = FakeResetStore()

    with pytest.raises(RegistrationInputError):
        request_password_reset(store, "not-an-email")

    assert store.issued == []


def test_request_reset_store_errors_propagate() -> None:
    store = FakeResetStore()
    store.fail = True

    with pytest.raises(RuntimeError):
        request_password_reset(store, "user@example.com")


def test_complete_reset_stores_the_token_hash_and_an_argon2id_hash() -> None:
    store = FakeResetStore()

    assert complete_password_reset(store, "T" * 43, NEW_PASSWORD) is True

    token_hash, new_hash = store.resets[0]
    assert token_hash == hash_password_reset_token("T" * 43)
    assert new_hash.startswith("$argon2id$")
    assert NEW_PASSWORD not in new_hash
    assert verify_password(NEW_PASSWORD, new_hash) is True


def test_complete_reset_rejects_a_weak_password_without_a_store_call() -> None:
    store = FakeResetStore()

    with pytest.raises(RegistrationInputError):
        complete_password_reset(store, "T" * 43, "short")

    assert store.resets == []


@pytest.mark.parametrize("raw_token", ["", "tökén", None])
def test_complete_reset_malformed_token_returns_false_without_store_call(
    raw_token: object,
) -> None:
    store = FakeResetStore()

    assert complete_password_reset(store, raw_token, NEW_PASSWORD) is False  # type: ignore[arg-type]
    assert store.resets == []


def test_complete_reset_returns_false_when_the_store_rejects() -> None:
    store = FakeResetStore()
    store.reset_result = False

    assert complete_password_reset(store, "T" * 43, NEW_PASSWORD) is False


def test_complete_reset_store_errors_propagate() -> None:
    store = FakeResetStore()
    store.fail = True

    with pytest.raises(RuntimeError):
        complete_password_reset(store, "T" * 43, NEW_PASSWORD)


def test_change_password_succeeds_with_compare_and_swap() -> None:
    store = FakeChangeStore()

    outcome = change_password(store, USER_ID, PASSWORD, NEW_PASSWORD)

    assert outcome is ChangeOutcome.CHANGED
    user_id, expected_hash, new_hash = store.replaced[0]
    assert user_id == USER_ID
    assert expected_hash == PASSWORD_HASH
    assert new_hash.startswith("$argon2id$")
    assert verify_password(NEW_PASSWORD, new_hash) is True


def test_change_password_wrong_current_password_changes_nothing() -> None:
    store = FakeChangeStore()

    outcome = change_password(
        store, USER_ID, "not the right password", NEW_PASSWORD
    )

    assert outcome is ChangeOutcome.WRONG_CURRENT
    assert store.replaced == []


def test_change_password_without_a_stored_hash_is_wrong_current() -> None:
    store = FakeChangeStore(stored_hash=None)

    assert (
        change_password(store, USER_ID, PASSWORD, NEW_PASSWORD)
        is ChangeOutcome.WRONG_CURRENT
    )
    assert store.replaced == []


def test_change_password_corrupted_stored_hash_fails_closed() -> None:
    store = FakeChangeStore(stored_hash="not-a-hash")

    assert (
        change_password(store, USER_ID, PASSWORD, NEW_PASSWORD)
        is ChangeOutcome.WRONG_CURRENT
    )
    assert store.replaced == []


def test_change_password_reports_a_conflict_when_the_hash_moved() -> None:
    store = FakeChangeStore()
    store.replace_result = False

    assert (
        change_password(store, USER_ID, PASSWORD, NEW_PASSWORD)
        is ChangeOutcome.CONFLICT
    )


def test_change_password_rejects_an_unchanged_password_before_the_store() -> None:
    store = FakeChangeStore()

    with pytest.raises(RegistrationInputError):
        change_password(store, USER_ID, PASSWORD, PASSWORD)

    assert store.get_calls == 0


def test_change_password_rejects_a_weak_new_password_before_the_store() -> None:
    store = FakeChangeStore()

    with pytest.raises(RegistrationInputError):
        change_password(store, USER_ID, PASSWORD, "short")

    assert store.get_calls == 0


@pytest.mark.parametrize("current", ["", None, "p" * 1025])
def test_change_password_invalid_current_is_wrong_without_store_call(
    current: object,
) -> None:
    store = FakeChangeStore()

    outcome = change_password(store, USER_ID, current, NEW_PASSWORD)  # type: ignore[arg-type]

    assert outcome is ChangeOutcome.WRONG_CURRENT
    assert store.get_calls == 0


def test_change_password_store_errors_propagate() -> None:
    store = FakeChangeStore()
    store.fail = True

    with pytest.raises(RuntimeError):
        change_password(store, USER_ID, PASSWORD, NEW_PASSWORD)