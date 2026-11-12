from __future__ import annotations

from uuid import UUID, uuid4

import psycopg
import pytest
from psycopg import errors

from backend.database.owner_store import PostgresOwnerStore

PASSWORD_HASH = "$argon2id$v=19$m=65536,t=3,p=4$c29tZXNhbHQ$c29tZWhhc2g"


class FakeResult:
    def __init__(self, row: tuple | None) -> None:
        self._row = row

    def fetchone(self) -> tuple | None:
        return self._row


class FakeConnection:
    def __init__(
        self,
        row: tuple | None = None,
        error: Exception | None = None,
    ) -> None:
        self.calls: list[tuple[str, object]] = []
        self._row = row
        self._error = error

    def __enter__(self) -> "FakeConnection":
        return self

    def __exit__(self, *exc_info: object) -> bool:
        return False

    def execute(self, sql: str, params: object = None) -> FakeResult:
        self.calls.append((sql, params))

        if self._error is not None:
            raise self._error

        return FakeResult(self._row)


def _install(
    monkeypatch: pytest.MonkeyPatch,
    connection: FakeConnection,
) -> None:
    monkeypatch.setattr(psycopg, "connect", lambda dsn: connection)


def test_returns_the_new_owner_id(monkeypatch: pytest.MonkeyPatch) -> None:
    user_id = uuid4()
    connection = FakeConnection(row=(user_id,))
    _install(monkeypatch, connection)

    result = PostgresOwnerStore("host=db").create_owner_account(
        "owner@example.com",
        PASSWORD_HASH,
    )

    assert result == user_id
    sql, params = connection.calls[0]
    assert "bootstrap_owner_account" in sql
    assert params == ("owner@example.com", PASSWORD_HASH)


def test_accepts_a_string_identity(monkeypatch: pytest.MonkeyPatch) -> None:
    user_id = uuid4()
    _install(monkeypatch, FakeConnection(row=(str(user_id),)))

    result = PostgresOwnerStore("host=db").create_owner_account(
        "owner@example.com",
        PASSWORD_HASH,
    )

    assert result == user_id
    assert isinstance(result, UUID)


def test_returns_none_when_an_account_exists(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    error = errors.ObjectNotInPrerequisiteState("An account already exists")
    _install(monkeypatch, FakeConnection(error=error))

    assert (
        PostgresOwnerStore("host=db").create_owner_account(
            "owner@example.com",
            PASSWORD_HASH,
        )
        is None
    )


def test_other_database_errors_propagate(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    error = errors.InsufficientPrivilege("permission denied")
    _install(monkeypatch, FakeConnection(error=error))

    with pytest.raises(errors.InsufficientPrivilege):
        PostgresOwnerStore("host=db").create_owner_account(
            "owner@example.com",
            PASSWORD_HASH,
        )


def test_fails_when_no_identity_is_returned(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install(monkeypatch, FakeConnection(row=None))

    with pytest.raises(RuntimeError):
        PostgresOwnerStore("host=db").create_owner_account(
            "owner@example.com",
            PASSWORD_HASH,
        )


def test_rejects_an_empty_dsn() -> None:
    with pytest.raises(ValueError):
        PostgresOwnerStore("   ")