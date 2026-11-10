from __future__ import annotations

import psycopg
import pytest

from backend.database.owner_store import PostgresAccountCounter


class FakeResult:
    def __init__(self, row: tuple | None) -> None:
        self._row = row

    def fetchone(self) -> tuple | None:
        return self._row


class FakeConnection:
    def __init__(
        self,
        role_row: tuple | None,
        count_row: tuple | None,
    ) -> None:
        self.statements: list[str] = []
        self._role_row = role_row
        self._count_row = count_row

    def __enter__(self) -> "FakeConnection":
        return self

    def __exit__(self, *exc_info: object) -> bool:
        return False

    def execute(self, sql: str, params: object = None) -> FakeResult:
        self.statements.append(sql)

        if "pg_roles" in sql:
            return FakeResult(self._role_row)

        return FakeResult(self._count_row)


def _install(
    monkeypatch: pytest.MonkeyPatch,
    connection: FakeConnection,
) -> None:
    monkeypatch.setattr(psycopg, "connect", lambda dsn: connection)


def test_counts_only_accounts_that_can_authenticate(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    connection = FakeConnection(role_row=(True,), count_row=(3,))
    _install(monkeypatch, connection)

    assert PostgresAccountCounter("host=db").count_accounts() == 3

    count_sql = connection.statements[-1]
    assert "public.users" in count_sql
    assert "email IS NOT NULL" in count_sql


def test_refuses_a_role_that_cannot_bypass_row_level_security(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    connection = FakeConnection(role_row=(False,), count_row=(0,))
    _install(monkeypatch, connection)

    with pytest.raises(RuntimeError, match="database owner role"):
        PostgresAccountCounter("host=db").count_accounts()

    assert all("count(*)" not in sql for sql in connection.statements)


def test_refuses_when_the_role_cannot_be_determined(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    connection = FakeConnection(role_row=None, count_row=(0,))
    _install(monkeypatch, connection)

    with pytest.raises(RuntimeError):
        PostgresAccountCounter("host=db").count_accounts()


def test_rejects_an_empty_dsn() -> None:
    with pytest.raises(ValueError):
        PostgresAccountCounter("   ")