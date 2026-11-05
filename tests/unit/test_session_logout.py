from __future__ import annotations

from datetime import datetime, timezone

import pytest

from backend.security.refresh_token import hash_refresh_token
from backend.security.session_logout import logout_session

NOW = datetime(2026, 11, 5, 12, 0, tzinfo=timezone.utc)
PRESENTED = "A" * 43


class FakeStore:
    def __init__(self, result: bool = True) -> None:
        self.result = result
        self.fail = False
        self.calls: list[tuple[str, datetime]] = []

    def revoke(self, presented_token_hash: str, now: datetime) -> bool:
        if self.fail:
            raise RuntimeError("database down")
        self.calls.append((presented_token_hash, now))
        return self.result


def test_store_receives_the_hash_and_time() -> None:
    store = FakeStore()

    assert logout_session(store, PRESENTED, now=NOW) is True
    assert store.calls == [(hash_refresh_token(PRESENTED), NOW)]


def test_returns_false_when_nothing_was_revoked() -> None:
    assert logout_session(FakeStore(result=False), PRESENTED, now=NOW) is False


@pytest.mark.parametrize("raw_token", ["", "tökén", None])
def test_malformed_token_returns_false_without_store_call(
    raw_token: object,
) -> None:
    store = FakeStore()

    assert logout_session(store, raw_token, now=NOW) is False  # type: ignore[arg-type]
    assert store.calls == []


def test_store_errors_propagate_so_callers_fail_closed() -> None:
    store = FakeStore()
    store.fail = True

    with pytest.raises(RuntimeError):
        logout_session(store, PRESENTED, now=NOW)


def test_naive_now_is_rejected() -> None:
    with pytest.raises(ValueError):
        logout_session(FakeStore(), PRESENTED, now=datetime(2026, 1, 1))