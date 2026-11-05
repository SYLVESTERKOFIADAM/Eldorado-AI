from __future__ import annotations

from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest

from backend.security.jwt import verify_access_token
from backend.security.refresh_token import hash_refresh_token
from backend.security.session_refresh import (
    RotationOutcome,
    RotationStatus,
    refresh_session,
)

NOW = datetime(2026, 11, 5, 12, 0, tzinfo=timezone.utc)
USER_ID = uuid4()
SESSION_ID = uuid4()
EXPIRES = NOW + timedelta(days=20)
PRESENTED = "A" * 43


@pytest.fixture(autouse=True)
def jwt_secret(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ELDORADO_JWT_SECRET", "unit-test-secret-" + "x" * 32)


class FakeStore:
    def __init__(self, status: RotationStatus = RotationStatus.ROTATED) -> None:
        self.status = status
        self.fail = False
        self.override: RotationOutcome | None = None
        self.calls: list[tuple[str, str, datetime]] = []

    def rotate(self, presented, replacement, now, mint_access_token):
        self.calls.append((presented, replacement, now))
        if self.fail:
            raise RuntimeError("database down")
        if self.override is not None:
            return self.override
        if self.status is RotationStatus.ROTATED:
            return RotationOutcome(
                RotationStatus.ROTATED,
                user_id=USER_ID,
                session_id=SESSION_ID,
                refresh_expires_at=EXPIRES,
                access_token=mint_access_token(USER_ID),
            )
        return RotationOutcome(self.status)


def test_rotation_returns_new_credentials() -> None:
    issued = refresh_session(FakeStore(), PRESENTED, now=NOW)

    assert issued is not None
    assert issued.user_id == USER_ID
    assert issued.session_id == SESSION_ID
    assert issued.refresh_expires_at == EXPIRES
    assert issued.refresh_token != PRESENTED
    assert verify_access_token(issued.access_token).user.user_id == USER_ID


def test_store_receives_presented_hash_and_new_replacement_hash() -> None:
    store = FakeStore()

    issued = refresh_session(store, PRESENTED, now=NOW)

    presented_hash, replacement_hash, now = store.calls[0]
    assert presented_hash == hash_refresh_token(PRESENTED)
    assert replacement_hash == hash_refresh_token(issued.refresh_token)
    assert replacement_hash != presented_hash
    assert now == NOW


def test_replay_returns_none() -> None:
    assert refresh_session(
        FakeStore(RotationStatus.REPLAY), PRESENTED, now=NOW
    ) is None


def test_invalid_returns_none() -> None:
    assert refresh_session(
        FakeStore(RotationStatus.INVALID), PRESENTED, now=NOW
    ) is None


@pytest.mark.parametrize("raw_token", ["", "tökén", None])
def test_malformed_token_returns_none_without_store_call(
    raw_token: object,
) -> None:
    store = FakeStore()

    assert refresh_session(store, raw_token, now=NOW) is None  # type: ignore[arg-type]
    assert store.calls == []


def test_store_errors_propagate_so_callers_fail_closed() -> None:
    store = FakeStore()
    store.fail = True

    with pytest.raises(RuntimeError):
        refresh_session(store, PRESENTED, now=NOW)


def test_incomplete_rotated_outcome_is_an_error() -> None:
    store = FakeStore()
    store.override = RotationOutcome(RotationStatus.ROTATED, user_id=USER_ID)

    with pytest.raises(RuntimeError):
        refresh_session(store, PRESENTED, now=NOW)


def test_credentials_are_not_in_repr() -> None:
    issued = refresh_session(FakeStore(), PRESENTED, now=NOW)

    assert issued.access_token not in repr(issued)
    assert issued.refresh_token not in repr(issued)


def test_naive_now_is_rejected() -> None:
    with pytest.raises(ValueError):
        refresh_session(FakeStore(), PRESENTED, now=datetime(2026, 1, 1))