from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest

from backend.models.session import (
    RefreshTokenRecord,
    SessionRecord,
)


def test_valid_session_record_is_created():
    session = SessionRecord(
        user_id=uuid4(),
        token_family_id=uuid4(),
        expires_at=datetime.now(timezone.utc) + timedelta(days=30),
    )

    assert session.id is not None
    assert session.is_revoked is False
    assert session.is_expired is False


def test_session_requires_expiry():
    with pytest.raises(
        ValueError,
        match="expires_at is required",
    ):
        SessionRecord(
            user_id=uuid4(),
            token_family_id=uuid4(),
        )


def test_session_expiry_must_be_after_creation():
    created_at = datetime.now(timezone.utc)

    with pytest.raises(
        ValueError,
        match="expires_at must be after created_at",
    ):
        SessionRecord(
            user_id=uuid4(),
            token_family_id=uuid4(),
            created_at=created_at,
            expires_at=created_at,
        )


def test_session_rejects_naive_created_at():
    with pytest.raises(
        ValueError,
        match="created_at must be timezone-aware",
    ):
        SessionRecord(
            user_id=uuid4(),
            token_family_id=uuid4(),
            created_at=datetime.now(),
            expires_at=datetime.now(timezone.utc) + timedelta(days=30),
        )


def test_session_rejects_last_used_before_creation():
    created_at = datetime.now(timezone.utc)
    last_used_at = created_at - timedelta(seconds=1)

    with pytest.raises(
        ValueError,
        match="last_used_at cannot be before created_at",
    ):
        SessionRecord(
            user_id=uuid4(),
            token_family_id=uuid4(),
            created_at=created_at,
            last_used_at=last_used_at,
            expires_at=created_at + timedelta(days=30),
        )


def test_expired_session_is_detected():
    created_at = datetime.now(timezone.utc) - timedelta(days=2)
    expires_at = created_at + timedelta(days=1)

    session = SessionRecord(
        user_id=uuid4(),
        token_family_id=uuid4(),
        created_at=created_at,
        expires_at=expires_at,
    )

    assert session.is_expired is True


def test_revoked_session_is_detected():
    created_at = datetime.now(timezone.utc) - timedelta(minutes=1)

    session = SessionRecord(
        user_id=uuid4(),
        token_family_id=uuid4(),
        created_at=created_at,
        expires_at=created_at + timedelta(days=30),
        revoked_at=created_at + timedelta(seconds=1),
    )

    assert session.is_revoked is True


def test_valid_refresh_token_record_is_created():
    token = RefreshTokenRecord(
        session_id=uuid4(),
        token_hash="a" * 64,
        expires_at=datetime.now(timezone.utc) + timedelta(days=30),
    )

    assert token.id is not None
    assert token.is_consumed is False
    assert token.is_expired is False


def test_refresh_token_requires_expiry():
    with pytest.raises(
        ValueError,
        match="expires_at is required",
    ):
        RefreshTokenRecord(
            session_id=uuid4(),
            token_hash="a" * 64,
        )


def test_refresh_token_rejects_blank_hash():
    with pytest.raises(
        ValueError,
        match="token_hash cannot be blank",
    ):
        RefreshTokenRecord(
            session_id=uuid4(),
            token_hash="   ",
            expires_at=datetime.now(timezone.utc) + timedelta(days=30),
        )


def test_refresh_token_expiry_must_be_after_issue():
    issued_at = datetime.now(timezone.utc)

    with pytest.raises(
        ValueError,
        match="expires_at must be after issued_at",
    ):
        RefreshTokenRecord(
            session_id=uuid4(),
            token_hash="a" * 64,
            issued_at=issued_at,
            expires_at=issued_at,
        )


def test_refresh_token_rejects_consumed_before_issue():
    issued_at = datetime.now(timezone.utc)

    with pytest.raises(
        ValueError,
        match="consumed_at cannot be before issued_at",
    ):
        RefreshTokenRecord(
            session_id=uuid4(),
            token_hash="a" * 64,
            issued_at=issued_at,
            expires_at=issued_at + timedelta(days=30),
            consumed_at=issued_at - timedelta(seconds=1),
        )


def test_refresh_token_cannot_replace_itself():
    token_id = uuid4()

    with pytest.raises(
        ValueError,
        match="replaced_by_id cannot reference the same token",
    ):
        RefreshTokenRecord(
            id=token_id,
            session_id=uuid4(),
            token_hash="a" * 64,
            expires_at=datetime.now(timezone.utc) + timedelta(days=30),
            replaced_by_id=token_id,
        )


def test_consumed_refresh_token_is_detected():
    issued_at = datetime.now(timezone.utc) - timedelta(minutes=1)

    token = RefreshTokenRecord(
        session_id=uuid4(),
        token_hash="a" * 64,
        issued_at=issued_at,
        expires_at=issued_at + timedelta(days=30),
        consumed_at=issued_at + timedelta(seconds=1),
    )

    assert token.is_consumed is True


def test_expired_refresh_token_is_detected():
    issued_at = datetime.now(timezone.utc) - timedelta(days=2)
    expires_at = issued_at + timedelta(days=1)

    token = RefreshTokenRecord(
        session_id=uuid4(),
        token_hash="a" * 64,
        issued_at=issued_at,
        expires_at=expires_at,
    )

    assert token.is_expired is True