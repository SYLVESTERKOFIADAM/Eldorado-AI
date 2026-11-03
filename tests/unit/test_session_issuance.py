from __future__ import annotations

from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest

from backend.models.session import RefreshTokenRecord, SessionRecord
from backend.security.jwt import verify_access_token
from backend.security.refresh_token import hash_refresh_token
from backend.security.session_issuance import issue_session

NOW = datetime(2026, 11, 3, 12, 0, tzinfo=timezone.utc)


@pytest.fixture(autouse=True)
def jwt_secret(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ELDORADO_JWT_SECRET", "unit-test-secret-" + "x" * 32)


class FakeSessionRepository:
    def __init__(
        self,
        fail_token: Exception | None = None,
        fail_revoke: Exception | None = None,
    ) -> None:
        self.sessions: list[SessionRecord] = []
        self.tokens: list[RefreshTokenRecord] = []
        self.revoked: list[tuple] = []
        self.fail_token = fail_token
        self.fail_revoke = fail_revoke

    def create_session(self, session: SessionRecord) -> SessionRecord:
        self.sessions.append(session)
        return session

    def create_refresh_token(
        self, token: RefreshTokenRecord
    ) -> RefreshTokenRecord:
        if self.fail_token is not None:
            raise self.fail_token
        self.tokens.append(token)
        return token

    def revoke_session(self, session_id, revoked_at):
        self.revoked.append((session_id, revoked_at))
        if self.fail_revoke is not None:
            raise self.fail_revoke


def test_issue_session_persists_session_and_hashed_refresh_token() -> None:
    repository = FakeSessionRepository()
    user_id = uuid4()

    issued = issue_session(repository, user_id, now=NOW)

    session = repository.sessions[0]
    token = repository.tokens[0]

    assert session.user_id == user_id
    assert session.created_at == NOW
    assert session.expires_at == NOW + timedelta(days=30)
    assert token.session_id == session.id == issued.session_id
    assert token.expires_at == session.expires_at == issued.refresh_expires_at
    assert token.token_hash == hash_refresh_token(issued.refresh_token)
    assert token.token_hash != issued.refresh_token
    assert issued.refresh_token not in repr(token)


def test_access_token_identifies_the_user() -> None:
    user_id = uuid4()

    issued = issue_session(FakeSessionRepository(), user_id, now=NOW)

    assert verify_access_token(issued.access_token).user.user_id == user_id


def test_each_issue_gets_a_new_family_and_new_tokens() -> None:
    repository = FakeSessionRepository()
    user_id = uuid4()

    first = issue_session(repository, user_id, now=NOW)
    second = issue_session(repository, user_id, now=NOW)

    assert first.refresh_token != second.refresh_token
    assert first.session_id != second.session_id
    assert (
        repository.sessions[0].token_family_id
        != repository.sessions[1].token_family_id
    )


def test_credentials_are_not_in_repr() -> None:
    issued = issue_session(FakeSessionRepository(), uuid4(), now=NOW)

    assert issued.access_token not in repr(issued)
    assert issued.refresh_token not in repr(issued)


def test_custom_lifetime_is_applied() -> None:
    repository = FakeSessionRepository()

    issue_session(
        repository, uuid4(), now=NOW, lifetime=timedelta(hours=1)
    )

    assert repository.sessions[0].expires_at == NOW + timedelta(hours=1)


def test_refresh_token_failure_revokes_the_session_and_reraises() -> None:
    repository = FakeSessionRepository(fail_token=RuntimeError("boom"))

    with pytest.raises(RuntimeError, match="boom"):
        issue_session(repository, uuid4(), now=NOW)

    assert [r[0] for r in repository.revoked] == [
        repository.sessions[0].id
    ]


def test_cleanup_failure_does_not_mask_the_original_error() -> None:
    repository = FakeSessionRepository(
        fail_token=RuntimeError("boom"),
        fail_revoke=ValueError("cleanup failed"),
    )

    with pytest.raises(RuntimeError, match="boom"):
        issue_session(repository, uuid4(), now=NOW)


def test_missing_jwt_secret_persists_nothing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("ELDORADO_JWT_SECRET", raising=False)
    repository = FakeSessionRepository()

    with pytest.raises(Exception):
        issue_session(repository, uuid4(), now=NOW)

    assert repository.sessions == []


def test_invalid_arguments_are_rejected() -> None:
    repository = FakeSessionRepository()

    with pytest.raises(TypeError):
        issue_session(repository, "not-a-uuid", now=NOW)  # type: ignore[arg-type]

    with pytest.raises(ValueError):
        issue_session(repository, uuid4(), now=datetime(2026, 1, 1))

    with pytest.raises(ValueError):
        issue_session(
            repository, uuid4(), now=NOW, lifetime=timedelta(0)
        )

    assert repository.sessions == []