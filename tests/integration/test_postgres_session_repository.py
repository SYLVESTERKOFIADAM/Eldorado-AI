from datetime import datetime, timedelta, timezone
from uuid import UUID, uuid4

import psycopg

from backend.database.connection import DatabaseConnection
from backend.models.session import RefreshTokenRecord, SessionRecord
from backend.repositories.postgres_session_repository import (
    PostgresSessionRepository,
)


DSN = "dbname=postgres user=eldorado_app host=localhost port=5432"

USER_A = UUID("76bab0d0-94f5-4925-a729-62e31726456f")
USER_B = UUID("dd0939fc-c93a-4f20-93de-3c1d6c88804f")


def _session(
    user_id: UUID,
    *,
    session_id: UUID | None = None,
    token_family_id: UUID | None = None,
) -> SessionRecord:
    created_at = datetime.now(timezone.utc)

    return SessionRecord(
        id=session_id or uuid4(),
        user_id=user_id,
        token_family_id=token_family_id or uuid4(),
        created_at=created_at,
        expires_at=created_at + timedelta(days=30),
    )


def _refresh_token(
    session_id: UUID,
    *,
    token_hash: str | None = None,
) -> RefreshTokenRecord:
    issued_at = datetime.now(timezone.utc)

    return RefreshTokenRecord(
        id=uuid4(),
        session_id=session_id,
        token_hash=token_hash or f"test-hash-{uuid4()}",
        issued_at=issued_at,
        expires_at=issued_at + timedelta(days=30),
    )


def test_same_user_can_create_and_read_session():
    database = DatabaseConnection(DSN)
    repository = PostgresSessionRepository(database, USER_A)

    session = _session(USER_A)

    created = repository.create_session(session)
    fetched = repository.get_session(session.id)

    assert created == session
    assert fetched == session

    repository.revoke_session(
        session.id,
        datetime.now(timezone.utc),
    )


def test_cross_user_session_read_is_hidden_by_rls():
    database = DatabaseConnection(DSN)

    session = _session(USER_A)

    repository_a = PostgresSessionRepository(database, USER_A)
    repository_b = PostgresSessionRepository(database, USER_B)

    repository_a.create_session(session)

    try:
        assert repository_b.get_session(session.id) is None
    finally:
        repository_a.revoke_session(
            session.id,
            datetime.now(timezone.utc),
        )


def test_cross_user_session_creation_is_rejected_by_rls():
    database = DatabaseConnection(DSN)
    repository = PostgresSessionRepository(database, USER_A)

    session = _session(USER_B)

    try:
        repository.create_session(session)
    except psycopg.errors.InsufficientPrivilege:
        return

    raise AssertionError(
        "Cross-user session INSERT was not rejected by RLS."
    )


def test_same_user_can_create_and_read_refresh_token():
    database = DatabaseConnection(DSN)
    repository = PostgresSessionRepository(database, USER_A)

    session = _session(USER_A)
    repository.create_session(session)

    token = _refresh_token(session.id)
    created = repository.create_refresh_token(token)
    fetched = repository.get_refresh_token_by_hash(token.token_hash)

    assert created == token
    assert fetched == token

    repository.revoke_session(
        session.id,
        datetime.now(timezone.utc),
    )


def test_cross_user_refresh_token_read_is_hidden_by_rls():
    database = DatabaseConnection(DSN)

    session = _session(USER_A)

    repository_a = PostgresSessionRepository(database, USER_A)
    repository_b = PostgresSessionRepository(database, USER_B)

    repository_a.create_session(session)

    token = _refresh_token(session.id)
    repository_a.create_refresh_token(token)

    try:
        assert (
            repository_b.get_refresh_token_by_hash(
                token.token_hash
            )
            is None
        )
    finally:
        repository_a.revoke_session(
            session.id,
            datetime.now(timezone.utc),
        )


def test_session_revoke_marks_session_revoked():
    database = DatabaseConnection(DSN)
    repository = PostgresSessionRepository(database, USER_A)

    session = _session(USER_A)
    repository.create_session(session)

    revoked_at = datetime.now(timezone.utc)

    revoked = repository.revoke_session(
        session.id,
        revoked_at,
    )

    assert revoked.revoked_at == revoked_at

    fetched = repository.get_session(session.id)

    assert fetched is not None
    assert fetched.revoked_at == revoked_at


def test_token_family_revocation_marks_all_user_sessions():
    database = DatabaseConnection(DSN)
    repository = PostgresSessionRepository(database, USER_A)

    family_id = uuid4()

    session_one = _session(
        USER_A,
        token_family_id=family_id,
    )
    session_two = _session(
        USER_A,
        token_family_id=family_id,
    )

    repository.create_session(session_one)
    repository.create_session(session_two)

    revoked_at = datetime.now(timezone.utc)

    affected = repository.revoke_token_family(
        family_id,
        revoked_at,
        revoked_at,
    )

    assert affected == 2

    fetched_one = repository.get_session(session_one.id)
    fetched_two = repository.get_session(session_two.id)

    assert fetched_one is not None
    assert fetched_two is not None
    assert fetched_one.revoked_at == revoked_at
    assert fetched_two.revoked_at == revoked_at
    assert fetched_one.reuse_detected_at == revoked_at
    assert fetched_two.reuse_detected_at == revoked_at


def test_refresh_token_rotation_consumes_current_token_and_creates_replacement():
    database = DatabaseConnection(DSN)
    repository = PostgresSessionRepository(database, USER_A)

    session = _session(USER_A)
    repository.create_session(session)

    current = _refresh_token(session.id)
    repository.create_refresh_token(current)

    replacement = _refresh_token(session.id)
    consumed_at = datetime.now(timezone.utc)

    rotated = repository.rotate_refresh_token(
        current.id,
        replacement,
        consumed_at,
    )

    assert rotated == replacement

    current_after = repository.get_refresh_token_by_hash(
        current.token_hash
    )
    replacement_after = repository.get_refresh_token_by_hash(
        replacement.token_hash
    )

    assert current_after is not None
    assert current_after.consumed_at == consumed_at
    assert current_after.replaced_by_id == replacement.id

    assert replacement_after == replacement

    session_after = repository.get_session(session.id)

    assert session_after is not None
    assert session_after.last_used_at == consumed_at


def test_consumed_refresh_token_cannot_be_rotated_again():
    database = DatabaseConnection(DSN)
    repository = PostgresSessionRepository(database, USER_A)

    session = _session(USER_A)
    repository.create_session(session)

    current = _refresh_token(session.id)
    repository.create_refresh_token(current)

    first_replacement = _refresh_token(session.id)

    repository.rotate_refresh_token(
        current.id,
        first_replacement,
        datetime.now(timezone.utc),
    )

    second_replacement = _refresh_token(session.id)

    try:
        repository.rotate_refresh_token(
            current.id,
            second_replacement,
            datetime.now(timezone.utc),
        )
    except ValueError as exc:
        assert str(exc) == (
            "Refresh token has already been consumed."
        )
    else:
        raise AssertionError(
            "A consumed refresh token was rotated successfully."
        )

    assert (
        repository.get_refresh_token_by_hash(
            second_replacement.token_hash
        )
        is None
    )


def test_rotation_failure_rolls_back_replacement_insert():
    database = DatabaseConnection(DSN)
    repository = PostgresSessionRepository(database, USER_A)

    session = _session(USER_A)
    repository.create_session(session)

    current = _refresh_token(session.id)
    repository.create_refresh_token(current)

    replacement = _refresh_token(session.id)

    try:
        repository.rotate_refresh_token(
            current.id,
            replacement,
            current.issued_at - timedelta(seconds=1),
        )
    except psycopg.errors.CheckViolation:
        pass
    else:
        raise AssertionError(
            "Invalid rotation timestamp was not rejected."
        )

    current_after = repository.get_refresh_token_by_hash(
        current.token_hash
    )
    replacement_after = repository.get_refresh_token_by_hash(
        replacement.token_hash
    )

    assert current_after is not None
    assert current_after.consumed_at is None
    assert current_after.replaced_by_id is None
    assert replacement_after is None


def test_cross_user_refresh_token_rotation_is_hidden_by_rls():
    database = DatabaseConnection(DSN)

    session = _session(USER_A)

    repository_a = PostgresSessionRepository(database, USER_A)
    repository_b = PostgresSessionRepository(database, USER_B)

    repository_a.create_session(session)

    token = _refresh_token(session.id)
    repository_a.create_refresh_token(token)

    replacement = _refresh_token(session.id)

    try:
        try:
            repository_b.rotate_refresh_token(
                token.id,
                replacement,
                datetime.now(timezone.utc),
            )
        except LookupError:
            pass
        else:
            raise AssertionError(
                "Cross-user refresh-token rotation was not "
                "blocked by RLS."
            )
    finally:
        repository_a.revoke_session(
            session.id,
            datetime.now(timezone.utc),
        )


def test_same_user_can_touch_session():
    database = DatabaseConnection(DSN)
    repository = PostgresSessionRepository(database, USER_A)

    session = _session(USER_A)
    repository.create_session(session)

    last_used_at = datetime.now(timezone.utc)

    touched = repository.touch_session(
        session.id,
        last_used_at,
    )

    assert touched.last_used_at == last_used_at

    fetched = repository.get_session(session.id)

    assert fetched is not None
    assert fetched.last_used_at == last_used_at

    repository.revoke_session(
        session.id,
        datetime.now(timezone.utc),
    )


def test_cross_user_touch_session_is_hidden_by_rls():
    database = DatabaseConnection(DSN)

    session = _session(USER_A)

    repository_a = PostgresSessionRepository(database, USER_A)
    repository_b = PostgresSessionRepository(database, USER_B)

    repository_a.create_session(session)

    try:
        try:
            repository_b.touch_session(
                session.id,
                datetime.now(timezone.utc),
            )
        except LookupError:
            pass
        else:
            raise AssertionError(
                "Cross-user session touch was not blocked by RLS."
            )
    finally:
        repository_a.revoke_session(
            session.id,
            datetime.now(timezone.utc),
        )


def test_cross_user_revoke_session_is_hidden_by_rls():
    database = DatabaseConnection(DSN)

    session = _session(USER_A)

    repository_a = PostgresSessionRepository(database, USER_A)
    repository_b = PostgresSessionRepository(database, USER_B)

    repository_a.create_session(session)

    try:
        try:
            repository_b.revoke_session(
                session.id,
                datetime.now(timezone.utc),
            )
        except LookupError:
            pass
        else:
            raise AssertionError(
                "Cross-user session revoke was not blocked by RLS."
            )

        fetched = repository_a.get_session(session.id)

        assert fetched is not None
        assert fetched.revoked_at is None
    finally:
        repository_a.revoke_session(
            session.id,
            datetime.now(timezone.utc),
        )


def test_cross_user_token_family_revocation_cannot_affect_other_user():
    database = DatabaseConnection(DSN)

    family_id = uuid4()

    session_a = _session(
        USER_A,
        token_family_id=family_id,
    )
    session_b = _session(
        USER_B,
        token_family_id=family_id,
    )

    repository_a = PostgresSessionRepository(database, USER_A)
    repository_b = PostgresSessionRepository(database, USER_B)

    repository_a.create_session(session_a)
    repository_b.create_session(session_b)

    revoked_at = datetime.now(timezone.utc)

    try:
        affected = repository_a.revoke_token_family(
            family_id,
            revoked_at,
            revoked_at,
        )

        assert affected == 1

        session_a_after = repository_a.get_session(
            session_a.id
        )
        session_b_after = repository_b.get_session(
            session_b.id
        )

        assert session_a_after is not None
        assert session_a_after.revoked_at == revoked_at

        assert session_b_after is not None
        assert session_b_after.revoked_at is None
        assert session_b_after.reuse_detected_at is None
    finally:
        repository_a.revoke_session(
            session_a.id,
            datetime.now(timezone.utc),
        )
        repository_b.revoke_session(
            session_b.id,
            datetime.now(timezone.utc),
        )


def test_cross_user_refresh_token_creation_is_rejected_by_rls():
    database = DatabaseConnection(DSN)

    session = _session(USER_A)

    repository_a = PostgresSessionRepository(database, USER_A)
    repository_b = PostgresSessionRepository(database, USER_B)

    repository_a.create_session(session)

    token = _refresh_token(session.id)

    try:
        try:
            repository_b.create_refresh_token(token)
        except psycopg.errors.InsufficientPrivilege:
            return

        raise AssertionError(
            "Cross-user refresh-token INSERT was not rejected by RLS."
        )
    finally:
        repository_a.revoke_session(
            session.id,
            datetime.now(timezone.utc),
        )


def test_rotation_rejects_replacement_from_different_session():
    database = DatabaseConnection(DSN)
    repository = PostgresSessionRepository(database, USER_A)

    session_one = _session(USER_A)
    session_two = _session(USER_A)

    repository.create_session(session_one)
    repository.create_session(session_two)

    current = _refresh_token(session_one.id)
    repository.create_refresh_token(current)

    replacement = _refresh_token(session_two.id)

    try:
        repository.rotate_refresh_token(
            current.id,
            replacement,
            datetime.now(timezone.utc),
        )
    except ValueError as exc:
        assert str(exc) == (
            "Replacement token must belong "
            "to the same session."
        )
    else:
        raise AssertionError(
            "Rotation accepted a replacement from another session."
        )

    current_after = repository.get_refresh_token_by_hash(
        current.token_hash
    )

    replacement_after = repository.get_refresh_token_by_hash(
        replacement.token_hash
    )

    assert current_after is not None
    assert current_after.consumed_at is None
    assert current_after.replaced_by_id is None
    assert replacement_after is None

    repository.revoke_session(
        session_one.id,
        datetime.now(timezone.utc),
    )

    repository.revoke_session(
        session_two.id,
        datetime.now(timezone.utc),
    )

def test_rotation_of_nonexistent_refresh_token_raises_lookup_error():
    database = DatabaseConnection(DSN)
    repository = PostgresSessionRepository(database, USER_A)

    session = _session(USER_A)
    repository.create_session(session)

    replacement = _refresh_token(session.id)

    try:
        repository.rotate_refresh_token(
            uuid4(),
            replacement,
            datetime.now(timezone.utc),
        )
    except LookupError:
        pass
    else:
        raise AssertionError(
            "Rotation of a nonexistent refresh token did not fail."
        )

    replacement_after = repository.get_refresh_token_by_hash(
        replacement.token_hash
    )

    assert replacement_after is None

    repository.revoke_session(
        session.id,
        datetime.now(timezone.utc),
    )
