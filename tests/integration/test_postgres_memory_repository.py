from uuid import UUID, uuid4

import psycopg
import pytest

from backend.database.connection import DatabaseConnection
from backend.models.memory import (
    MemoryProvenance,
    MemoryRecord,
    MemorySensitivity,
    MemoryStatus,
    MemoryType,
)
from backend.repositories.postgres_memory_repository import (
    PostgresMemoryRepository,
)


DSN = "dbname=postgres user=eldorado_app host=localhost port=5432"

USER_A = UUID("76bab0d0-94f5-4925-a729-62e31726456f")
USER_B = UUID("dd0939fc-c93a-4f20-93de-3c1d6c88804f")

MEMORY_A = UUID("d6f6e0cb-cf12-489f-8635-afa669f570da")
MEMORY_B = UUID("04fc10e5-ca9a-4fc9-bba1-7a19ac184f55")


def make_repository(user_id: UUID) -> PostgresMemoryRepository:
    database = DatabaseConnection(DSN)
    return PostgresMemoryRepository(database, user_id)


def test_get_returns_own_memory():
    repository = make_repository(USER_A)

    memory = repository.get(MEMORY_A)

    assert memory is not None
    assert memory.id == MEMORY_A
    assert memory.user_id == USER_A
    assert memory.content == "PRIVATE MEMORY FOR TEST USER A"


def test_get_cannot_read_other_users_memory():
    repository = make_repository(USER_A)

    memory = repository.get(MEMORY_B)

    assert memory is None


def test_list_by_user_returns_only_rows_visible_to_authenticated_user():
    repository = make_repository(USER_A)

    memories = repository.list_by_user(USER_A)

    assert len(memories) == 1
    assert memories[0].id == MEMORY_A
    assert memories[0].user_id == USER_A


def test_list_by_user_cannot_bypass_rls():
    repository = make_repository(USER_A)

    memories = repository.list_by_user(USER_B)

    assert memories == []


def test_save_round_trip():
    repository = make_repository(USER_A)

    memory_id = uuid4()

    memory = MemoryRecord(
        id=memory_id,
        user_id=USER_A,
        memory_type=MemoryType.PREFERENCE,
        content="POSTGRES REPOSITORY ROUND TRIP TEST",
        provenance=MemoryProvenance.EXPLICIT_USER_STATEMENT,
        confidence=0.85,
        sensitivity=MemorySensitivity.INTERNAL,
        status=MemoryStatus.CANDIDATE,
        user_approved=False,
    )

    saved = repository.save(memory)

    try:
        assert saved.id == memory.id
        assert saved.user_id == USER_A
        assert saved.memory_type == MemoryType.PREFERENCE
        assert saved.content == memory.content
        assert saved.provenance == MemoryProvenance.EXPLICIT_USER_STATEMENT
        assert saved.confidence == 0.85
        assert saved.sensitivity == MemorySensitivity.INTERNAL
        assert saved.status == MemoryStatus.CANDIDATE
        assert saved.user_approved is False
    finally:
        repository.delete(memory_id)


def test_save_cannot_insert_memory_for_another_user():
    repository = make_repository(USER_A)

    memory = MemoryRecord(
        user_id=USER_B,
        memory_type=MemoryType.PREFERENCE,
        content="CROSS USER REPOSITORY INSERT TEST",
        provenance=MemoryProvenance.EXPLICIT_USER_STATEMENT,
        status=MemoryStatus.ACTIVE,
        user_approved=True,
    )

    with pytest.raises(psycopg.errors.InsufficientPrivilege):
        repository.save(memory)


def test_delete_own_memory():
    repository = make_repository(USER_A)

    memory_id = uuid4()

    memory = MemoryRecord(
        id=memory_id,
        user_id=USER_A,
        memory_type=MemoryType.TEMPORARY,
        content="DELETE REPOSITORY TEST",
        provenance=MemoryProvenance.EXPLICIT_USER_STATEMENT,
    )

    repository.save(memory)

    try:
        assert repository.get(memory_id) is not None

        repository.delete(memory_id)

        assert repository.get(memory_id) is None
    finally:
        repository.delete(memory_id)


def test_delete_other_users_memory_does_nothing():
    repository = make_repository(USER_A)

    repository.delete(MEMORY_B)

    verifier = make_repository(USER_B)

    memory = verifier.get(MEMORY_B)

    assert memory is not None
    assert memory.id == MEMORY_B
    assert memory.user_id == USER_B


def test_save_preserves_optional_timestamps():
    repository = make_repository(USER_A)

    memory_id = uuid4()

    memory = MemoryRecord(
        id=memory_id,
        user_id=USER_A,
        memory_type=MemoryType.EPISODIC,
        content="TIMESTAMP ROUND TRIP TEST",
        provenance=MemoryProvenance.CONVERSATION_INFERENCE,
        last_used_at=None,
        expires_at=None,
    )

    saved = repository.save(memory)

    try:
        assert saved.created_at == memory.created_at
        assert saved.updated_at == memory.updated_at
        assert saved.last_used_at is None
        assert saved.expires_at is None
    finally:
        repository.delete(memory_id)


def test_transaction_rollback_removes_unsaved_memory():
    database = DatabaseConnection(DSN)
    repository = PostgresMemoryRepository(database, USER_A)

    memory_id = uuid4()

    memory = MemoryRecord(
        id=memory_id,
        user_id=USER_A,
        memory_type=MemoryType.TEMPORARY,
        content="ROLLBACK REPOSITORY TEST",
        provenance=MemoryProvenance.EXPLICIT_USER_STATEMENT,
    )

    with pytest.raises(RuntimeError, match="ROLLBACK_REPOSITORY_TEST"):
        with database.transaction(USER_A) as connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    """
                    INSERT INTO memories (
                        id,
                        user_id,
                        memory_type,
                        content,
                        provenance,
                        confidence,
                        sensitivity,
                        status,
                        user_approved,
                        created_at,
                        updated_at,
                        last_used_at,
                        expires_at
                    )
                    VALUES (
                        %s, %s, %s, %s, %s, %s, %s, %s,
                        %s, %s, %s, %s, %s
                    )
                    """,
                    (
                        memory.id,
                        memory.user_id,
                        memory.memory_type.value,
                        memory.content,
                        memory.provenance.value,
                        memory.confidence,
                        memory.sensitivity.value,
                        memory.status.value,
                        memory.user_approved,
                        memory.created_at,
                        memory.updated_at,
                        memory.last_used_at,
                        memory.expires_at,
                    ),
                )

            raise RuntimeError("ROLLBACK_REPOSITORY_TEST")

    assert repository.get(memory_id) is None