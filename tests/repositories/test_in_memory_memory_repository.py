from uuid import uuid4

from backend.models.memory import (
    MemoryProvenance,
    MemoryType,
    MemoryRecord,
)
from backend.repositories.in_memory_memory_repository import (
    InMemoryMemoryRepository,
)


def create_test_memory(*, user_id=None, content="Test memory."):
    return MemoryRecord(
        user_id=user_id or uuid4(),
        memory_type=MemoryType.PREFERENCE,
        content=content,
        provenance=MemoryProvenance.EXPLICIT_USER_STATEMENT,
    )


def test_save_stores_and_returns_memory():
    repository = InMemoryMemoryRepository()
    memory = create_test_memory()

    saved = repository.save(memory)

    assert saved == memory
    assert repository.get(memory.id) == memory


def test_get_returns_none_for_unknown_memory():
    repository = InMemoryMemoryRepository()

    result = repository.get(uuid4())

    assert result is None


def test_list_by_user_returns_only_that_users_memories():
    repository = InMemoryMemoryRepository()

    user_a = uuid4()
    user_b = uuid4()

    memory_a1 = create_test_memory(user_id=user_a, content="A1")
    memory_a2 = create_test_memory(user_id=user_a, content="A2")
    memory_b1 = create_test_memory(user_id=user_b, content="B1")

    repository.save(memory_a1)
    repository.save(memory_a2)
    repository.save(memory_b1)

    user_a_memories = repository.list_by_user(user_a)

    assert user_a_memories == [memory_a1, memory_a2]


def test_list_by_user_returns_empty_list_for_unknown_user():
    repository = InMemoryMemoryRepository()

    memory = create_test_memory()
    repository.save(memory)

    result = repository.list_by_user(uuid4())

    assert result == []


def test_delete_removes_memory():
    repository = InMemoryMemoryRepository()
    memory = create_test_memory()

    repository.save(memory)
    repository.delete(memory.id)

    assert repository.get(memory.id) is None


def test_delete_nonexistent_memory_is_safe():
    repository = InMemoryMemoryRepository()

    repository.delete(uuid4())


def test_multiple_users_remain_isolated():
    repository = InMemoryMemoryRepository()

    user_a = uuid4()
    user_b = uuid4()

    memory_a = create_test_memory(
        user_id=user_a,
        content="Private memory A",
    )
    memory_b = create_test_memory(
        user_id=user_b,
        content="Private memory B",
    )

    repository.save(memory_a)
    repository.save(memory_b)

    assert repository.list_by_user(user_a) == [memory_a]
    assert repository.list_by_user(user_b) == [memory_b]