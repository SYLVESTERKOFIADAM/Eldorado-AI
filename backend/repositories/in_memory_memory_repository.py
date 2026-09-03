from __future__ import annotations

from uuid import UUID

from backend.models.memory import MemoryRecord
from backend.repositories.memory_repository import MemoryRepository


class InMemoryMemoryRepository(MemoryRepository):
    """
    In-memory repository used for tests and local development.

    Production persistence uses PostgreSQL with database-level isolation.
    """

    def __init__(self) -> None:
        self._memories: dict[UUID, MemoryRecord] = {}

    def save(self, memory: MemoryRecord) -> MemoryRecord:
        self._memories[memory.id] = memory
        return memory

    def get(self, memory_id: UUID) -> MemoryRecord | None:
        return self._memories.get(memory_id)

    def update(self, memory: MemoryRecord) -> MemoryRecord:
        if memory.id not in self._memories:
            raise LookupError("Memory was not found.")

        self._memories[memory.id] = memory
        return memory

    def list_by_user(self, user_id: UUID) -> list[MemoryRecord]:
        return [
            memory
            for memory in self._memories.values()
            if memory.user_id == user_id
        ]

    def delete(self, memory_id: UUID) -> None:
        self._memories.pop(memory_id, None)
