from __future__ import annotations

from abc import ABC, abstractmethod
from uuid import UUID

from backend.models.memory import MemoryRecord


class MemoryRepository(ABC):
    """
    Persistence boundary for Eldorado-AI memory.

    The memory service depends on this interface rather than a
    specific database implementation.

    Security rule:
    Repository methods must preserve user ownership boundaries.
    Persistence must never turn memory into authorization.
    """

    @abstractmethod
    def save(self, memory: MemoryRecord) -> MemoryRecord:
        """Persist a memory record and return the stored record."""
        raise NotImplementedError

    @abstractmethod
    def get(self, memory_id: UUID) -> MemoryRecord | None:
        """Return a memory by ID, or None if it does not exist."""
        raise NotImplementedError

    @abstractmethod
    def list_by_user(self, user_id: UUID) -> list[MemoryRecord]:
        """Return memory records belonging to the specified user."""
        raise NotImplementedError

    @abstractmethod
    def delete(self, memory_id: UUID) -> None:
        """Remove a memory from the persistence layer."""
        raise NotImplementedError