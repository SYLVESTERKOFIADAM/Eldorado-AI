from __future__ import annotations

from uuid import UUID

from backend.models.memory import (
    MemoryProvenance,
    MemoryRecord,
    MemoryStatus,
    MemoryType,
)
from backend.repositories.memory_repository import MemoryRepository
from backend.security.authenticated_user import AuthenticatedUser
from backend.services.memory_policy import MemoryPolicy


class MemoryService:
    """
    Application service for controlled memory operations.

    Security principles:
    - AuthenticatedUser establishes the application identity.
    - Memory ownership is derived from authenticated identity.
    - Memory never grants authorization.
    - Lifecycle state is enforced before retrieval.
    - Policy decisions are centralized in MemoryPolicy.
    - Repository access is abstracted from the service.
    """

    def __init__(self, repository: MemoryRepository):
        self._repository = repository
        self._policy = MemoryPolicy()

    def create_memory(
        self,
        *,
        authenticated_user: AuthenticatedUser,
        memory_type: MemoryType,
        content: str,
        provenance: MemoryProvenance,
    ) -> MemoryRecord:
        memory = MemoryRecord(
            user_id=authenticated_user.user_id,
            memory_type=memory_type,
            content=content,
            provenance=provenance,
        )

        decision = self._policy.evaluate(memory)

        if not decision.allowed:
            raise ValueError(decision.reason)

        return self._repository.save(memory)

    def get_memory(
        self,
        *,
        memory_id: UUID,
        authenticated_user: AuthenticatedUser,
    ) -> MemoryRecord:
        memory = self._repository.get(memory_id)

        if memory is None:
            raise LookupError("Memory was not found.")

        if memory.user_id != authenticated_user.user_id:
            raise PermissionError(
                "User is not authorized to access this memory."
            )

        decision = self._policy.evaluate(memory)

        if not decision.allowed:
            raise LookupError(decision.reason)

        return memory

    def approve_memory(
        self,
        *,
        memory_id: UUID,
        authenticated_user: AuthenticatedUser,
    ) -> MemoryRecord:
        memory = self._repository.get(memory_id)

        if memory is None:
            raise LookupError("Memory was not found.")

        if memory.user_id != authenticated_user.user_id:
            raise PermissionError(
                "User is not authorized to modify this memory."
            )

        if memory.status == MemoryStatus.QUARANTINED:
            raise ValueError("Quarantined memory cannot be approved.")

        if memory.status in {
            MemoryStatus.DELETED,
            MemoryStatus.SUPERSEDED,
            MemoryStatus.EXPIRED,
        }:
            raise ValueError("Inactive memory cannot be approved.")

        memory.approve()

        decision = self._policy.evaluate(memory)

        if not decision.allowed:
            raise ValueError(decision.reason)

        return self._repository.save(memory)

    def delete_memory(
        self,
        *,
        memory_id: UUID,
        authenticated_user: AuthenticatedUser,
    ) -> MemoryRecord:
        memory = self._repository.get(memory_id)

        if memory is None:
            raise LookupError("Memory was not found.")

        if memory.user_id != authenticated_user.user_id:
            raise PermissionError(
                "User is not authorized to modify this memory."
            )

        memory.delete()

        return self._repository.save(memory)

    def quarantine_memory(
        self,
        *,
        memory_id: UUID,
        authenticated_user: AuthenticatedUser,
    ) -> MemoryRecord:
        memory = self._repository.get(memory_id)

        if memory is None:
            raise LookupError("Memory was not found.")

        if memory.user_id != authenticated_user.user_id:
            raise PermissionError(
                "User is not authorized to modify this memory."
            )

        memory.quarantine()

        return self._repository.save(memory)
