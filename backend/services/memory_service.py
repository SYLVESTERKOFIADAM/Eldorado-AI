from __future__ import annotations

from uuid import UUID

from backend.models.memory import (
    MemoryProvenance,
    MemoryRecord,
    MemorySensitivity,
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
        confidence: float = 0.0,
        sensitivity: MemorySensitivity = MemorySensitivity.INTERNAL,
    ) -> MemoryRecord:
        memory = MemoryRecord(
            user_id=authenticated_user.user_id,
            memory_type=memory_type,
            content=content,
            provenance=provenance,
            confidence=confidence,
            sensitivity=sensitivity,
        )

        decision = self._policy.evaluate(memory)

        if not decision.allowed:
            raise ValueError(decision.reason)

        return self._repository.save(memory)

    def list_active_memories(
        self,
        *,
        memory_type: MemoryType,
        authenticated_user: AuthenticatedUser,
    ) -> list[MemoryRecord]:
        """
        Return active memories of one type belonging to the authenticated user.

        Memory retrieval remains ownership-bound and lifecycle-aware.
        Memory contents never grant permissions or tool capabilities.
        """
        memories = self._repository.list_by_user(
            authenticated_user.user_id
        )

        return [
            memory
            for memory in memories
            if memory.memory_type == memory_type
            and memory.status == MemoryStatus.ACTIVE
            and not memory.is_expired
        ]

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

        if memory.status == MemoryStatus.ACTIVE:
            raise ValueError("Memory is already active.")

        if memory.status == MemoryStatus.QUARANTINED:
            raise ValueError("Quarantined memory cannot be approved.")

        if memory.status in {
            MemoryStatus.DELETED,
            MemoryStatus.SUPERSEDED,
            MemoryStatus.EXPIRED,
        }:
            raise ValueError("Inactive memory cannot be approved.")

        if memory.status != MemoryStatus.CANDIDATE:
            raise ValueError("Only candidate memory can be approved.")

        if (
            memory.provenance == MemoryProvenance.CONVERSATION_INFERENCE
            and memory.sensitivity
            in {
                MemorySensitivity.SENSITIVE,
                MemorySensitivity.RESTRICTED,
            }
        ):
            raise ValueError(
                "Sensitive inferred memory cannot be approved directly."
            )

        decision = self._policy.evaluate(memory)

        if not decision.allowed:
            raise ValueError(decision.reason)

        memory.approve()

        return self._repository.update(memory)

    def supersede_memory(
        self,
        *,
        memory_id: UUID,
        authenticated_user: AuthenticatedUser,
    ) -> MemoryRecord:
        """
        Mark an owned memory as superseded.

        Superseding changes lifecycle state only. It does not grant
        permissions, authorize tools, authenticate users, or change
        security policy.
        """
        memory = self._repository.get(memory_id)

        if memory is None:
            raise LookupError("Memory was not found.")

        if memory.user_id != authenticated_user.user_id:
            raise PermissionError(
                "User is not authorized to modify this memory."
            )

        if memory.status == MemoryStatus.SUPERSEDED:
            raise ValueError("Memory is already superseded.")

        if memory.status in {
            MemoryStatus.DELETED,
            MemoryStatus.EXPIRED,
        }:
            raise ValueError("Inactive memory cannot be superseded.")

        memory.supersede()

        return self._repository.update(memory)

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

        return self._repository.update(memory)

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

        return self._repository.update(memory)
