from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from uuid import UUID, uuid4

from backend.models.memory import (
    MemoryProvenance,
    MemorySensitivity,
    MemoryType,
)


@dataclass(frozen=True)
class MemoryCandidate:
    """
    Untrusted proposal for a potential durable memory.

    A MemoryCandidate is NOT durable memory and has no authority.
    It cannot grant permissions, authorize tools, authenticate users,
    or directly persist itself.

    Ownership comes from authenticated application identity and is
    represented separately from AI-generated content.
    """

    authenticated_user_id: UUID
    memory_type: MemoryType
    content: str
    provenance: MemoryProvenance

    confidence: float = 0.0
    sensitivity: MemorySensitivity = MemorySensitivity.INTERNAL

    id: UUID = field(default_factory=uuid4)
    created_at: datetime = field(
        default_factory=lambda: datetime.now(timezone.utc)
    )

    def __post_init__(self) -> None:
        self._validate()

    def _validate(self) -> None:
        if not self.content.strip():
            raise ValueError("Memory candidate content cannot be empty.")

        if len(self.content) > 2000:
            raise ValueError(
                "Memory candidate content cannot exceed 2000 characters."
            )

        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError(
                "Memory candidate confidence must be between 0.0 and 1.0."
            )

        if self.created_at.tzinfo is None:
            raise ValueError(
                "Memory candidate created_at must be timezone-aware."
            )
