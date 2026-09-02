from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Optional
from uuid import UUID, uuid4


class MemoryType(str, Enum):
    PROFILE = "profile"
    PREFERENCE = "preference"
    EPISODIC = "episodic"
    FEEDBACK = "feedback"
    PROJECT = "project"
    TEMPORARY = "temporary"


class MemoryStatus(str, Enum):
    CANDIDATE = "candidate"
    ACTIVE = "active"
    SUPERSEDED = "superseded"
    DELETED = "deleted"
    EXPIRED = "expired"
    QUARANTINED = "quarantined"


class MemoryProvenance(str, Enum):
    EXPLICIT_USER_STATEMENT = "explicit_user_statement"
    USER_FEEDBACK = "user_feedback"
    CONVERSATION_INFERENCE = "conversation_inference"
    IMPORTED_DATA = "imported_data"
    EXTERNAL_CONTENT = "external_content"


class MemorySensitivity(str, Enum):
    PUBLIC = "public"
    INTERNAL = "internal"
    SENSITIVE = "sensitive"
    RESTRICTED = "restricted"


@dataclass
class MemoryRecord:
    """
    Domain representation of a single Eldorado memory.

    Memory is personalization data, not an authorization mechanism.
    This model intentionally contains no permission or capability fields.
    """

    user_id: UUID
    memory_type: MemoryType
    content: str
    provenance: MemoryProvenance

    confidence: float = 0.0
    sensitivity: MemorySensitivity = MemorySensitivity.INTERNAL
    status: MemoryStatus = MemoryStatus.CANDIDATE

    user_approved: bool = False

    id: UUID = field(default_factory=uuid4)

    created_at: datetime = field(
        default_factory=lambda: datetime.now(timezone.utc)
    )
    updated_at: datetime = field(
        default_factory=lambda: datetime.now(timezone.utc)
    )
    last_used_at: Optional[datetime] = None
    expires_at: Optional[datetime] = None

    def __post_init__(self) -> None:
        self._validate()

    def _validate(self) -> None:
        if not self.content.strip():
            raise ValueError("Memory content cannot be empty.")

        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError("Memory confidence must be between 0.0 and 1.0.")

        if self.created_at.tzinfo is None:
            raise ValueError("created_at must be timezone-aware.")

        if self.updated_at.tzinfo is None:
            raise ValueError("updated_at must be timezone-aware.")

        if self.last_used_at is not None and self.last_used_at.tzinfo is None:
            raise ValueError("last_used_at must be timezone-aware.")

        if self.expires_at is not None and self.expires_at.tzinfo is None:
            raise ValueError("expires_at must be timezone-aware.")

        if self.status == MemoryStatus.ACTIVE and not self.user_approved:
            if self.provenance in {
                MemoryProvenance.EXTERNAL_CONTENT,
                MemoryProvenance.IMPORTED_DATA,
            }:
                raise ValueError(
                    "External or imported memory cannot become active "
                    "without explicit user approval."
                )

    @property
    def is_expired(self) -> bool:
        if self.expires_at is None:
            return False

        return datetime.now(timezone.utc) >= self.expires_at

    def approve(self) -> None:
        """
        Explicitly approve this memory for normal use.

        Approval changes memory lifecycle state only.
        It does not grant permissions or authorize tools.
        """
        self.user_approved = True
        self.status = MemoryStatus.ACTIVE
        self.updated_at = datetime.now(timezone.utc)

    def supersede(self) -> None:
        self.status = MemoryStatus.SUPERSEDED
        self.updated_at = datetime.now(timezone.utc)

    def delete(self) -> None:
        self.status = MemoryStatus.DELETED
        self.updated_at = datetime.now(timezone.utc)

    def quarantine(self) -> None:
        self.status = MemoryStatus.QUARANTINED
        self.updated_at = datetime.now(timezone.utc)

    def mark_used(self) -> None:
        now = datetime.now(timezone.utc)
        self.last_used_at = now
        self.updated_at = now