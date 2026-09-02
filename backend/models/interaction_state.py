from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Optional
from uuid import UUID, uuid4


class EmotionalState(str, Enum):
    UNKNOWN = "unknown"
    CALM = "calm"
    HAPPY = "happy"
    EXCITED = "excited"
    FRUSTRATED = "frustrated"
    ANGRY = "angry"
    SAD = "sad"
    ANXIOUS = "anxious"
    CONFUSED = "confused"
    TIRED = "tired"
    URGENT = "urgent"


class DetectionSource(str, Enum):
    TEXT = "text"
    VOICE = "voice"
    MULTIMODAL = "multimodal"
    USER_REPORTED = "user_reported"


@dataclass
class InteractionState:
    """
    Temporary representation of the user's current interaction state.

    This is an observation, not a permanent user profile and not an
    authorization mechanism.
    """

    user_id: UUID
    emotional_state: EmotionalState = EmotionalState.UNKNOWN
    confidence: float = 0.0
    source: DetectionSource = DetectionSource.TEXT

    id: UUID = field(default_factory=uuid4)
    observed_at: datetime = field(
        default_factory=lambda: datetime.now(timezone.utc)
    )
    expires_at: Optional[datetime] = None

    def __post_init__(self) -> None:
        self._validate()

    def _validate(self) -> None:
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError(
                "Interaction state confidence must be between 0.0 and 1.0."
            )

        if self.observed_at.tzinfo is None:
            raise ValueError("observed_at must be timezone-aware.")

        if self.expires_at is not None and self.expires_at.tzinfo is None:
            raise ValueError("expires_at must be timezone-aware.")

    @property
    def is_expired(self) -> bool:
        if self.expires_at is None:
            return False

        return datetime.now(timezone.utc) >= self.expires_at