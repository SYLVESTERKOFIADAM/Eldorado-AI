from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from math import isfinite
from typing import Optional
from uuid import UUID, uuid4


@dataclass
class VoiceFeatures:
    """
    Temporary acoustic features extracted from a voice interaction.

    This model contains derived features only. It does not store raw audio,
    speaker identity templates, or authentication credentials.

    Voice features are observational signals and must not be treated as
    proof of emotional state, identity, authorization, or intent.
    """

    user_id: UUID

    mean_pitch_hz: Optional[float] = None
    pitch_range_hz: Optional[float] = None
    mean_intensity_db: Optional[float] = None
    speech_rate_wpm: Optional[float] = None
    pause_ratio: Optional[float] = None

    confidence: float = 0.0

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
                "Voice feature confidence must be between 0.0 and 1.0."
            )

        if self.observed_at.tzinfo is None:
            raise ValueError("observed_at must be timezone-aware.")

        if self.expires_at is not None and self.expires_at.tzinfo is None:
            raise ValueError("expires_at must be timezone-aware.")

        if self.mean_pitch_hz is not None:
            self._validate_non_negative(
                self.mean_pitch_hz,
                "mean_pitch_hz",
            )

        if self.pitch_range_hz is not None:
            self._validate_non_negative(
                self.pitch_range_hz,
                "pitch_range_hz",
            )

        if self.speech_rate_wpm is not None:
            self._validate_non_negative(
                self.speech_rate_wpm,
                "speech_rate_wpm",
            )

        if self.pause_ratio is not None:
            if not 0.0 <= self.pause_ratio <= 1.0:
                raise ValueError(
                    "pause_ratio must be between 0.0 and 1.0."
                )

        if (
            self.mean_pitch_hz is not None
            and self.pitch_range_hz is not None
            and self.pitch_range_hz > self.mean_pitch_hz
            and self.mean_pitch_hz > 0
        ):
            # A range greater than the mean can be valid, so this is
            # intentionally not rejected. The check above is retained
            # only to make the relationship explicit in the model.
            pass

        if self.mean_intensity_db is not None:
            if not isfinite(self.mean_intensity_db):
                raise ValueError(
                    "mean_intensity_db must be a finite number."
                )

    @staticmethod
    def _validate_non_negative(value: float, field_name: str) -> None:
        if not isfinite(value):
            raise ValueError(f"{field_name} must be a finite number.")

        if value < 0.0:
            raise ValueError(f"{field_name} cannot be negative.")

    @property
    def is_expired(self) -> bool:
        if self.expires_at is None:
            return False

        return datetime.now(timezone.utc) >= self.expires_at