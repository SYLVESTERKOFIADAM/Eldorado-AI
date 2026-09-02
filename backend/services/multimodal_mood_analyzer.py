from __future__ import annotations

from abc import ABC, abstractmethod

from backend.models.interaction_state import InteractionState


class MultimodalMoodAnalyzer(ABC):
    """
    Security boundary for combining independent mood observations.

    The fusion layer produces a temporary interaction-state observation.

    This interface must never:
    - authenticate a user,
    - identify a speaker,
    - grant permissions,
    - authorize tools,
    - modify memory,
    - modify security policy,
    - persist raw audio.
    """

    @abstractmethod
    def analyze(
        self,
        text_state: InteractionState | None,
        voice_state: InteractionState | None,
    ) -> InteractionState:
        """
        Fuse text and voice observations into one interaction state.
        """
        raise NotImplementedError
