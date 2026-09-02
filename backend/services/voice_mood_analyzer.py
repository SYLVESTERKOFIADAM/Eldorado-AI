from __future__ import annotations

from abc import ABC, abstractmethod

from backend.models.interaction_state import InteractionState
from backend.models.voice_features import VoiceFeatures


class VoiceMoodAnalyzer(ABC):
    """
    Boundary for converting acoustic voice features into a temporary
    interaction-state observation.

    Implementations may use deterministic rules, local ML models, or
    external providers.

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
    def analyze(self, features: VoiceFeatures) -> InteractionState:
        """
        Convert validated voice features into a temporary interaction state.
        """
        raise NotImplementedError
