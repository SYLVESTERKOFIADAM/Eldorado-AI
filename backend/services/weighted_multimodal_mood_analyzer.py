from __future__ import annotations

from datetime import datetime, timedelta, timezone

from backend.models.interaction_state import (
    DetectionSource,
    EmotionalState,
    InteractionState,
)
from backend.security.authenticated_user import AuthenticatedUser
from backend.services.multimodal_mood_analyzer import MultimodalMoodAnalyzer


class WeightedMultimodalMoodAnalyzer(MultimodalMoodAnalyzer):
    """
    Conservative late-fusion analyzer for text and voice mood observations.

    Security properties:
    - Only observations belonging to the authenticated user are accepted.
    - Expired observations are ignored.
    - Mood inference never authenticates or authorizes.
    - No memory is written.
    - No raw audio is processed or persisted.
    - Conflicting evidence produces UNKNOWN unless one modality
      clearly dominates.
    """

    DEFAULT_TEXT_WEIGHT = 0.55
    DEFAULT_VOICE_WEIGHT = 0.45

    MIN_CONFIDENCE = 0.60
    MIN_DOMINANCE_MARGIN = 0.15
    DEFAULT_STATE_TTL_SECONDS = 60

    def __init__(
        self,
        authenticated_user: AuthenticatedUser,
        text_weight: float = DEFAULT_TEXT_WEIGHT,
        voice_weight: float = DEFAULT_VOICE_WEIGHT,
    ) -> None:
        if not authenticated_user.user_id:
            raise PermissionError("Authenticated user is required.")

        if text_weight < 0 or voice_weight < 0:
            raise ValueError("Fusion weights cannot be negative.")

        if text_weight + voice_weight <= 0:
            raise ValueError("At least one fusion weight must be positive.")

        self._authenticated_user = authenticated_user

        total = text_weight + voice_weight
        self._text_weight = text_weight / total
        self._voice_weight = voice_weight / total

    def analyze(
        self,
        text_state: InteractionState | None,
        voice_state: InteractionState | None,
    ) -> InteractionState:
        """
        Fuse available text and voice observations.

        Invalid, expired, or cross-user observations are rejected rather
        than silently incorporated into the result.
        """
        text_state = self._validate_observation(text_state)
        voice_state = self._validate_observation(voice_state)

        if text_state is None and voice_state is None:
            return self._unknown_state()

        if text_state is None:
            return self._single_modality_state(voice_state)

        if voice_state is None:
            return self._single_modality_state(text_state)

        scores: dict[EmotionalState, float] = {}

        self._add_score(
            scores,
            text_state,
            self._text_weight,
        )

        self._add_score(
            scores,
            voice_state,
            self._voice_weight,
        )

        ranked = sorted(
            scores.items(),
            key=lambda item: item[1],
            reverse=True,
        )

        winning_state, winning_score = ranked[0]

        if len(ranked) > 1:
            _, second_score = ranked[1]
            dominance_margin = winning_score - second_score

            if dominance_margin < self.MIN_DOMINANCE_MARGIN:
                return self._unknown_state()

            combined_evidence = winning_score + second_score
        else:
            combined_evidence = winning_score

        if combined_evidence < self.MIN_CONFIDENCE:
            return self._unknown_state()

        return self._build_state(
            emotional_state=winning_state,
            confidence=min(combined_evidence, 1.0),
        )

    def _validate_observation(
        self,
        state: InteractionState | None,
    ) -> InteractionState | None:
        if state is None:
            return None

        if state.user_id != self._authenticated_user.user_id:
            raise PermissionError(
                "Interaction state belongs to another user."
            )

        if state.is_expired:
            return None

        if state.confidence < 0.0 or state.confidence > 1.0:
            raise ValueError("Interaction confidence must be between 0 and 1.")

        if state.confidence < self.MIN_CONFIDENCE:
            return None

        return state

    @staticmethod
    def _add_score(
        scores: dict[EmotionalState, float],
        state: InteractionState,
        weight: float,
    ) -> None:
        scores[state.emotional_state] = (
            scores.get(state.emotional_state, 0.0)
            + (state.confidence * weight)
        )

    def _single_modality_state(
        self,
        state: InteractionState,
    ) -> InteractionState:
        return self._build_state(
            emotional_state=state.emotional_state,
            confidence=state.confidence,
        )

    def _unknown_state(self) -> InteractionState:
        return self._build_state(
            emotional_state=EmotionalState.UNKNOWN,
            confidence=0.0,
        )

    def _build_state(
        self,
        emotional_state: EmotionalState,
        confidence: float,
    ) -> InteractionState:
        now = datetime.now(timezone.utc)

        return InteractionState(
            user_id=self._authenticated_user.user_id,
            emotional_state=emotional_state,
            confidence=confidence,
            source=DetectionSource.MULTIMODAL,
            observed_at=now,
            expires_at=now
            + timedelta(seconds=self.DEFAULT_STATE_TTL_SECONDS),
        )
