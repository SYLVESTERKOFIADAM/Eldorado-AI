from __future__ import annotations

from backend.models.interaction_state import (
    DetectionSource,
    EmotionalState,
    InteractionState,
)
from backend.models.voice_features import VoiceFeatures
from backend.security.authenticated_user import AuthenticatedUser
from backend.services.voice_mood_analyzer import VoiceMoodAnalyzer


class BaselineVoiceMoodAnalyzer(VoiceMoodAnalyzer):
    """
    Conservative rule-based baseline for voice mood estimation.

    This is intentionally not presented as a clinical or definitive
    emotion classifier. Acoustic signals are probabilistic indicators.

    The analyzer:
    - uses only derived VoiceFeatures,
    - preserves the trusted authenticated user identity,
    - produces temporary InteractionState,
    - never persists audio,
    - never authenticates or identifies the speaker,
    - never grants permissions or tool access.
    """

    def __init__(self, authenticated_user: AuthenticatedUser) -> None:
        self._authenticated_user = authenticated_user

    def analyze(self, features: VoiceFeatures) -> InteractionState:
        if features.user_id != self._authenticated_user.user_id:
            raise PermissionError(
                "Voice features do not belong to the authenticated user."
            )

        if features.is_expired:
            return InteractionState(
                user_id=self._authenticated_user.user_id,
                emotional_state=EmotionalState.UNKNOWN,
                confidence=0.0,
                source=DetectionSource.VOICE,
                observed_at=features.observed_at,
                expires_at=features.expires_at,
            )

        state, confidence = self._estimate(features)

        return InteractionState(
            user_id=self._authenticated_user.user_id,
            emotional_state=state,
            confidence=confidence,
            source=DetectionSource.VOICE,
            observed_at=features.observed_at,
            expires_at=features.expires_at,
        )

    @staticmethod
    def _estimate(
        features: VoiceFeatures,
    ) -> tuple[EmotionalState, float]:
        """
        Apply conservative acoustic heuristics.

        Higher pitch + higher intensity + faster speech can be consistent
        with heightened activation, but these signals are not sufficient
        to distinguish emotions reliably.
        """

        activation_score = 0.0
        evidence_count = 0

        if features.mean_pitch_hz is not None:
            if features.mean_pitch_hz >= 220.0:
                activation_score += 0.35
            elif features.mean_pitch_hz <= 130.0:
                activation_score -= 0.20
            evidence_count += 1

        if features.mean_intensity_db is not None:
            if features.mean_intensity_db >= 75.0:
                activation_score += 0.30
            evidence_count += 1

        if features.speech_rate_wpm is not None:
            if features.speech_rate_wpm >= 170.0:
                activation_score += 0.30
            elif features.speech_rate_wpm <= 90.0:
                activation_score -= 0.20
            evidence_count += 1

        if features.pause_ratio is not None:
            if features.pause_ratio >= 0.40:
                activation_score -= 0.15
            evidence_count += 1

        if evidence_count == 0:
            return EmotionalState.UNKNOWN, 0.0

        if activation_score >= 0.60:
            return EmotionalState.EXCITED, round(
                min(0.60 + activation_score * 0.40, 0.90),
                2,
            )

        if activation_score <= -0.25:
            return EmotionalState.CALM, round(
                min(0.60 + abs(activation_score) * 0.40, 0.85),
                2,
            )

        return EmotionalState.UNKNOWN, 0.50
