from __future__ import annotations

import re

from backend.models.interaction_state import (
    DetectionSource,
    EmotionalState,
    InteractionState,
)
from backend.security.authenticated_user import AuthenticatedUser


class MoodService:
    """
    Estimates the user's current interaction state from text.

    This service produces temporary observations. It does not create
    permanent memory and does not grant permissions or tool access.

    Identity comes exclusively from the trusted authentication context.
    """

    _SIGNALS: dict[EmotionalState, tuple[str, ...]] = {
        EmotionalState.FRUSTRATED: (
            "frustrated",
            "annoyed",
            "fed up",
            "this is ridiculous",
            "not working",
            "doesn't work",
            "does not work",
            "again",
            "properly",
        ),
        EmotionalState.ANGRY: (
            "angry",
            "furious",
            "damn",
            "hate this",
            "what the hell",
        ),
        EmotionalState.SAD: (
            "sad",
            "unhappy",
            "lonely",
            "hurt",
            "heartbroken",
            "depressed",
        ),
        EmotionalState.ANXIOUS: (
            "worried",
            "anxious",
            "nervous",
            "scared",
            "afraid",
            "panic",
        ),
        EmotionalState.CONFUSED: (
            "confused",
            "don't understand",
            "do not understand",
            "what does this mean",
            "i don't get it",
            "i do not get it",
        ),
        EmotionalState.EXCITED: (
            "excited",
            "amazing",
            "awesome",
            "can't wait",
            "cannot wait",
        ),
        EmotionalState.HAPPY: (
            "happy",
            "glad",
            "great",
            "love this",
            "thank you",
            "thanks",
        ),
        EmotionalState.TIRED: (
            "tired",
            "exhausted",
            "sleepy",
            "worn out",
        ),
    }

    def __init__(self, authenticated_user: AuthenticatedUser) -> None:
        self._authenticated_user = authenticated_user

    def analyze_text(self, text: str) -> InteractionState:
        """
        Analyze text and return a temporary interaction-state observation.
        """

        if not text.strip():
            raise ValueError("Text cannot be empty.")

        normalized = self._normalize(text)

        scores: dict[EmotionalState, int] = {
            state: 0 for state in self._SIGNALS
        }

        for state, signals in self._SIGNALS.items():
            for signal in signals:
                if self._contains_signal(normalized, signal):
                    scores[state] += 1

        state, score = self._select_state(scores)

        confidence = self._calculate_confidence(
            text=normalized,
            state=state,
            score=score,
        )

        return InteractionState(
            user_id=self._authenticated_user.user_id,
            emotional_state=state,
            confidence=confidence,
            source=DetectionSource.TEXT,
        )

    @staticmethod
    def _normalize(text: str) -> str:
        return re.sub(r"\s+", " ", text.lower()).strip()

    @staticmethod
    def _contains_signal(text: str, signal: str) -> bool:
        if " " in signal:
            return signal in text

        return re.search(rf"\b{re.escape(signal)}\b", text) is not None

    @staticmethod
    def _select_state(
        scores: dict[EmotionalState, int],
    ) -> tuple[EmotionalState, int]:
        state, score = max(
            scores.items(),
            key=lambda item: item[1],
        )

        if score == 0:
            return EmotionalState.UNKNOWN, 0

        return state, score

    @staticmethod
    def _calculate_confidence(
        text: str,
        state: EmotionalState,
        score: int,
    ) -> float:
        if state == EmotionalState.UNKNOWN:
            return 0.0

        signal_strength = min(score / 3.0, 1.0)

        punctuation_bonus = 0.05 if "!" in text else 0.0

        return min(
            round(0.50 + (0.40 * signal_strength) + punctuation_bonus, 2),
            0.95,
        )