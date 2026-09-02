from __future__ import annotations

from backend.models.interaction_state import (
    EmotionalState,
    InteractionState,
)
from backend.models.response_strategy import (
    ResponseDirectness,
    ResponseStrategy,
    ResponseTone,
    ResponseVerbosity,
)


class AdaptationService:
    """
    Converts temporary interaction state into a response strategy.

    This service controls response presentation only.

    It must never:
    - grant permissions,
    - authorize tools,
    - modify authentication,
    - modify security policy,
    - alter memory authorization,
    - bypass confirmation requirements.

    Low-confidence emotional observations produce conservative
    adaptation rather than aggressive behavioral changes.
    """

    _MIN_CONFIDENCE = 0.60

    def adapt(self, state: InteractionState) -> ResponseStrategy:
        """
        Produce a safe response strategy from the current interaction state.
        """

        if state.is_expired or state.confidence < self._MIN_CONFIDENCE:
            return ResponseStrategy()

        strategies: dict[EmotionalState, ResponseStrategy] = {
            EmotionalState.FRUSTRATED: ResponseStrategy(
                tone=ResponseTone.CALM,
                verbosity=ResponseVerbosity.CONCISE,
                directness=ResponseDirectness.HIGH,
            ),
            EmotionalState.ANGRY: ResponseStrategy(
                tone=ResponseTone.CALM,
                verbosity=ResponseVerbosity.CONCISE,
                directness=ResponseDirectness.HIGH,
            ),
            EmotionalState.SAD: ResponseStrategy(
                tone=ResponseTone.SUPPORTIVE,
                verbosity=ResponseVerbosity.NORMAL,
                directness=ResponseDirectness.NORMAL,
            ),
            EmotionalState.ANXIOUS: ResponseStrategy(
                tone=ResponseTone.CALM,
                verbosity=ResponseVerbosity.NORMAL,
                directness=ResponseDirectness.NORMAL,
            ),
            EmotionalState.CONFUSED: ResponseStrategy(
                tone=ResponseTone.SUPPORTIVE,
                verbosity=ResponseVerbosity.DETAILED,
                directness=ResponseDirectness.NORMAL,
            ),
            EmotionalState.EXCITED: ResponseStrategy(
                tone=ResponseTone.ENCOURAGING,
                verbosity=ResponseVerbosity.NORMAL,
                directness=ResponseDirectness.NORMAL,
            ),
            EmotionalState.HAPPY: ResponseStrategy(
                tone=ResponseTone.ENCOURAGING,
                verbosity=ResponseVerbosity.NORMAL,
                directness=ResponseDirectness.NORMAL,
            ),
            EmotionalState.TIRED: ResponseStrategy(
                tone=ResponseTone.CALM,
                verbosity=ResponseVerbosity.CONCISE,
                directness=ResponseDirectness.NORMAL,
            ),
        }

        return strategies.get(
            state.emotional_state,
            ResponseStrategy(),
        )