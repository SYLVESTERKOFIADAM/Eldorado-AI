from uuid import uuid4
from datetime import datetime, timedelta, timezone

import pytest

def test_expired_state_returns_default_strategy() -> None:
    service = AdaptationService()

    state = InteractionState(
        user_id=uuid4(),
        emotional_state=EmotionalState.FRUSTRATED,
        confidence=0.90,
        observed_at=datetime.now(timezone.utc) - timedelta(minutes=10),
        expires_at=datetime.now(timezone.utc) - timedelta(minutes=5),
    )

    result = service.adapt(state)

    assert result == ResponseStrategy()

from backend.models.interaction_state import (
    DetectionSource,
    EmotionalState,
    InteractionState,
)
from backend.models.response_strategy import (
    ResponseDirectness,
    ResponseStrategy,
    ResponseTone,
    ResponseVerbosity,
)
from backend.services.adaptation_service import AdaptationService


def create_state(
    emotional_state: EmotionalState,
    confidence: float,
) -> InteractionState:
    return InteractionState(
        user_id=uuid4(),
        emotional_state=emotional_state,
        confidence=confidence,
        source=DetectionSource.TEXT,
    )


def test_low_confidence_produces_default_strategy() -> None:
    service = AdaptationService()

    state = create_state(
        EmotionalState.FRUSTRATED,
        confidence=0.59,
    )

    result = service.adapt(state)

    assert result == ResponseStrategy()


def test_frustration_produces_calm_concise_direct_strategy() -> None:
    service = AdaptationService()

    state = create_state(
        EmotionalState.FRUSTRATED,
        confidence=0.80,
    )

    result = service.adapt(state)

    assert result.tone == ResponseTone.CALM
    assert result.verbosity == ResponseVerbosity.CONCISE
    assert result.directness == ResponseDirectness.HIGH


def test_anger_produces_calm_direct_strategy() -> None:
    service = AdaptationService()

    state = create_state(
        EmotionalState.ANGRY,
        confidence=0.90,
    )

    result = service.adapt(state)

    assert result.tone == ResponseTone.CALM
    assert result.directness == ResponseDirectness.HIGH


def test_confusion_produces_detailed_supportive_strategy() -> None:
    service = AdaptationService()

    state = create_state(
        EmotionalState.CONFUSED,
        confidence=0.75,
    )

    result = service.adapt(state)

    assert result.tone == ResponseTone.SUPPORTIVE
    assert result.verbosity == ResponseVerbosity.DETAILED


def test_happiness_produces_encouraging_strategy() -> None:
    service = AdaptationService()

    state = create_state(
        EmotionalState.HAPPY,
        confidence=0.80,
    )

    result = service.adapt(state)

    assert result.tone == ResponseTone.ENCOURAGING
    assert result.verbosity == ResponseVerbosity.NORMAL


def test_unknown_state_uses_default_strategy() -> None:
    service = AdaptationService()

    state = create_state(
        EmotionalState.UNKNOWN,
        confidence=0.90,
    )

    result = service.adapt(state)

    assert result == ResponseStrategy()


def test_adaptation_does_not_change_authenticated_identity() -> None:
    service = AdaptationService()
    user_id = uuid4()

    state = InteractionState(
        user_id=user_id,
        emotional_state=EmotionalState.FRUSTRATED,
        confidence=0.85,
        source=DetectionSource.TEXT,
    )

    result = service.adapt(state)

    assert state.user_id == user_id
    assert not hasattr(result, "user_id")


def test_adaptation_strategy_contains_no_permission_controls() -> None:
    service = AdaptationService()

    state = create_state(
        EmotionalState.ANGRY,
        confidence=0.95,
    )

    result = service.adapt(state)

    assert not hasattr(result, "permissions")
    assert not hasattr(result, "tool_access")
    assert not hasattr(result, "authorization")