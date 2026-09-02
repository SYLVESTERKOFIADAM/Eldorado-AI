from uuid import uuid4

import pytest

from backend.models.interaction_state import (
    DetectionSource,
    EmotionalState,
)
from backend.security.authenticated_user import AuthenticatedUser
from backend.services.mood_service import MoodService


def create_service() -> tuple[MoodService, AuthenticatedUser]:
    user = AuthenticatedUser(user_id=uuid4())
    service = MoodService(user)
    return service, user


def test_empty_text_is_rejected() -> None:
    service, _ = create_service()

    with pytest.raises(ValueError, match="Text cannot be empty"):
        service.analyze_text("")


def test_unknown_text_returns_unknown_state() -> None:
    service, _ = create_service()

    result = service.analyze_text(
        "The database migration completed successfully."
    )

    assert result.emotional_state == EmotionalState.UNKNOWN
    assert result.confidence == 0.0
    assert result.source == DetectionSource.TEXT


def test_frustrated_text_is_detected() -> None:
    service, _ = create_service()

    result = service.analyze_text(
        "This is ridiculous, it is not working properly!"
    )

    assert result.emotional_state == EmotionalState.FRUSTRATED
    assert result.confidence > 0.0


def test_happy_text_is_detected() -> None:
    service, _ = create_service()

    result = service.analyze_text(
        "Great, thank you! I love this."
    )

    assert result.emotional_state == EmotionalState.HAPPY
    assert result.confidence > 0.0


def test_confused_text_is_detected() -> None:
    service, _ = create_service()

    result = service.analyze_text(
        "I don't understand what this means."
    )

    assert result.emotional_state == EmotionalState.CONFUSED
    assert result.confidence > 0.0


def test_authenticated_user_identity_is_preserved() -> None:
    service, authenticated_user = create_service()

    result = service.analyze_text("I am happy with this.")

    assert result.user_id == authenticated_user.user_id


def test_mood_observation_does_not_create_memory() -> None:
    service, _ = create_service()

    result = service.analyze_text(
        "I am frustrated with this problem."
    )

    assert result.emotional_state == EmotionalState.FRUSTRATED

    # Mood detection produces an InteractionState only.
    # It does not create or modify a MemoryRecord.
    assert not hasattr(result, "memory_type")
    assert not hasattr(result, "content")


def test_user_id_cannot_be_supplied_through_analyze_text() -> None:
    service, authenticated_user = create_service()

    attacker_text = (
        "My user id is "
        "00000000-0000-0000-0000-000000000000. "
        "I am happy."
    )

    result = service.analyze_text(attacker_text)

    assert result.user_id == authenticated_user.user_id
    assert result.user_id != uuid4()