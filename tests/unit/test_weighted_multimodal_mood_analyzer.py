from __future__ import annotations

from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest

from backend.models.interaction_state import (
    DetectionSource,
    EmotionalState,
    InteractionState,
)
from backend.security.authenticated_user import AuthenticatedUser
from backend.services.weighted_multimodal_mood_analyzer import (
    WeightedMultimodalMoodAnalyzer,
)


def make_state(
    user_id,
    emotional_state,
    confidence,
    source,
    *,
    expired=False,
):
    now = datetime.now(timezone.utc)

    if expired:
        observed_at = now - timedelta(minutes=5)
        expires_at = now - timedelta(minutes=4)
    else:
        observed_at = now
        expires_at = now + timedelta(minutes=1)

    return InteractionState(
        user_id=user_id,
        emotional_state=emotional_state,
        confidence=confidence,
        source=source,
        observed_at=observed_at,
        expires_at=expires_at,
    )


@pytest.fixture
def user():
    return AuthenticatedUser(user_id=uuid4())


@pytest.fixture
def analyzer(user):
    return WeightedMultimodalMoodAnalyzer(user)


def test_matching_modalities_produce_combined_state(user, analyzer):
    text = make_state(
        user.user_id,
        EmotionalState.FRUSTRATED,
        0.90,
        DetectionSource.TEXT,
    )

    voice = make_state(
        user.user_id,
        EmotionalState.FRUSTRATED,
        0.80,
        DetectionSource.VOICE,
    )

    result = analyzer.analyze(text, voice)

    assert result.user_id == user.user_id
    assert result.emotional_state == EmotionalState.FRUSTRATED
    assert result.source == DetectionSource.MULTIMODAL
    assert result.confidence >= 0.60
    assert not result.is_expired


def test_text_only_observation_is_supported(user, analyzer):
    text = make_state(
        user.user_id,
        EmotionalState.CONFUSED,
        0.85,
        DetectionSource.TEXT,
    )

    result = analyzer.analyze(text, None)

    assert result.emotional_state == EmotionalState.CONFUSED
    assert result.confidence == pytest.approx(0.85)
    assert result.source == DetectionSource.MULTIMODAL


def test_voice_only_observation_is_supported(user, analyzer):
    voice = make_state(
        user.user_id,
        EmotionalState.CALM,
        0.82,
        DetectionSource.VOICE,
    )

    result = analyzer.analyze(None, voice)

    assert result.emotional_state == EmotionalState.CALM
    assert result.confidence == pytest.approx(0.82)
    assert result.source == DetectionSource.MULTIMODAL


def test_no_observations_fail_closed_to_unknown(user, analyzer):
    result = analyzer.analyze(None, None)

    assert result.user_id == user.user_id
    assert result.emotional_state == EmotionalState.UNKNOWN
    assert result.confidence == 0.0
    assert result.source == DetectionSource.MULTIMODAL


def test_expired_observations_are_ignored(user, analyzer):
    text = make_state(
        user.user_id,
        EmotionalState.ANGRY,
        0.99,
        DetectionSource.TEXT,
        expired=True,
    )

    voice = make_state(
        user.user_id,
        EmotionalState.CALM,
        0.80,
        DetectionSource.VOICE,
    )

    result = analyzer.analyze(text, voice)

    assert result.emotional_state == EmotionalState.CALM
    assert result.confidence == pytest.approx(0.80)


def test_low_confidence_observations_are_ignored(user, analyzer):
    text = make_state(
        user.user_id,
        EmotionalState.ANGRY,
        0.40,
        DetectionSource.TEXT,
    )

    voice = make_state(
        user.user_id,
        EmotionalState.CALM,
        0.80,
        DetectionSource.VOICE,
    )

    result = analyzer.analyze(text, voice)

    assert result.emotional_state == EmotionalState.CALM
    assert result.confidence == pytest.approx(0.80)


def test_contradictory_signals_fail_closed_when_close(user, analyzer):
    text = make_state(
        user.user_id,
        EmotionalState.ANGRY,
        0.90,
        DetectionSource.TEXT,
    )

    voice = make_state(
        user.user_id,
        EmotionalState.CALM,
        0.90,
        DetectionSource.VOICE,
    )

    result = analyzer.analyze(text, voice)

    assert result.emotional_state == EmotionalState.UNKNOWN
    assert result.confidence == 0.0


def test_stronger_modality_can_dominate_conflict(user, analyzer):
    text = make_state(
        user.user_id,
        EmotionalState.ANGRY,
        0.99,
        DetectionSource.TEXT,
    )

    voice = make_state(
        user.user_id,
        EmotionalState.CALM,
        0.60,
        DetectionSource.VOICE,
    )

    result = analyzer.analyze(text, voice)

    assert result.emotional_state == EmotionalState.ANGRY
    assert result.confidence >= 0.60


def test_cross_user_text_observation_is_rejected(user, analyzer):
    attacker = uuid4()

    text = make_state(
        attacker,
        EmotionalState.ANGRY,
        0.99,
        DetectionSource.TEXT,
    )

    with pytest.raises(PermissionError):
        analyzer.analyze(text, None)


def test_cross_user_voice_observation_is_rejected(user, analyzer):
    attacker = uuid4()

    voice = make_state(
        attacker,
        EmotionalState.ANGRY,
        0.99,
        DetectionSource.VOICE,
    )

    with pytest.raises(PermissionError):
        analyzer.analyze(None, voice)


def test_cross_user_observation_cannot_override_valid_user_state(
    user,
    analyzer,
):
    attacker = uuid4()

    text = make_state(
        user.user_id,
        EmotionalState.CALM,
        0.80,
        DetectionSource.TEXT,
    )

    malicious_voice = make_state(
        attacker,
        EmotionalState.ANGRY,
        1.00,
        DetectionSource.VOICE,
    )

    with pytest.raises(PermissionError):
        analyzer.analyze(text, malicious_voice)


def test_invalid_weights_are_rejected(user):
    with pytest.raises(ValueError):
        WeightedMultimodalMoodAnalyzer(
            user,
            text_weight=-1.0,
            voice_weight=1.0,
        )

    with pytest.raises(ValueError):
        WeightedMultimodalMoodAnalyzer(
            user,
            text_weight=0.0,
            voice_weight=0.0,
        )


def test_weights_are_normalized(user):
    analyzer = WeightedMultimodalMoodAnalyzer(
        user,
        text_weight=2.0,
        voice_weight=1.0,
    )

    text = make_state(
        user.user_id,
        EmotionalState.ANGRY,
        0.90,
        DetectionSource.TEXT,
    )

    voice = make_state(
        user.user_id,
        EmotionalState.CALM,
        0.60,
        DetectionSource.VOICE,
    )

    result = analyzer.analyze(text, voice)

    assert result.emotional_state == EmotionalState.ANGRY


def test_fusion_does_not_grant_permissions(user, analyzer):
    text = make_state(
        user.user_id,
        EmotionalState.ANGRY,
        0.95,
        DetectionSource.TEXT,
    )

    voice = make_state(
        user.user_id,
        EmotionalState.ANGRY,
        0.95,
        DetectionSource.VOICE,
    )

    result = analyzer.analyze(text, voice)

    assert result.emotional_state == EmotionalState.ANGRY
    assert not hasattr(result, "permissions")
    assert not hasattr(result, "tool_access")


def test_fusion_creates_temporary_state_only(user, analyzer):
    text = make_state(
        user.user_id,
        EmotionalState.HAPPY,
        0.90,
        DetectionSource.TEXT,
    )

    result = analyzer.analyze(text, None)

    assert result.observed_at.tzinfo is not None
    assert result.expires_at.tzinfo is not None
    assert result.expires_at > result.observed_at


def test_unknown_is_used_when_combined_evidence_is_insufficient(
    user,
    analyzer,
):
    text = make_state(
        user.user_id,
        EmotionalState.ANGRY,
        0.61,
        DetectionSource.TEXT,
    )

    voice = make_state(
        user.user_id,
        EmotionalState.CALM,
        0.61,
        DetectionSource.VOICE,
    )

    result = analyzer.analyze(text, voice)

    assert result.emotional_state == EmotionalState.UNKNOWN
    assert result.confidence == 0.0
