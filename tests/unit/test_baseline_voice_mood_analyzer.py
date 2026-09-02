from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest

from backend.models.interaction_state import (
    DetectionSource,
    EmotionalState,
)
from backend.models.voice_features import VoiceFeatures
from backend.security.authenticated_user import AuthenticatedUser
from backend.services.baseline_voice_mood_analyzer import (
    BaselineVoiceMoodAnalyzer,
)


def test_high_activation_voice_is_detected_as_excited() -> None:
    user_id = uuid4()
    analyzer = BaselineVoiceMoodAnalyzer(
        AuthenticatedUser(user_id=user_id)
    )

    features = VoiceFeatures(
        user_id=user_id,
        mean_pitch_hz=250.0,
        mean_intensity_db=80.0,
        speech_rate_wpm=190.0,
        pause_ratio=0.10,
        confidence=0.90,
    )

    state = analyzer.analyze(features)

    assert state.user_id == user_id
    assert state.emotional_state == EmotionalState.EXCITED
    assert state.source == DetectionSource.VOICE
    assert state.confidence >= 0.60


def test_low_activation_voice_can_be_detected_as_calm() -> None:
    user_id = uuid4()
    analyzer = BaselineVoiceMoodAnalyzer(
        AuthenticatedUser(user_id=user_id)
    )

    features = VoiceFeatures(
        user_id=user_id,
        mean_pitch_hz=110.0,
        speech_rate_wpm=80.0,
        pause_ratio=0.20,
        confidence=0.90,
    )

    state = analyzer.analyze(features)

    assert state.user_id == user_id
    assert state.emotional_state == EmotionalState.CALM
    assert state.source == DetectionSource.VOICE


def test_insufficient_voice_features_return_unknown() -> None:
    user_id = uuid4()
    analyzer = BaselineVoiceMoodAnalyzer(
        AuthenticatedUser(user_id=user_id)
    )

    features = VoiceFeatures(
        user_id=user_id,
        confidence=0.90,
    )

    state = analyzer.analyze(features)

    assert state.emotional_state == EmotionalState.UNKNOWN
    assert state.confidence == 0.0
    assert state.source == DetectionSource.VOICE


def test_expired_voice_features_return_unknown() -> None:
    user_id = uuid4()
    analyzer = BaselineVoiceMoodAnalyzer(
        AuthenticatedUser(user_id=user_id)
    )

    features = VoiceFeatures(
        user_id=user_id,
        mean_pitch_hz=250.0,
        mean_intensity_db=80.0,
        speech_rate_wpm=190.0,
        observed_at=datetime.now(timezone.utc) - timedelta(minutes=10),
        expires_at=datetime.now(timezone.utc) - timedelta(minutes=5),
        confidence=0.90,
    )

    state = analyzer.analyze(features)

    assert state.emotional_state == EmotionalState.UNKNOWN
    assert state.confidence == 0.0
    assert state.source == DetectionSource.VOICE


def test_authenticated_identity_is_preserved() -> None:
    user_id = uuid4()
    analyzer = BaselineVoiceMoodAnalyzer(
        AuthenticatedUser(user_id=user_id)
    )

    features = VoiceFeatures(
        user_id=user_id,
        mean_pitch_hz=180.0,
    )

    state = analyzer.analyze(features)

    assert state.user_id == user_id


def test_cross_user_voice_features_are_rejected() -> None:
    authenticated_user_id = uuid4()
    attacker_user_id = uuid4()

    analyzer = BaselineVoiceMoodAnalyzer(
        AuthenticatedUser(user_id=authenticated_user_id)
    )

    features = VoiceFeatures(
        user_id=attacker_user_id,
        mean_pitch_hz=250.0,
        mean_intensity_db=80.0,
        speech_rate_wpm=190.0,
        confidence=0.90,
    )

    with pytest.raises(PermissionError):
        analyzer.analyze(features)


def test_voice_analysis_does_not_authenticate_or_authorize() -> None:
    user_id = uuid4()
    analyzer = BaselineVoiceMoodAnalyzer(
        AuthenticatedUser(user_id=user_id)
    )

    features = VoiceFeatures(
        user_id=user_id,
        mean_pitch_hz=250.0,
        confidence=0.90,
    )

    state = analyzer.analyze(features)

    assert state.user_id == user_id
    assert not hasattr(state, "authenticated")
    assert not hasattr(state, "authorized")
    assert not hasattr(state, "permissions")
    assert not hasattr(state, "tool_access")


def test_voice_analysis_does_not_store_audio() -> None:
    user_id = uuid4()
    analyzer = BaselineVoiceMoodAnalyzer(
        AuthenticatedUser(user_id=user_id)
    )

    features = VoiceFeatures(
        user_id=user_id,
        mean_pitch_hz=180.0,
        confidence=0.90,
    )

    state = analyzer.analyze(features)

    assert not hasattr(state, "audio")
    assert not hasattr(state, "raw_audio")
    assert not hasattr(state, "audio_data")
