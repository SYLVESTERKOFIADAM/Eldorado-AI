from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest

from backend.models.voice_features import VoiceFeatures


def test_valid_voice_features_are_accepted() -> None:
    features = VoiceFeatures(
        user_id=uuid4(),
        mean_pitch_hz=180.0,
        pitch_range_hz=60.0,
        mean_intensity_db=65.0,
        speech_rate_wpm=140.0,
        pause_ratio=0.20,
        confidence=0.85,
    )

    assert features.mean_pitch_hz == 180.0
    assert features.speech_rate_wpm == 140.0
    assert features.pause_ratio == 0.20
    assert features.confidence == 0.85


def test_confidence_must_be_between_zero_and_one() -> None:
    with pytest.raises(ValueError):
        VoiceFeatures(
            user_id=uuid4(),
            confidence=1.1,
        )


def test_negative_pitch_is_rejected() -> None:
    with pytest.raises(ValueError):
        VoiceFeatures(
            user_id=uuid4(),
            mean_pitch_hz=-10.0,
        )


def test_negative_speech_rate_is_rejected() -> None:
    with pytest.raises(ValueError):
        VoiceFeatures(
            user_id=uuid4(),
            speech_rate_wpm=-1.0,
        )


def test_pause_ratio_must_be_between_zero_and_one() -> None:
    with pytest.raises(ValueError):
        VoiceFeatures(
            user_id=uuid4(),
            pause_ratio=1.5,
        )


def test_observed_at_must_be_timezone_aware() -> None:
    with pytest.raises(ValueError):
        VoiceFeatures(
            user_id=uuid4(),
            observed_at=datetime.now(),
        )


def test_expired_voice_features_are_detected() -> None:
    features = VoiceFeatures(
        user_id=uuid4(),
        observed_at=datetime.now(timezone.utc) - timedelta(minutes=10),
        expires_at=datetime.now(timezone.utc) - timedelta(minutes=5),
    )

    assert features.is_expired is True


def test_voice_features_do_not_contain_raw_audio() -> None:
    features = VoiceFeatures(
        user_id=uuid4(),
        mean_pitch_hz=180.0,
    )

    assert not hasattr(features, "audio")
    assert not hasattr(features, "raw_audio")
    assert not hasattr(features, "audio_data")
