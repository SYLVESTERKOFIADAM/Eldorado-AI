from datetime import datetime, timezone
from uuid import uuid4

import pytest

from backend.models.memory import (
    MemoryProvenance,
    MemorySensitivity,
    MemoryType,
)
from backend.models.memory_candidate import MemoryCandidate


def test_candidate_requires_non_empty_content():
    with pytest.raises(ValueError, match="cannot be empty"):
        MemoryCandidate(
            authenticated_user_id=uuid4(),
            memory_type=MemoryType.PREFERENCE,
            content="   ",
            provenance=MemoryProvenance.CONVERSATION_INFERENCE,
        )


def test_candidate_rejects_excessively_large_content():
    with pytest.raises(ValueError, match="2000 characters"):
        MemoryCandidate(
            authenticated_user_id=uuid4(),
            memory_type=MemoryType.PREFERENCE,
            content="x" * 2001,
            provenance=MemoryProvenance.CONVERSATION_INFERENCE,
        )


def test_candidate_rejects_invalid_confidence():
    with pytest.raises(ValueError, match="between 0.0 and 1.0"):
        MemoryCandidate(
            authenticated_user_id=uuid4(),
            memory_type=MemoryType.PREFERENCE,
            content="Prefers concise answers",
            provenance=MemoryProvenance.CONVERSATION_INFERENCE,
            confidence=1.1,
        )


def test_candidate_accepts_valid_confidence_boundaries():
    user_id = uuid4()

    low = MemoryCandidate(
        authenticated_user_id=user_id,
        memory_type=MemoryType.PREFERENCE,
        content="Prefers concise answers",
        provenance=MemoryProvenance.CONVERSATION_INFERENCE,
        confidence=0.0,
    )

    high = MemoryCandidate(
        authenticated_user_id=user_id,
        memory_type=MemoryType.PREFERENCE,
        content="Prefers detailed answers",
        provenance=MemoryProvenance.USER_FEEDBACK,
        confidence=1.0,
    )

    assert low.confidence == 0.0
    assert high.confidence == 1.0


def test_candidate_requires_timezone_aware_timestamp():
    with pytest.raises(ValueError, match="timezone-aware"):
        MemoryCandidate(
            authenticated_user_id=uuid4(),
            memory_type=MemoryType.PREFERENCE,
            content="Prefers concise answers",
            provenance=MemoryProvenance.CONVERSATION_INFERENCE,
            created_at=datetime(2026, 9, 2),
        )


def test_candidate_is_immutable():
    candidate = MemoryCandidate(
        authenticated_user_id=uuid4(),
        memory_type=MemoryType.PREFERENCE,
        content="Prefers concise answers",
        provenance=MemoryProvenance.CONVERSATION_INFERENCE,
        confidence=0.8,
    )

    with pytest.raises(AttributeError):
        candidate.content = "Malicious replacement"


def test_candidate_preserves_provenance_and_sensitivity():
    candidate = MemoryCandidate(
        authenticated_user_id=uuid4(),
        memory_type=MemoryType.PREFERENCE,
        content="Prefers concise answers",
        provenance=MemoryProvenance.USER_FEEDBACK,
        confidence=0.9,
        sensitivity=MemorySensitivity.SENSITIVE,
    )

    assert candidate.provenance == MemoryProvenance.USER_FEEDBACK
    assert candidate.sensitivity == MemorySensitivity.SENSITIVE


def test_candidate_has_no_authorization_fields():
    candidate = MemoryCandidate(
        authenticated_user_id=uuid4(),
        memory_type=MemoryType.PREFERENCE,
        content="Prefers concise answers",
        provenance=MemoryProvenance.CONVERSATION_INFERENCE,
        confidence=0.8,
    )

    assert not hasattr(candidate, "permissions")
    assert not hasattr(candidate, "capabilities")
    assert not hasattr(candidate, "authorization")
    assert not hasattr(candidate, "tool_access")
