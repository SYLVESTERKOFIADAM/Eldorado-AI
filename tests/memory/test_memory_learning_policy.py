from uuid import uuid4

import pytest

from backend.models.memory import (
    MemoryProvenance,
    MemorySensitivity,
    MemoryType,
)
from backend.models.memory_candidate import MemoryCandidate
from backend.services.memory_learning_policy import (
    MemoryLearningDecision,
    MemoryLearningPolicy,
)


@pytest.fixture
def policy() -> MemoryLearningPolicy:
    return MemoryLearningPolicy()


def make_candidate(
    provenance: MemoryProvenance,
    confidence: float = 0.9,
    sensitivity: MemorySensitivity = MemorySensitivity.INTERNAL,
) -> MemoryCandidate:
    return MemoryCandidate(
        authenticated_user_id=uuid4(),
        memory_type=MemoryType.PREFERENCE,
        content="Prefers concise responses",
        provenance=provenance,
        confidence=confidence,
        sensitivity=sensitivity,
    )


def test_explicit_user_statement_is_allowed(policy):
    candidate = make_candidate(
        MemoryProvenance.EXPLICIT_USER_STATEMENT,
        confidence=0.5,
    )

    decision = policy.evaluate(candidate)

    assert decision.decision == MemoryLearningDecision.ALLOW


def test_user_feedback_is_allowed(policy):
    candidate = make_candidate(
        MemoryProvenance.USER_FEEDBACK,
        confidence=0.5,
    )

    decision = policy.evaluate(candidate)

    assert decision.decision == MemoryLearningDecision.ALLOW


def test_high_confidence_inference_requires_approval(policy):
    candidate = make_candidate(
        MemoryProvenance.CONVERSATION_INFERENCE,
        confidence=0.85,
    )

    decision = policy.evaluate(candidate)

    assert decision.decision == MemoryLearningDecision.REQUIRE_APPROVAL


def test_low_confidence_inference_is_rejected(policy):
    candidate = make_candidate(
        MemoryProvenance.CONVERSATION_INFERENCE,
        confidence=0.84,
    )

    decision = policy.evaluate(candidate)

    assert decision.decision == MemoryLearningDecision.REJECT


def test_sensitive_inference_is_rejected(policy):
    candidate = make_candidate(
        MemoryProvenance.CONVERSATION_INFERENCE,
        confidence=0.99,
        sensitivity=MemorySensitivity.SENSITIVE,
    )

    decision = policy.evaluate(candidate)

    assert decision.decision == MemoryLearningDecision.REJECT


def test_external_content_requires_approval(policy):
    candidate = make_candidate(
        MemoryProvenance.EXTERNAL_CONTENT,
        confidence=1.0,
    )

    decision = policy.evaluate(candidate)

    assert decision.decision == MemoryLearningDecision.REQUIRE_APPROVAL


def test_imported_data_requires_approval(policy):
    candidate = make_candidate(
        MemoryProvenance.IMPORTED_DATA,
        confidence=1.0,
    )

    decision = policy.evaluate(candidate)

    assert decision.decision == MemoryLearningDecision.REQUIRE_APPROVAL


def test_restricted_inference_is_rejected(policy):
    candidate = make_candidate(
        MemoryProvenance.CONVERSATION_INFERENCE,
        confidence=1.0,
        sensitivity=MemorySensitivity.RESTRICTED,
    )

    decision = policy.evaluate(candidate)

    assert decision.decision == MemoryLearningDecision.REJECT


def test_restricted_explicit_statement_is_allowed(policy):
    candidate = make_candidate(
        MemoryProvenance.EXPLICIT_USER_STATEMENT,
        confidence=1.0,
        sensitivity=MemorySensitivity.RESTRICTED,
    )

    decision = policy.evaluate(candidate)

    assert decision.decision == MemoryLearningDecision.ALLOW


def test_policy_decision_contains_security_reason(policy):
    candidate = make_candidate(
        MemoryProvenance.CONVERSATION_INFERENCE,
        confidence=0.5,
    )

    decision = policy.evaluate(candidate)

    assert decision.reason
    assert "confidence" in decision.reason.lower()
