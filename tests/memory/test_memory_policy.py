from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest



from backend.models.memory import (
    MemoryProvenance,
    MemoryRecord,
    MemoryStatus,
    MemoryType,
)
from backend.services.memory_policy import MemoryPolicy

import pytest

@pytest.fixture
def policy():
    return MemoryPolicy()


def make_memory(
    *,
    provenance=MemoryProvenance.EXPLICIT_USER_STATEMENT,
    status=MemoryStatus.CANDIDATE,
    user_approved=False,
    expires_at=None,
):
    return MemoryRecord(
        user_id=uuid4(),
        memory_type=MemoryType.PREFERENCE,
        content="Test memory.",
        provenance=provenance,
        status=status,
        user_approved=user_approved,
        expires_at=expires_at,
    )


def test_valid_candidate_is_allowed(policy):
    memory = make_memory()

    decision = policy.evaluate(memory)

    assert decision.allowed is True


def test_external_unapproved_memory_can_be_retained_as_candidate(policy):
    memory = make_memory(
        provenance=MemoryProvenance.EXTERNAL_CONTENT,
    )

    decision = policy.evaluate(memory)

    assert decision.allowed is True
    assert memory.status == MemoryStatus.CANDIDATE
    assert memory.user_approved is False


def test_imported_unapproved_memory_can_be_retained_as_candidate(policy):
    memory = make_memory(
        provenance=MemoryProvenance.IMPORTED_DATA,
    )

    decision = policy.evaluate(memory)

    assert decision.allowed is True
    assert memory.status == MemoryStatus.CANDIDATE
    assert memory.user_approved is False




def test_approved_external_memory_is_allowed(policy):
    memory = make_memory(
        provenance=MemoryProvenance.EXTERNAL_CONTENT,
        status=MemoryStatus.CANDIDATE,
    )

    memory.approve()

    decision = policy.evaluate(memory)

    assert decision.allowed is True
    assert memory.status == MemoryStatus.ACTIVE
    assert memory.user_approved is True


def test_inactive_lifecycle_states_are_denied(policy):
    for status in (
        MemoryStatus.DELETED,
        MemoryStatus.SUPERSEDED,
        MemoryStatus.EXPIRED,
    ):
        memory = make_memory(status=status)

        decision = policy.evaluate(memory)

        assert decision.allowed is False


def test_expired_memory_is_denied(policy):
    memory = make_memory(
        expires_at=datetime.now(timezone.utc) - timedelta(minutes=1),
    )

    decision = policy.evaluate(memory)

    assert decision.allowed is False
    assert "expired" in decision.reason.lower()


def test_quarantined_memory_is_denied(policy):
    memory = make_memory(
        status=MemoryStatus.QUARANTINED,
    )

    decision = policy.evaluate(memory)

    assert decision.allowed is False
    assert "quarantined" in decision.reason.lower()


def test_policy_does_not_grant_authorization(policy):
    assert not hasattr(policy, "grant_permission")
    assert not hasattr(policy, "grant_tool_access")
    assert not hasattr(policy, "grant_capability")
