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


@pytest.fixture
def policy():
    return MemoryPolicy()


def make_memory(**overrides):
    values = {
        "user_id": uuid4(),
        "memory_type": MemoryType.PREFERENCE,
        "content": "Prefers detailed technical explanations.",
        "provenance": MemoryProvenance.EXPLICIT_USER_STATEMENT,
    }
    values.update(overrides)
    return MemoryRecord(**values)


def test_valid_candidate_is_allowed(policy):
    memory = make_memory()

    decision = policy.evaluate(memory)

    assert decision.allowed is True


def test_external_unapproved_memory_is_denied(policy):
    memory = make_memory(
        provenance=MemoryProvenance.EXTERNAL_CONTENT,
    )

    decision = policy.evaluate(memory)

    assert decision.allowed is False
    assert "approval" in decision.reason.lower()


def test_imported_unapproved_memory_is_denied(policy):
    memory = make_memory(
        provenance=MemoryProvenance.IMPORTED_DATA,
    )

    decision = policy.evaluate(memory)

    assert decision.allowed is False
    assert "approval" in decision.reason.lower()


def test_approved_external_memory_is_allowed(policy):
    memory = make_memory(
        provenance=MemoryProvenance.EXTERNAL_CONTENT,
    )
    memory.approve()

    decision = policy.evaluate(memory)

    assert decision.allowed is True


@pytest.mark.parametrize(
    "status",
    [
        MemoryStatus.DELETED,
        MemoryStatus.SUPERSEDED,
        MemoryStatus.EXPIRED,
    ],
)
def test_inactive_lifecycle_states_are_denied(policy, status):
    memory = make_memory(status=status)

    decision = policy.evaluate(memory)

    assert decision.allowed is False


def test_expired_memory_is_denied(policy):
    memory = make_memory(
        expires_at=datetime.now(timezone.utc) - timedelta(seconds=1),
    )

    decision = policy.evaluate(memory)

    assert decision.allowed is False
    assert "expired" in decision.reason.lower()


def test_quarantined_memory_is_denied(policy):
    memory = make_memory(
        provenance=MemoryProvenance.EXTERNAL_CONTENT,
    )
    memory.quarantine()

    decision = policy.evaluate(memory)

    assert decision.allowed is False
    assert "quarantined" in decision.reason.lower()


def test_policy_does_not_grant_authorization(policy):
    memory = make_memory()

    decision = policy.evaluate(memory)

    assert decision.allowed is True
    assert not hasattr(decision, "permission")
    assert not hasattr(decision, "permissions")
    assert not hasattr(decision, "tool_access")
    assert not hasattr(decision, "capabilities")
    assert not hasattr(decision, "role")
