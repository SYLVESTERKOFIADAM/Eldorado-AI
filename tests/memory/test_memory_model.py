from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest

from backend.models.memory import (
    MemoryProvenance,
    MemoryRecord,
    MemorySensitivity,
    MemoryStatus,
    MemoryType,
)


def test_valid_memory_record_is_created():
    record = MemoryRecord(
        user_id=uuid4(),
        memory_type=MemoryType.PREFERENCE,
        content="Prefers detailed technical explanations.",
        provenance=MemoryProvenance.EXPLICIT_USER_STATEMENT,
        confidence=0.95,
    )

    assert record.memory_type == MemoryType.PREFERENCE
    assert record.confidence == 0.95
    assert record.status == MemoryStatus.CANDIDATE
    assert record.user_approved is False


def test_empty_memory_is_rejected():
    with pytest.raises(ValueError, match="cannot be empty"):
        MemoryRecord(
            user_id=uuid4(),
            memory_type=MemoryType.PREFERENCE,
            content="   ",
            provenance=MemoryProvenance.EXPLICIT_USER_STATEMENT,
        )


@pytest.mark.parametrize("confidence", [-0.01, 1.01, 2.0])
def test_invalid_confidence_is_rejected(confidence):
    with pytest.raises(
        ValueError,
        match="must be between 0.0 and 1.0",
    ):
        MemoryRecord(
            user_id=uuid4(),
            memory_type=MemoryType.PREFERENCE,
            content="Test preference",
            provenance=MemoryProvenance.EXPLICIT_USER_STATEMENT,
            confidence=confidence,
        )


def test_external_memory_cannot_become_active_without_approval():
    with pytest.raises(
        ValueError,
        match="cannot become active",
    ):
        MemoryRecord(
            user_id=uuid4(),
            memory_type=MemoryType.EPISODIC,
            content="Instruction found on an external website.",
            provenance=MemoryProvenance.EXTERNAL_CONTENT,
            status=MemoryStatus.ACTIVE,
            user_approved=False,
        )


def test_imported_memory_cannot_become_active_without_approval():
    with pytest.raises(
        ValueError,
        match="cannot become active",
    ):
        MemoryRecord(
            user_id=uuid4(),
            memory_type=MemoryType.PROFILE,
            content="Imported user information.",
            provenance=MemoryProvenance.IMPORTED_DATA,
            status=MemoryStatus.ACTIVE,
            user_approved=False,
        )


def test_user_can_approve_memory():
    record = MemoryRecord(
        user_id=uuid4(),
        memory_type=MemoryType.PREFERENCE,
        content="Prefers PowerShell commands.",
        provenance=MemoryProvenance.EXPLICIT_USER_STATEMENT,
    )

    record.approve()

    assert record.user_approved is True
    assert record.status == MemoryStatus.ACTIVE


def test_approval_does_not_create_authorization_fields():
    record = MemoryRecord(
        user_id=uuid4(),
        memory_type=MemoryType.PREFERENCE,
        content="Prefers detailed explanations.",
        provenance=MemoryProvenance.EXPLICIT_USER_STATEMENT,
    )

    record.approve()

    assert not hasattr(record, "permission")
    assert not hasattr(record, "permissions")
    assert not hasattr(record, "tool_access")
    assert not hasattr(record, "capabilities")
    assert not hasattr(record, "role")


def test_memory_can_be_superseded():
    record = MemoryRecord(
        user_id=uuid4(),
        memory_type=MemoryType.PREFERENCE,
        content="Old preference.",
        provenance=MemoryProvenance.EXPLICIT_USER_STATEMENT,
    )

    record.supersede()

    assert record.status == MemoryStatus.SUPERSEDED


def test_memory_can_be_deleted():
    record = MemoryRecord(
        user_id=uuid4(),
        memory_type=MemoryType.PREFERENCE,
        content="Preference to remove.",
        provenance=MemoryProvenance.EXPLICIT_USER_STATEMENT,
    )

    record.delete()

    assert record.status == MemoryStatus.DELETED


def test_memory_can_be_quarantined():
    record = MemoryRecord(
        user_id=uuid4(),
        memory_type=MemoryType.EPISODIC,
        content="Potentially poisoned memory.",
        provenance=MemoryProvenance.EXTERNAL_CONTENT,
    )

    record.quarantine()

    assert record.status == MemoryStatus.QUARANTINED


def test_expired_memory_is_detected():
    record = MemoryRecord(
        user_id=uuid4(),
        memory_type=MemoryType.TEMPORARY,
        content="Temporary context.",
        provenance=MemoryProvenance.EXPLICIT_USER_STATEMENT,
        expires_at=datetime.now(timezone.utc) - timedelta(seconds=1),
    )

    assert record.is_expired is True


def test_non_expired_memory_is_detected():
    record = MemoryRecord(
        user_id=uuid4(),
        memory_type=MemoryType.TEMPORARY,
        content="Temporary context.",
        provenance=MemoryProvenance.EXPLICIT_USER_STATEMENT,
        expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
    )

    assert record.is_expired is False