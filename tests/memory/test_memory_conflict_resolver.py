from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest

from backend.models.memory import MemoryProvenance, MemoryRecord, MemoryType
from backend.services.memory_conflict_resolver import MemoryConflictResolver


def create_memory(
    *,
    user_id,
    provenance,
    updated_at,
    content,
):
    return MemoryRecord(
        user_id=user_id,
        memory_type=MemoryType.PREFERENCE,
        content=content,
        provenance=provenance,
        updated_at=updated_at,
    )


@pytest.fixture
def resolver():
    return MemoryConflictResolver()


def test_explicit_user_statement_beats_conversation_inference(resolver):
    user_id = uuid4()
    now = datetime.now(timezone.utc)

    existing = create_memory(
        user_id=user_id,
        provenance=MemoryProvenance.CONVERSATION_INFERENCE,
        updated_at=now,
        content="User prefers short responses.",
    )

    incoming = create_memory(
        user_id=user_id,
        provenance=MemoryProvenance.EXPLICIT_USER_STATEMENT,
        updated_at=now - timedelta(days=1),
        content="User prefers detailed responses.",
    )

    decision = resolver.resolve(
        existing=existing,
        incoming=incoming,
    )

    assert decision.winner is incoming
    assert decision.loser is existing


def test_user_feedback_beats_conversation_inference(resolver):
    user_id = uuid4()
    now = datetime.now(timezone.utc)

    existing = create_memory(
        user_id=user_id,
        provenance=MemoryProvenance.CONVERSATION_INFERENCE,
        updated_at=now,
        content="User prefers short responses.",
    )

    incoming = create_memory(
        user_id=user_id,
        provenance=MemoryProvenance.USER_FEEDBACK,
        updated_at=now - timedelta(days=1),
        content="User prefers detailed responses.",
    )

    decision = resolver.resolve(
        existing=existing,
        incoming=incoming,
    )

    assert decision.winner is incoming
    assert decision.loser is existing


def test_equal_provenance_uses_most_recent_memory(resolver):
    user_id = uuid4()
    now = datetime.now(timezone.utc)

    existing = create_memory(
        user_id=user_id,
        provenance=MemoryProvenance.EXPLICIT_USER_STATEMENT,
        updated_at=now - timedelta(days=1),
        content="User prefers short responses.",
    )

    incoming = create_memory(
        user_id=user_id,
        provenance=MemoryProvenance.EXPLICIT_USER_STATEMENT,
        updated_at=now,
        content="User prefers detailed responses.",
    )

    decision = resolver.resolve(
        existing=existing,
        incoming=incoming,
    )

    assert decision.winner is incoming
    assert decision.loser is existing


def test_equal_provenance_existing_memory_wins_when_newer(resolver):
    user_id = uuid4()
    now = datetime.now(timezone.utc)

    existing = create_memory(
        user_id=user_id,
        provenance=MemoryProvenance.USER_FEEDBACK,
        updated_at=now,
        content="User prefers concise responses.",
    )

    incoming = create_memory(
        user_id=user_id,
        provenance=MemoryProvenance.USER_FEEDBACK,
        updated_at=now - timedelta(days=1),
        content="User prefers verbose responses.",
    )

    decision = resolver.resolve(
        existing=existing,
        incoming=incoming,
    )

    assert decision.winner is existing
    assert decision.loser is incoming


def test_cross_user_conflict_resolution_is_rejected(resolver):
    existing = create_memory(
        user_id=uuid4(),
        provenance=MemoryProvenance.EXPLICIT_USER_STATEMENT,
        updated_at=datetime.now(timezone.utc),
        content="User prefers short responses.",
    )

    incoming = create_memory(
        user_id=uuid4(),
        provenance=MemoryProvenance.EXPLICIT_USER_STATEMENT,
        updated_at=datetime.now(timezone.utc),
        content="User prefers detailed responses.",
    )

    with pytest.raises(
        PermissionError,
        match="different users",
    ):
        resolver.resolve(
            existing=existing,
            incoming=incoming,
        )


def test_resolver_does_not_delete_or_modify_memory(resolver):
    user_id = uuid4()
    now = datetime.now(timezone.utc)

    existing = create_memory(
        user_id=user_id,
        provenance=MemoryProvenance.CONVERSATION_INFERENCE,
        updated_at=now,
        content="Original preference.",
    )

    incoming = create_memory(
        user_id=user_id,
        provenance=MemoryProvenance.EXPLICIT_USER_STATEMENT,
        updated_at=now,
        content="Updated preference.",
    )

    resolver.resolve(
        existing=existing,
        incoming=incoming,
    )

    assert existing.status.value == "candidate"
    assert incoming.status.value == "candidate"


def test_resolution_reason_is_deterministic(resolver):
    user_id = uuid4()
    now = datetime.now(timezone.utc)

    existing = create_memory(
        user_id=user_id,
        provenance=MemoryProvenance.CONVERSATION_INFERENCE,
        updated_at=now,
        content="Existing preference.",
    )

    incoming = create_memory(
        user_id=user_id,
        provenance=MemoryProvenance.EXPLICIT_USER_STATEMENT,
        updated_at=now,
        content="Incoming preference.",
    )

    decision = resolver.resolve(
        existing=existing,
        incoming=incoming,
    )

    assert decision.reason == "Incoming memory has stronger provenance."
