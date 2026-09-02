from uuid import uuid4

import pytest

from backend.models.memory import (
    MemoryProvenance,
    MemoryStatus,
    MemoryType,
)
from backend.services.memory_service import MemoryService


class InMemoryRepository:
    """Minimal repository used only for service tests."""

    def __init__(self):
        self.records = {}

    def save(self, memory):
        self.records[memory.id] = memory
        return memory

    def get(self, memory_id):
        return self.records.get(memory_id)

    def list_by_user(self, user_id):
        return [
            memory
            for memory in self.records.values()
            if memory.user_id == user_id
        ]


@pytest.fixture
def repository():
    return InMemoryRepository()


@pytest.fixture
def service(repository):
    return MemoryService(repository)


def test_service_can_store_user_memory(service, repository):
    user_id = uuid4()

    memory = service.create_memory(
        user_id=user_id,
        memory_type=MemoryType.PREFERENCE,
        content="Prefers detailed technical explanations.",
        provenance=MemoryProvenance.EXPLICIT_USER_STATEMENT,
    )

    assert memory.user_id == user_id
    assert memory.status == MemoryStatus.CANDIDATE
    assert memory.id in repository.records


def test_external_memory_requires_approval(service):
    memory = service.create_memory(
        user_id=uuid4(),
        memory_type=MemoryType.EPISODIC,
        content="Information obtained from an external website.",
        provenance=MemoryProvenance.EXTERNAL_CONTENT,
    )

    assert memory.status == MemoryStatus.CANDIDATE
    assert memory.user_approved is False


def test_user_can_approve_external_memory(service):
    user_id = uuid4()

    memory = service.create_memory(
        user_id=user_id,
        memory_type=MemoryType.PREFERENCE,
        content="Approved external information.",
        provenance=MemoryProvenance.EXTERNAL_CONTENT,
    )

    approved = service.approve_memory(
        memory_id=memory.id,
        user_id=user_id,
    )

    assert approved.status == MemoryStatus.ACTIVE
    assert approved.user_approved is True


def test_user_cannot_retrieve_another_users_memory(service):
    owner_id = uuid4()
    attacker_id = uuid4()

    memory = service.create_memory(
        user_id=owner_id,
        memory_type=MemoryType.PREFERENCE,
        content="Private user preference.",
        provenance=MemoryProvenance.EXPLICIT_USER_STATEMENT,
    )

    with pytest.raises(PermissionError):
        service.get_memory(
            memory_id=memory.id,
            user_id=attacker_id,
        )


def test_user_can_retrieve_own_memory(service):
    user_id = uuid4()

    memory = service.create_memory(
        user_id=user_id,
        memory_type=MemoryType.PREFERENCE,
        content="User's own preference.",
        provenance=MemoryProvenance.EXPLICIT_USER_STATEMENT,
    )

    retrieved = service.get_memory(
        memory_id=memory.id,
        user_id=user_id,
    )

    assert retrieved.id == memory.id


def test_deleted_memory_cannot_be_retrieved(service):
    user_id = uuid4()

    memory = service.create_memory(
        user_id=user_id,
        memory_type=MemoryType.PREFERENCE,
        content="Memory that will be deleted.",
        provenance=MemoryProvenance.EXPLICIT_USER_STATEMENT,
    )

    service.delete_memory(
        memory_id=memory.id,
        user_id=user_id,
    )

    with pytest.raises(LookupError):
        service.get_memory(
            memory_id=memory.id,
            user_id=user_id,
        )


def test_quarantined_memory_cannot_be_retrieved(service):
    user_id = uuid4()

    memory = service.create_memory(
        user_id=user_id,
        memory_type=MemoryType.PREFERENCE,
        content="Suspicious memory.",
        provenance=MemoryProvenance.EXPLICIT_USER_STATEMENT,
    )

    service.quarantine_memory(
        memory_id=memory.id,
        user_id=user_id,
    )

    with pytest.raises(LookupError):
        service.get_memory(
            memory_id=memory.id,
            user_id=user_id,
        )


def test_memory_service_has_no_authorization_capabilities(service):
    assert not hasattr(service, "grant_permission")
    assert not hasattr(service, "grant_tool_access")
    assert not hasattr(service, "grant_capability")
