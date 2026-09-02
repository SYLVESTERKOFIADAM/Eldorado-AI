from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest

from backend.models.memory import (
    MemoryProvenance,
    MemoryStatus,
    MemorySensitivity,
    MemoryType,
)
from backend.repositories.in_memory_memory_repository import (
    InMemoryMemoryRepository,
)
from backend.security.authenticated_user import AuthenticatedUser
from backend.services.memory_service import MemoryService


@pytest.fixture
def repository():
    return InMemoryMemoryRepository()


@pytest.fixture
def service(repository):
    return MemoryService(repository)


def create_user() -> AuthenticatedUser:
    return AuthenticatedUser(user_id=uuid4())


def create_test_memory(
    service,
    authenticated_user=None,
    *,
    provenance=MemoryProvenance.EXPLICIT_USER_STATEMENT,
):
    authenticated_user = authenticated_user or create_user()

    return service.create_memory(
        authenticated_user=authenticated_user,
        memory_type=MemoryType.PREFERENCE,
        content="Test user preference.",
        provenance=provenance,
    )


def test_service_can_store_user_memory(service, repository):
    user = create_user()

    memory = create_test_memory(
        service,
        user,
    )

    assert memory.user_id == user.user_id
    assert memory.status == MemoryStatus.CANDIDATE
    assert repository.get(memory.id) == memory


def test_creation_uses_authenticated_identity(service):
    user = create_user()

    memory = service.create_memory(
        authenticated_user=user,
        memory_type=MemoryType.PREFERENCE,
        content="Authenticated preference.",
        provenance=MemoryProvenance.EXPLICIT_USER_STATEMENT,
    )

    assert memory.user_id == user.user_id


def test_external_memory_requires_approval(service):
    memory = create_test_memory(
        service,
        provenance=MemoryProvenance.EXTERNAL_CONTENT,
    )

    assert memory.status == MemoryStatus.CANDIDATE
    assert memory.user_approved is False


def test_user_can_approve_external_memory(service):
    user = create_user()

    memory = create_test_memory(
        service,
        user,
        provenance=MemoryProvenance.EXTERNAL_CONTENT,
    )

    approved = service.approve_memory(
        memory_id=memory.id,
        authenticated_user=user,
    )

    assert approved.status == MemoryStatus.ACTIVE
    assert approved.user_approved is True


def test_user_cannot_approve_another_users_memory(service):
    owner = create_user()
    attacker = create_user()

    memory = create_test_memory(
        service,
        owner,
        provenance=MemoryProvenance.EXTERNAL_CONTENT,
    )

    with pytest.raises(PermissionError):
        service.approve_memory(
            memory_id=memory.id,
            authenticated_user=attacker,
        )

    assert memory.status == MemoryStatus.CANDIDATE
    assert memory.user_approved is False


def test_user_cannot_retrieve_another_users_memory(service):
    owner = create_user()
    attacker = create_user()

    memory = create_test_memory(service, owner)

    with pytest.raises(PermissionError):
        service.get_memory(
            memory_id=memory.id,
            authenticated_user=attacker,
        )


def test_user_can_retrieve_own_memory(service):
    user = create_user()

    memory = create_test_memory(service, user)

    retrieved = service.get_memory(
        memory_id=memory.id,
        authenticated_user=user,
    )

    assert retrieved.id == memory.id


def test_deleted_memory_cannot_be_retrieved(service):
    user = create_user()

    memory = create_test_memory(service, user)

    service.delete_memory(
        memory_id=memory.id,
        authenticated_user=user,
    )

    with pytest.raises(LookupError):
        service.get_memory(
            memory_id=memory.id,
            authenticated_user=user,
        )


def test_user_cannot_delete_another_users_memory(service):
    owner = create_user()
    attacker = create_user()

    memory = create_test_memory(service, owner)

    with pytest.raises(PermissionError):
        service.delete_memory(
            memory_id=memory.id,
            authenticated_user=attacker,
        )

    assert memory.status == MemoryStatus.CANDIDATE


def test_user_can_delete_own_memory(service):
    user = create_user()

    memory = create_test_memory(service, user)

    deleted = service.delete_memory(
        memory_id=memory.id,
        authenticated_user=user,
    )

    assert deleted.status == MemoryStatus.DELETED


def test_quarantined_memory_cannot_be_retrieved(service):
    user = create_user()

    memory = create_test_memory(service, user)

    service.quarantine_memory(
        memory_id=memory.id,
        authenticated_user=user,
    )

    with pytest.raises(LookupError):
        service.get_memory(
            memory_id=memory.id,
            authenticated_user=user,
        )


def test_user_cannot_quarantine_another_users_memory(service):
    owner = create_user()
    attacker = create_user()

    memory = create_test_memory(service, owner)

    with pytest.raises(PermissionError):
        service.quarantine_memory(
            memory_id=memory.id,
            authenticated_user=attacker,
        )

    assert memory.status == MemoryStatus.CANDIDATE


def test_user_can_quarantine_own_memory(service):
    user = create_user()

    memory = create_test_memory(service, user)

    quarantined = service.quarantine_memory(
        memory_id=memory.id,
        authenticated_user=user,
    )

    assert quarantined.status == MemoryStatus.QUARANTINED


def test_expired_memory_cannot_be_retrieved(service, repository):
    user = create_user()

    memory = create_test_memory(service, user)

    memory.expires_at = datetime.now(timezone.utc) - timedelta(minutes=1)
    repository.save(memory)

    with pytest.raises(LookupError):
        service.get_memory(
            memory_id=memory.id,
            authenticated_user=user,
        )


def test_superseded_memory_cannot_be_retrieved(service, repository):
    user = create_user()

    memory = create_test_memory(service, user)

    memory.supersede()
    repository.save(memory)

    with pytest.raises(LookupError):
        service.get_memory(
            memory_id=memory.id,
            authenticated_user=user,
        )


def test_nonexistent_memory_raises_lookup_error(service):
    user = create_user()

    with pytest.raises(LookupError):
        service.get_memory(
            memory_id=uuid4(),
            authenticated_user=user,
        )


def test_approve_nonexistent_memory_raises_lookup_error(service):
    user = create_user()

    with pytest.raises(LookupError):
        service.approve_memory(
            memory_id=uuid4(),
            authenticated_user=user,
        )


def test_delete_nonexistent_memory_raises_lookup_error(service):
    user = create_user()

    with pytest.raises(LookupError):
        service.delete_memory(
            memory_id=uuid4(),
            authenticated_user=user,
        )


def test_quarantine_nonexistent_memory_raises_lookup_error(service):
    user = create_user()

    with pytest.raises(LookupError):
        service.quarantine_memory(
            memory_id=uuid4(),
            authenticated_user=user,
        )


def test_memory_service_has_no_authorization_capabilities(service):
    assert not hasattr(service, "grant_permission")
    assert not hasattr(service, "grant_tool_access")
    assert not hasattr(service, "grant_capability")

def test_active_memory_cannot_be_approved_again(service):
    user = create_user()

    memory = create_test_memory(
        service,
        user,
        provenance=MemoryProvenance.EXPLICIT_USER_STATEMENT,
    )

    approved = service.approve_memory(
        memory_id=memory.id,
        authenticated_user=user,
    )

    assert approved.status == MemoryStatus.ACTIVE

    with pytest.raises(ValueError, match="already active"):
        service.approve_memory(
            memory_id=memory.id,
            authenticated_user=user,
        )





def test_sensitive_inferred_memory_cannot_be_approved_directly(service):
    user = create_user()

    memory = service.create_memory(
        authenticated_user=user,
        memory_type=MemoryType.PREFERENCE,
        content="Sensitive inferred preference.",
        provenance=MemoryProvenance.CONVERSATION_INFERENCE,
        confidence=0.99,
        sensitivity=MemorySensitivity.SENSITIVE,
    )

    with pytest.raises(ValueError, match="Sensitive inferred"):
        service.approve_memory(
            memory_id=memory.id,
            authenticated_user=user,
        )

def test_sensitive_inferred_memory_cannot_be_approved_directly(service):
    user = create_user()

    memory = service.create_memory(
        authenticated_user=user,
        memory_type=MemoryType.PREFERENCE,
        content="Sensitive inferred preference.",
        provenance=MemoryProvenance.CONVERSATION_INFERENCE,
        confidence=0.99,
        sensitivity=MemorySensitivity.SENSITIVE,
    )

    with pytest.raises(ValueError, match="Sensitive inferred"):
        service.approve_memory(
            memory_id=memory.id,
            authenticated_user=user,
        )
