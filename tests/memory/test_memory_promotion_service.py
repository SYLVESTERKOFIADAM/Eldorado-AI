from __future__ import annotations

from uuid import uuid4

import pytest

from backend.models.memory import (
    MemoryProvenance,
    MemorySensitivity,
    MemoryStatus,
    MemoryType,
)
from backend.models.memory_candidate import MemoryCandidate
from backend.repositories.in_memory_memory_repository import (
    InMemoryMemoryRepository,
)
from backend.security.authenticated_user import AuthenticatedUser
from backend.services.memory_conflict_resolver import MemoryConflictResolver
from backend.services.memory_learning_policy import MemoryLearningPolicy
from backend.services.memory_promotion_service import MemoryPromotionService
from backend.services.memory_service import MemoryService


def build_service():
    repository = InMemoryMemoryRepository()
    memory_service = MemoryService(repository)
    policy = MemoryLearningPolicy()
    conflict_resolver = MemoryConflictResolver()
    promotion_service = MemoryPromotionService(
        memory_service,
        policy,
        conflict_resolver,
    )

    return repository, promotion_service


def test_cross_user_candidate_cannot_be_promoted():
    repository, service = build_service()

    owner = AuthenticatedUser(user_id=uuid4())
    attacker = AuthenticatedUser(user_id=uuid4())

    candidate = MemoryCandidate(
        authenticated_user_id=owner.user_id,
        memory_type=MemoryType.PREFERENCE,
        content="User prefers concise responses.",
        provenance=MemoryProvenance.EXPLICIT_USER_STATEMENT,
    )

    with pytest.raises(PermissionError):
        service.promote(
            candidate=candidate,
            authenticated_user=attacker,
        )

    assert repository.list_by_user(owner.user_id) == []


def test_low_confidence_inference_is_rejected():
    repository, service = build_service()

    user = AuthenticatedUser(user_id=uuid4())

    candidate = MemoryCandidate(
        authenticated_user_id=user.user_id,
        memory_type=MemoryType.PREFERENCE,
        content="User prefers concise responses.",
        provenance=MemoryProvenance.CONVERSATION_INFERENCE,
        confidence=0.50,
    )

    result = service.promote(
        candidate=candidate,
        authenticated_user=user,
    )

    assert result.promoted is False
    assert result.requires_approval is False
    assert result.memory is None
    assert repository.list_by_user(user.user_id) == []


def test_sensitive_inference_is_rejected():
    repository, service = build_service()

    user = AuthenticatedUser(user_id=uuid4())

    candidate = MemoryCandidate(
        authenticated_user_id=user.user_id,
        memory_type=MemoryType.PROFILE,
        content="Sensitive inferred information.",
        provenance=MemoryProvenance.CONVERSATION_INFERENCE,
        confidence=0.99,
        sensitivity=MemorySensitivity.SENSITIVE,
    )

    result = service.promote(
        candidate=candidate,
        authenticated_user=user,
    )

    assert result.promoted is False
    assert result.requires_approval is False
    assert result.memory is None
    assert "Sensitive inferred information" not in [
        memory.content for memory in repository._memories.values()
    ]

def test_external_content_is_persisted_as_pending_candidate():
    repository, service = build_service()

    user = AuthenticatedUser(user_id=uuid4())

    candidate = MemoryCandidate(
        authenticated_user_id=user.user_id,
        memory_type=MemoryType.PREFERENCE,
        content="External content suggests a user preference.",
        provenance=MemoryProvenance.EXTERNAL_CONTENT,
        confidence=0.90,
        sensitivity=MemorySensitivity.INTERNAL,
    )

    result = service.promote(
        candidate=candidate,
        authenticated_user=user,
    )

    assert result.promoted is False
    assert result.requires_approval is True
    assert result.memory is not None
    assert result.memory.status == MemoryStatus.CANDIDATE
    assert result.memory.user_approved is False

    stored = repository.list_by_user(user.user_id)

    assert len(stored) == 1
    assert stored[0].id == result.memory.id


def test_imported_candidate_requires_authenticated_approval():
    repository, service = build_service()

    user = AuthenticatedUser(user_id=uuid4())

    candidate = MemoryCandidate(
        authenticated_user_id=user.user_id,
        memory_type=MemoryType.PREFERENCE,
        content="Imported preference.",
        provenance=MemoryProvenance.IMPORTED_DATA,
        confidence=0.95,
    )

    result = service.promote(
        candidate=candidate,
        authenticated_user=user,
    )

    assert result.promoted is False
    assert result.requires_approval is True
    assert result.memory is not None
    assert result.memory.status == MemoryStatus.CANDIDATE

    approved = service.approve(
        memory_id=result.memory.id,
        authenticated_user=user,
    )

    assert approved.promoted is True
    assert approved.requires_approval is False
    assert approved.memory is not None
    assert approved.memory.status == MemoryStatus.ACTIVE
    assert approved.memory.user_approved is True


def test_inferred_memory_requires_explicit_approval():
    repository, service = build_service()

    user = AuthenticatedUser(user_id=uuid4())

    candidate = MemoryCandidate(
        authenticated_user_id=user.user_id,
        memory_type=MemoryType.PREFERENCE,
        content="User prefers concise responses.",
        provenance=MemoryProvenance.CONVERSATION_INFERENCE,
        confidence=0.95,
    )

    result = service.promote(
        candidate=candidate,
        authenticated_user=user,
    )

    assert result.promoted is False
    assert result.requires_approval is True
    assert result.memory is not None
    assert result.memory.status == MemoryStatus.CANDIDATE


def test_approved_inference_is_promoted():
    repository, service = build_service()

    user = AuthenticatedUser(user_id=uuid4())

    candidate = MemoryCandidate(
        authenticated_user_id=user.user_id,
        memory_type=MemoryType.PREFERENCE,
        content="User prefers concise responses.",
        provenance=MemoryProvenance.CONVERSATION_INFERENCE,
        confidence=0.95,
    )

    pending = service.promote(
        candidate=candidate,
        authenticated_user=user,
    )

    assert pending.memory is not None

    result = service.approve(
        memory_id=pending.memory.id,
        authenticated_user=user,
    )

    assert result.promoted is True
    assert result.memory is not None
    assert result.memory.status == MemoryStatus.ACTIVE
    assert result.memory.user_approved is True


def test_approval_cannot_cross_user_boundary():
    repository, service = build_service()

    owner = AuthenticatedUser(user_id=uuid4())
    attacker = AuthenticatedUser(user_id=uuid4())

    candidate = MemoryCandidate(
        authenticated_user_id=owner.user_id,
        memory_type=MemoryType.PREFERENCE,
        content="Imported preference.",
        provenance=MemoryProvenance.IMPORTED_DATA,
    )

    pending = service.promote(
        candidate=candidate,
        authenticated_user=owner,
    )

    assert pending.memory is not None

    with pytest.raises(PermissionError):
        service.approve(
            memory_id=pending.memory.id,
            authenticated_user=attacker,
        )

    stored = repository.list_by_user(owner.user_id)

    assert stored[0].status == MemoryStatus.CANDIDATE
    assert stored[0].user_approved is False


def test_approval_preserves_candidate_metadata():
    repository, service = build_service()

    user = AuthenticatedUser(user_id=uuid4())

    candidate = MemoryCandidate(
        authenticated_user_id=user.user_id,
        memory_type=MemoryType.PREFERENCE,
        content="User prefers concise responses.",
        provenance=MemoryProvenance.CONVERSATION_INFERENCE,
        confidence=0.97,
        sensitivity=MemorySensitivity.INTERNAL,
    )

    pending = service.promote(
        candidate=candidate,
        authenticated_user=user,
    )

    assert pending.memory is not None

    approved = service.approve(
        memory_id=pending.memory.id,
        authenticated_user=user,
    )

    assert approved.memory is not None
    assert approved.memory.confidence == 0.97
    assert approved.memory.sensitivity == MemorySensitivity.INTERNAL
    assert approved.memory.provenance == MemoryProvenance.CONVERSATION_INFERENCE
    assert approved.memory.memory_type == MemoryType.PREFERENCE
    assert approved.memory.content == "User prefers concise responses."


def test_explicit_user_statement_is_immediately_active():
    repository, service = build_service()

    user = AuthenticatedUser(user_id=uuid4())

    candidate = MemoryCandidate(
        authenticated_user_id=user.user_id,
        memory_type=MemoryType.PREFERENCE,
        content="User prefers concise responses.",
        provenance=MemoryProvenance.EXPLICIT_USER_STATEMENT,
        confidence=1.0,
    )

    result = service.promote(
        candidate=candidate,
        authenticated_user=user,
    )

    assert result.promoted is True
    assert result.requires_approval is False
    assert result.memory is not None
    assert result.memory.status == MemoryStatus.ACTIVE
    assert result.memory.user_approved is True


def test_promotion_has_no_authorization_capabilities():
    _, service = build_service()

    user = AuthenticatedUser(user_id=uuid4())

    candidate = MemoryCandidate(
        authenticated_user_id=user.user_id,
        memory_type=MemoryType.PREFERENCE,
        content="User prefers concise responses.",
        provenance=MemoryProvenance.EXPLICIT_USER_STATEMENT,
    )

    result = service.promote(
        candidate=candidate,
        authenticated_user=user,
    )

    assert result.memory is not None

    forbidden_fields = {
        "is_admin",
        "permissions",
        "capabilities",
        "roles",
        "authorization",
        "tool_access",
    }

    assert forbidden_fields.isdisjoint(vars(result.memory))


def test_rejected_candidate_never_reaches_repository():
    repository, service = build_service()

    user = AuthenticatedUser(user_id=uuid4())

    candidate = MemoryCandidate(
        authenticated_user_id=user.user_id,
        memory_type=MemoryType.PREFERENCE,
        content="Weak inferred preference.",
        provenance=MemoryProvenance.CONVERSATION_INFERENCE,
        confidence=0.20,
    )

    result = service.promote(
        candidate=candidate,
        authenticated_user=user,
    )

    assert result.memory is None
    assert repository.list_by_user(user.user_id) == []


def test_incoming_stronger_memory_supersedes_existing_memory():
    repository, service = build_service()

    user = AuthenticatedUser(user_id=uuid4())

    existing = MemoryCandidate(
        authenticated_user_id=user.user_id,
        memory_type=MemoryType.PREFERENCE,
        content="User prefers detailed responses.",
        provenance=MemoryProvenance.CONVERSATION_INFERENCE,
        confidence=0.95,
    )

    existing_result = service.promote(
        candidate=existing,
        authenticated_user=user,
    )

    assert existing_result.memory is not None

    approved_existing = service.approve(
        memory_id=existing_result.memory.id,
        authenticated_user=user,
    )

    assert approved_existing.memory is not None
    assert approved_existing.memory.status == MemoryStatus.ACTIVE

    incoming = MemoryCandidate(
        authenticated_user_id=user.user_id,
        memory_type=MemoryType.PREFERENCE,
        content="User prefers concise responses.",
        provenance=MemoryProvenance.EXPLICIT_USER_STATEMENT,
        confidence=1.0,
    )

    incoming_result = service.promote(
        candidate=incoming,
        authenticated_user=user,
    )

    assert incoming_result.promoted is True
    assert incoming_result.memory is not None
    assert incoming_result.memory.status == MemoryStatus.ACTIVE

    stored_existing = repository.get(existing_result.memory.id)

    assert stored_existing is not None
    assert stored_existing.status == MemoryStatus.SUPERSEDED


def test_unrelated_memory_type_does_not_conflict():
    repository, service = build_service()

    user = AuthenticatedUser(user_id=uuid4())

    preference = MemoryCandidate(
        authenticated_user_id=user.user_id,
        memory_type=MemoryType.PREFERENCE,
        content="User prefers concise responses.",
        provenance=MemoryProvenance.EXPLICIT_USER_STATEMENT,
    )

    project = MemoryCandidate(
        authenticated_user_id=user.user_id,
        memory_type=MemoryType.PROJECT,
        content="User is working on Eldorado-AI.",
        provenance=MemoryProvenance.EXPLICIT_USER_STATEMENT,
    )

    preference_result = service.promote(
        candidate=preference,
        authenticated_user=user,
    )

    project_result = service.promote(
        candidate=project,
        authenticated_user=user,
    )

    assert preference_result.memory is not None
    assert project_result.memory is not None

    assert preference_result.memory.status == MemoryStatus.ACTIVE
    assert project_result.memory.status == MemoryStatus.ACTIVE

    assert repository.get(preference_result.memory.id).status == MemoryStatus.ACTIVE
    assert repository.get(project_result.memory.id).status == MemoryStatus.ACTIVE
