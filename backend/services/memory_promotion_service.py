from __future__ import annotations

from dataclasses import dataclass
from uuid import UUID

from backend.models.memory import MemoryRecord
from backend.models.memory_candidate import MemoryCandidate
from backend.security.authenticated_user import AuthenticatedUser
from backend.services.memory_conflict_resolver import MemoryConflictResolver
from backend.services.memory_learning_policy import (
    MemoryLearningDecision,
    MemoryLearningPolicy,
)
from backend.services.memory_service import MemoryService


@dataclass(frozen=True)
class MemoryPromotionResult:
    promoted: bool
    requires_approval: bool
    memory: MemoryRecord | None
    reason: str


class MemoryPromotionService:
    """
    Security boundary between untrusted memory candidates and durable memory.

    A candidate is only a proposal.

    Promotion requires:
    1. authenticated ownership validation;
    2. MemoryLearningPolicy approval;
    3. explicit authenticated approval when required;
    4. deterministic conflict resolution before activation.

    Candidate data can never grant permissions, capabilities,
    authentication, or authorization.
    """

    def __init__(
        self,
        memory_service: MemoryService,
        policy: MemoryLearningPolicy,
        conflict_resolver: MemoryConflictResolver,
    ) -> None:
        self._memory_service = memory_service
        self._policy = policy
        self._conflict_resolver = conflict_resolver

    def promote(
        self,
        *,
        candidate: MemoryCandidate,
        authenticated_user: AuthenticatedUser,
    ) -> MemoryPromotionResult:
        """
        Evaluate and, when policy allows, persist a candidate.

        Conflicts are resolved only against active memories belonging to
        the authenticated user and matching the candidate memory type.

        This method cannot approve a candidate on behalf of the user when
        policy requires explicit approval.
        """

        self._verify_ownership(
            candidate.authenticated_user_id,
            authenticated_user,
        )

        decision = self._policy.evaluate(candidate)

        if decision.decision == MemoryLearningDecision.REJECT:
            return MemoryPromotionResult(
                promoted=False,
                requires_approval=False,
                memory=None,
                reason=decision.reason,
            )

        memory = self._memory_service.create_memory(
            authenticated_user=authenticated_user,
            memory_type=candidate.memory_type,
            content=candidate.content,
            provenance=candidate.provenance,
            confidence=candidate.confidence,
            sensitivity=candidate.sensitivity,
        )

        if decision.decision == MemoryLearningDecision.REQUIRE_APPROVAL:
            return MemoryPromotionResult(
                promoted=False,
                requires_approval=True,
                memory=memory,
                reason=decision.reason,
            )

        approved_memory = self._activate_with_conflict_resolution(
            memory=memory,
            authenticated_user=authenticated_user,
        )

        return MemoryPromotionResult(
            promoted=True,
            requires_approval=False,
            memory=approved_memory,
            reason=decision.reason,
        )

    def approve(
        self,
        *,
        memory_id: UUID,
        authenticated_user: AuthenticatedUser,
    ) -> MemoryPromotionResult:
        """
        Trusted authenticated approval boundary.

        The approval decision comes from the authenticated application
        action, never from candidate content or an AI-controlled flag.
        """

        memory = self._memory_service.get_memory(
            memory_id=memory_id,
            authenticated_user=authenticated_user,
        )

        if memory.status.value != "candidate":
            raise ValueError("Only candidate memory can be approved.")

        approved_memory = self._activate_with_conflict_resolution(
            memory=memory,
            authenticated_user=authenticated_user,
        )

        return MemoryPromotionResult(
            promoted=True,
            requires_approval=False,
            memory=approved_memory,
            reason="Memory was explicitly approved by the authenticated user.",
        )

    def _activate_with_conflict_resolution(
        self,
        *,
        memory: MemoryRecord,
        authenticated_user: AuthenticatedUser,
    ) -> MemoryRecord:
        """
        Resolve conflicts immediately before activating a memory.

        Only active memories owned by the authenticated user and matching
        the incoming memory type are considered.

        If an existing memory wins, the incoming candidate is deleted
        through MemoryService so the lifecycle change is persisted by
        every repository implementation.
        """

        active_memories = self._memory_service.list_active_memories(
            memory_type=memory.memory_type,
            authenticated_user=authenticated_user,
        )

        for existing in active_memories:
            conflict = self._conflict_resolver.resolve(
                existing=existing,
                incoming=memory,
            )

            if conflict.winner.id == existing.id:
                return self._memory_service.delete_memory(
                    memory_id=memory.id,
                    authenticated_user=authenticated_user,
                )

            self._memory_service.supersede_memory(
                memory_id=existing.id,
                authenticated_user=authenticated_user,
            )

        return self._memory_service.approve_memory(
            memory_id=memory.id,
            authenticated_user=authenticated_user,
        )

    @staticmethod
    def _verify_ownership(
        candidate_user_id: UUID,
        authenticated_user: AuthenticatedUser,
    ) -> None:
        if candidate_user_id != authenticated_user.user_id:
            raise PermissionError(
                "Candidate does not belong to the authenticated user."
            )
