from __future__ import annotations

from dataclasses import dataclass

from backend.models.memory import MemoryProvenance, MemoryRecord


@dataclass(frozen=True)
class MemoryConflictDecision:
    """
    Deterministic decision for resolving conflicting memory records.

    Memory remains personalization data and never becomes an authority
    for authentication, authorization, permissions, or tool access.
    """

    winner: MemoryRecord
    loser: MemoryRecord
    reason: str


class MemoryConflictResolver:
    """
    Resolves conflicts between memory records using provenance precedence.

    Precedence:
        explicit user statement
        > user feedback
        > imported/external explicit evidence
        > conversation inference

    If precedence is equal, the more recently updated memory wins.

    The resolver does not delete records. The losing record is expected
    to be marked SUPERSEDED by the application service.
    """

    _PROVENANCE_PRIORITY = {
        MemoryProvenance.EXPLICIT_USER_STATEMENT: 4,
        MemoryProvenance.USER_FEEDBACK: 3,
        MemoryProvenance.IMPORTED_DATA: 2,
        MemoryProvenance.EXTERNAL_CONTENT: 2,
        MemoryProvenance.CONVERSATION_INFERENCE: 1,
    }

    def resolve(
        self,
        *,
        existing: MemoryRecord,
        incoming: MemoryRecord,
    ) -> MemoryConflictDecision:
        if existing.user_id != incoming.user_id:
            raise PermissionError(
                "Cannot resolve conflicts across different users."
            )

        existing_priority = self._PROVENANCE_PRIORITY[existing.provenance]
        incoming_priority = self._PROVENANCE_PRIORITY[incoming.provenance]

        if incoming_priority > existing_priority:
            return MemoryConflictDecision(
                winner=incoming,
                loser=existing,
                reason="Incoming memory has stronger provenance.",
            )

        if existing_priority > incoming_priority:
            return MemoryConflictDecision(
                winner=existing,
                loser=incoming,
                reason="Existing memory has stronger provenance.",
            )

        if incoming.updated_at > existing.updated_at:
            return MemoryConflictDecision(
                winner=incoming,
                loser=existing,
                reason="Provenance is equal; incoming memory is more recent.",
            )

        return MemoryConflictDecision(
            winner=existing,
            loser=incoming,
            reason="Existing memory has equal or newer evidence.",
        )
