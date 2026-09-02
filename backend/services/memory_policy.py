from __future__ import annotations

from dataclasses import dataclass

from backend.models.memory import (
    MemoryProvenance,
    MemoryRecord,
    MemoryStatus,
)


@dataclass(frozen=True)
class MemoryPolicyDecision:
    allowed: bool
    reason: str


class MemoryPolicy:
    """
    Security policy for memory retention and activation.

    Memory is personalization data, not authority.
    This policy must never grant permissions or tool capabilities.
    """

    def evaluate(self, memory: MemoryRecord) -> MemoryPolicyDecision:
        # Security containment states take precedence over all other checks.
        if memory.status == MemoryStatus.QUARANTINED:
            return MemoryPolicyDecision(
                allowed=False,
                reason="Quarantined memory cannot be activated.",
            )

        if memory.status in {
            MemoryStatus.DELETED,
            MemoryStatus.SUPERSEDED,
            MemoryStatus.EXPIRED,
        }:
            return MemoryPolicyDecision(
                allowed=False,
                reason="Memory is not eligible for active use.",
            )

        if memory.is_expired:
            return MemoryPolicyDecision(
                allowed=False,
                reason="Memory has expired.",
            )

        if memory.provenance in {
            MemoryProvenance.EXTERNAL_CONTENT,
            MemoryProvenance.IMPORTED_DATA,
        } and not memory.user_approved:
            return MemoryPolicyDecision(
                allowed=False,
                reason=(
                    "External or imported memory requires explicit "
                    "user approval before activation."
                ),
            )

        return MemoryPolicyDecision(
            allowed=True,
            reason="Memory satisfies the current retention policy.",
        )
