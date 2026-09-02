from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from backend.models.memory import (
    MemoryProvenance,
    MemorySensitivity,
)
from backend.models.memory_candidate import MemoryCandidate


class MemoryLearningDecision(str, Enum):
    ALLOW = "allow"
    REQUIRE_APPROVAL = "require_approval"
    REJECT = "reject"


@dataclass(frozen=True)
class MemoryLearningPolicyDecision:
    decision: MemoryLearningDecision
    reason: str


class MemoryLearningPolicy:
    """
    Security policy governing promotion of untrusted memory candidates.

    A candidate is only a proposal. This policy never grants permissions,
    authorizes tools, authenticates users, or changes security policy.
    """

    MIN_INFERENCE_CONFIDENCE = 0.85

    def evaluate(
        self,
        candidate: MemoryCandidate,
    ) -> MemoryLearningPolicyDecision:
        if candidate.sensitivity == MemorySensitivity.RESTRICTED:
            if candidate.provenance != (
                MemoryProvenance.EXPLICIT_USER_STATEMENT
            ):
                return MemoryLearningPolicyDecision(
                    decision=MemoryLearningDecision.REJECT,
                    reason=(
                        "Restricted memory requires an explicit user "
                        "statement."
                    ),
                )

        if candidate.provenance == MemoryProvenance.EXPLICIT_USER_STATEMENT:
            return MemoryLearningPolicyDecision(
                decision=MemoryLearningDecision.ALLOW,
                reason="Explicit user statement may be retained.",
            )

        if candidate.provenance == MemoryProvenance.USER_FEEDBACK:
            return MemoryLearningPolicyDecision(
                decision=MemoryLearningDecision.ALLOW,
                reason="Explicit user feedback may be retained.",
            )

        if candidate.provenance in {
            MemoryProvenance.EXTERNAL_CONTENT,
            MemoryProvenance.IMPORTED_DATA,
        }:
            return MemoryLearningPolicyDecision(
                decision=MemoryLearningDecision.REQUIRE_APPROVAL,
                reason=(
                    "External or imported information requires explicit "
                    "user approval before durable retention."
                ),
            )

        if candidate.provenance == MemoryProvenance.CONVERSATION_INFERENCE:
            if candidate.sensitivity in {
                MemorySensitivity.SENSITIVE,
                MemorySensitivity.RESTRICTED,
            }:
                return MemoryLearningPolicyDecision(
                    decision=MemoryLearningDecision.REJECT,
                    reason=(
                        "Sensitive inferred information cannot be "
                        "automatically promoted to durable memory."
                    ),
                )

            if candidate.confidence >= self.MIN_INFERENCE_CONFIDENCE:
                return MemoryLearningPolicyDecision(
                    decision=MemoryLearningDecision.REQUIRE_APPROVAL,
                    reason=(
                        "Inferred memory requires explicit user approval."
                    ),
                )

            return MemoryLearningPolicyDecision(
                decision=MemoryLearningDecision.REJECT,
                reason=(
                    "Inferred memory confidence is below the promotion "
                    "threshold."
                ),
            )

        return MemoryLearningPolicyDecision(
            decision=MemoryLearningDecision.REJECT,
            reason="Unknown memory provenance is not trusted.",
        )
