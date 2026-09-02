from __future__ import annotations

from dataclasses import dataclass
from uuid import UUID


@dataclass(frozen=True)
class AuthenticatedUser:
    """
    Trusted application identity established by the authentication layer.

    This identity must originate from authentication, never from user
    supplied content, memory, or AI-generated output.
    """

    user_id: UUID
