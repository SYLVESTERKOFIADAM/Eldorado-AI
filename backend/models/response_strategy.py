from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class ResponseTone(str, Enum):
    NEUTRAL = "neutral"
    CALM = "calm"
    SUPPORTIVE = "supportive"
    DIRECT = "direct"
    ENCOURAGING = "encouraging"


class ResponseVerbosity(str, Enum):
    CONCISE = "concise"
    NORMAL = "normal"
    DETAILED = "detailed"


class ResponseDirectness(str, Enum):
    LOW = "low"
    NORMAL = "normal"
    HIGH = "high"


@dataclass(frozen=True)
class ResponseStrategy:
    """
    Safe response-generation preferences derived from the current
    interaction state.

    ResponseStrategy controls presentation only.

    It must never grant permissions, authorize tools, modify security
    policy, or change authentication state.
    """

    tone: ResponseTone = ResponseTone.NEUTRAL
    verbosity: ResponseVerbosity = ResponseVerbosity.NORMAL
    directness: ResponseDirectness = ResponseDirectness.NORMAL