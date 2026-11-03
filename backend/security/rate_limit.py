from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from typing import Protocol

_BUCKET_PATTERN = re.compile(r"^[a-z_]{1,32}$")


class RateLimitExceeded(Exception):
    """Raised when an attempt exceeds its rate limit."""


class RateLimitStore(Protocol):
    def hit(
        self,
        bucket: str,
        key_hash: str,
        limit: int,
        window_seconds: int,
    ) -> bool:
        """Record one attempt. True if allowed, False if over the limit."""


@dataclass(frozen=True)
class RateLimitPolicy:
    bucket: str
    limit: int
    window_seconds: int

    def __post_init__(self) -> None:
        if _BUCKET_PATTERN.fullmatch(self.bucket) is None:
            raise ValueError("invalid rate limit bucket")

        if not 1 <= self.limit <= 100000:
            raise ValueError("invalid rate limit")

        if not 1 <= self.window_seconds <= 86400:
            raise ValueError("invalid rate limit window")


# Starting policies. Tune with real traffic data. Endpoints apply them.
LOGIN_PER_ACCOUNT = RateLimitPolicy("login_account", 10, 900)
LOGIN_PER_IP = RateLimitPolicy("login_ip", 30, 900)
REGISTER_PER_EMAIL = RateLimitPolicy("register_email", 3, 3600)
REGISTER_PER_IP = RateLimitPolicy("register_ip", 5, 3600)
VERIFY_PER_IP = RateLimitPolicy("verify_ip", 20, 3600)


def hash_rate_limit_key(bucket: str, identifier: str) -> str:
    """Stable SHA-256 key for an identifier within one bucket."""
    normalized = identifier.strip().lower()

    if not normalized:
        raise ValueError("rate limit identifier must not be empty")

    return hashlib.sha256(
        f"{bucket}\x00{normalized}".encode("utf-8")
    ).hexdigest()


def check_rate_limit(
    store: RateLimitStore,
    policy: RateLimitPolicy,
    identifier: str,
) -> bool:
    """
    Record an attempt. Returns True if allowed.

    Fails closed: store errors propagate, and callers must deny the
    request when this function raises.
    """
    if not isinstance(identifier, str):
        raise ValueError("rate limit identifier must be a string")

    return store.hit(
        policy.bucket,
        hash_rate_limit_key(policy.bucket, identifier),
        policy.limit,
        policy.window_seconds,
    )


def enforce_rate_limit(
    store: RateLimitStore,
    policy: RateLimitPolicy,
    identifier: str,
) -> None:
    if not check_rate_limit(store, policy, identifier):
        raise RateLimitExceeded("rate limit exceeded")