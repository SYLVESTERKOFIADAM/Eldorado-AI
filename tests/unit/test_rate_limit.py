from __future__ import annotations

import re

import pytest

from backend.security import rate_limit
from backend.security.rate_limit import (
    RateLimitExceeded,
    RateLimitPolicy,
    check_rate_limit,
    enforce_rate_limit,
    hash_rate_limit_key,
)

POLICY = RateLimitPolicy("test_bucket", 3, 60)


class FakeStore:
    def __init__(self, allow: bool = True) -> None:
        self.allow = allow
        self.calls: list[tuple[str, str, int, int]] = []

    def hit(
        self, bucket: str, key_hash: str, limit: int, window_seconds: int
    ) -> bool:
        self.calls.append((bucket, key_hash, limit, window_seconds))
        return self.allow


class FailingStore:
    def hit(self, *args: object) -> bool:
        raise RuntimeError("database unavailable")


def test_key_hash_is_sha256_hex_and_deterministic() -> None:
    first = hash_rate_limit_key("login_ip", "203.0.113.7")

    assert re.fullmatch(r"[0-9a-f]{64}", first)
    assert first == hash_rate_limit_key("login_ip", "203.0.113.7")


def test_key_hash_normalizes_case_and_whitespace() -> None:
    assert hash_rate_limit_key("b", "  User@Example.COM ") == (
        hash_rate_limit_key("b", "user@example.com")
    )


def test_same_identifier_in_different_buckets_differs() -> None:
    assert hash_rate_limit_key("a", "x") != hash_rate_limit_key("b", "x")


def test_empty_identifier_is_rejected() -> None:
    with pytest.raises(ValueError):
        hash_rate_limit_key("b", "   ")


def test_check_passes_policy_values_and_hashed_key() -> None:
    store = FakeStore()

    assert check_rate_limit(store, POLICY, "user@example.com") is True

    bucket, key_hash, limit, window = store.calls[0]
    assert (bucket, limit, window) == ("test_bucket", 3, 60)
    assert "user@example.com" not in key_hash
    assert key_hash == hash_rate_limit_key("test_bucket", "user@example.com")


def test_check_returns_false_when_store_denies() -> None:
    assert check_rate_limit(FakeStore(allow=False), POLICY, "x") is False


def test_enforce_raises_when_over_limit() -> None:
    with pytest.raises(RateLimitExceeded):
        enforce_rate_limit(FakeStore(allow=False), POLICY, "x")


def test_enforce_allows_within_limit() -> None:
    enforce_rate_limit(FakeStore(allow=True), POLICY, "x")


def test_store_errors_propagate_so_callers_fail_closed() -> None:
    with pytest.raises(RuntimeError):
        check_rate_limit(FailingStore(), POLICY, "x")  # type: ignore[arg-type]


def test_non_string_identifier_is_rejected() -> None:
    with pytest.raises(ValueError):
        check_rate_limit(FakeStore(), POLICY, None)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("bucket", "limit", "window"),
    [
        ("Bad-Bucket", 1, 60),
        ("", 1, 60),
        ("a" * 33, 1, 60),
        ("ok", 0, 60),
        ("ok", 100001, 60),
        ("ok", 1, 0),
        ("ok", 1, 86401),
    ],
)
def test_invalid_policies_are_rejected(
    bucket: str, limit: int, window: int
) -> None:
    with pytest.raises(ValueError):
        RateLimitPolicy(bucket, limit, window)


def test_builtin_policies_are_valid_and_distinct() -> None:
    policies = [
        rate_limit.LOGIN_PER_ACCOUNT,
        rate_limit.LOGIN_PER_IP,
        rate_limit.REGISTER_PER_EMAIL,
        rate_limit.REGISTER_PER_IP,
        rate_limit.VERIFY_PER_IP,
    ]

    assert len({policy.bucket for policy in policies}) == len(policies)