from __future__ import annotations

import re

import pytest

from backend.security.refresh_token import (
    generate_refresh_token,
    hash_refresh_token,
)


def test_generated_token_has_a_sha256_hash_matching_the_raw_token() -> None:
    token = generate_refresh_token()

    assert re.fullmatch(r"[0-9a-f]{64}", token.token_hash)
    assert hash_refresh_token(token.raw_token) == token.token_hash


def test_generated_tokens_are_unique_and_long() -> None:
    first = generate_refresh_token()
    second = generate_refresh_token()

    assert first.raw_token != second.raw_token
    assert first.token_hash != second.token_hash
    assert len(first.raw_token) >= 43


def test_raw_token_is_not_in_repr() -> None:
    token = generate_refresh_token()

    assert token.raw_token not in repr(token)


@pytest.mark.parametrize("raw_token", ["", None, 123, b"token"])
def test_hashing_rejects_invalid_input(raw_token: object) -> None:
    with pytest.raises(ValueError):
        hash_refresh_token(raw_token)  # type: ignore[arg-type]


def test_hashing_rejects_non_ascii_token() -> None:
    with pytest.raises(ValueError, match="refresh token is invalid"):
        hash_refresh_token("token-ñ")