from __future__ import annotations

import re

import pytest

from backend.security.email_verification import (
    generate_email_verification_token,
    hash_email_verification_token,
)


def test_generated_token_has_a_sha256_hash() -> None:
    token = generate_email_verification_token()

    assert re.fullmatch(r"[0-9a-f]{64}", token.token_hash)


def test_generated_token_hash_matches_raw_token() -> None:
    token = generate_email_verification_token()

    assert hash_email_verification_token(token.raw_token) == token.token_hash


def test_generated_tokens_are_unique() -> None:
    first = generate_email_verification_token()
    second = generate_email_verification_token()

    assert first.raw_token != second.raw_token
    assert first.token_hash != second.token_hash


def test_hashing_same_token_is_deterministic() -> None:
    token = generate_email_verification_token()

    assert (
        hash_email_verification_token(token.raw_token)
        == hash_email_verification_token(token.raw_token)
    )


@pytest.mark.parametrize("raw_token", ["", None, 123, b"token"])
def test_hashing_rejects_invalid_token_input(raw_token: object) -> None:
    with pytest.raises(ValueError):
        hash_email_verification_token(raw_token)  # type: ignore[arg-type]


def test_hashing_rejects_non_ascii_token() -> None:
    with pytest.raises(ValueError, match="verification token is invalid"):
        hash_email_verification_token("token-ñ")
