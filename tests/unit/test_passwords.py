"""Tests for backend.security.passwords.

Coverage is organized into four groups: hashing behavior, verification
behavior, error handling for malformed input, and the rehash-detection
path used to migrate users to stronger parameters over time.
"""

from __future__ import annotations

import pytest

from backend.security.passwords import (
    PasswordHashError,
    hash_password,
    needs_rehash,
    verify_password,
)

# --------------------------------------------------------------------------
# Hashing behavior
# --------------------------------------------------------------------------


def test_hash_password_returns_argon2id_hash() -> None:
    """hash_password should produce a hash tagged with the argon2id variant."""
    password = "TestPassword123!"

    password_hash = hash_password(password)

    assert password_hash.startswith("$argon2id$")


def test_hash_password_generates_unique_salts() -> None:
    """Hashing the same password twice must yield different hashes.

    A fixed or missing salt would mean any two users with the same
    password have identical stored hashes, which is the failure mode
    this test guards against.
    """
    password = "TestPassword123!"

    first_hash = hash_password(password)
    second_hash = hash_password(password)

    assert first_hash != second_hash


def test_plaintext_password_is_not_stored_in_hash() -> None:
    """The encoded hash must not contain the plaintext password verbatim."""
    password = "SuperSecretPassword123!"

    password_hash = hash_password(password)

    assert password not in password_hash


def test_empty_password_is_rejected() -> None:
    """hash_password should refuse an empty password rather than hash it."""
    with pytest.raises(ValueError, match="password must not be empty"):
        hash_password("")


# --------------------------------------------------------------------------
# Verification behavior
# --------------------------------------------------------------------------


def test_correct_password_verifies() -> None:
    """A password should verify successfully against its own hash."""
    password = "TestPassword123!"
    password_hash = hash_password(password)

    assert verify_password(password, password_hash) is True


def test_wrong_password_does_not_verify() -> None:
    """An incorrect password should fail verification without raising."""
    password_hash = hash_password("TestPassword123!")

    assert verify_password("WrongPassword123!", password_hash) is False


def test_unicode_password_verifies() -> None:
    """Passwords containing non-ASCII characters should hash and verify correctly."""
    password = "Pässwörd-测试-🔐-123!"

    password_hash = hash_password(password)

    assert verify_password(password, password_hash) is True


# --------------------------------------------------------------------------
# Error handling
# --------------------------------------------------------------------------


def test_malformed_hash_raises_password_hash_error() -> None:
    """A stored value that isn't a valid Argon2 hash should raise
    PasswordHashError rather than silently returning False.

    This distinguishes a data-integrity problem (corrupted or malformed
    stored hash) from an ordinary failed verification attempt.
    """
    with pytest.raises(PasswordHashError, match="stored password hash is invalid"):
        verify_password("TestPassword123!", "not-a-valid-argon2-hash")


# --------------------------------------------------------------------------
# Rehashing
# --------------------------------------------------------------------------


def test_current_hash_does_not_need_rehash() -> None:
    """A hash produced with the module's current parameters should not
    be flagged for rehashing."""
    password_hash = hash_password("TestPassword123!")

    assert needs_rehash(password_hash) is False