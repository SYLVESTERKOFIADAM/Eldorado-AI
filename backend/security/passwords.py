from __future__ import annotations

from argon2 import PasswordHasher
from argon2.exceptions import (
    InvalidHashError,
    VerificationError,
    VerifyMismatchError,
)


_HASHER = PasswordHasher(
    time_cost=3,
    memory_cost=65536,  # 64 MiB
    parallelism=4,
    hash_len=32,
    salt_len=16,
)


class PasswordHashError(Exception):
    """Raised when a stored password hash is invalid or corrupted."""


def hash_password(plain_password: str) -> str:
    """
    Hash a plaintext password using Argon2id.

    Password policy is enforced by the authentication layer.
    This function only rejects an empty password.
    """
    if not plain_password:
        raise ValueError("password must not be empty")

    return _HASHER.hash(plain_password)


def verify_password(
    plain_password: str,
    stored_hash: str,
) -> bool:
    """
    Verify a plaintext password against an encoded Argon2id hash.

    Returns False when the password is incorrect.
    Raises PasswordHashError when the stored hash is malformed
    or corrupted.
    """
    try:
        _HASHER.verify(stored_hash, plain_password)
        return True

    except VerifyMismatchError:
        return False

    except (VerificationError, InvalidHashError) as exc:
        raise PasswordHashError(
            "stored password hash is invalid"
        ) from exc


def needs_rehash(stored_hash: str) -> bool:
    """
    Return True when the stored hash no longer matches the
    module's current Argon2id parameters.
    """
    return _HASHER.check_needs_rehash(stored_hash)