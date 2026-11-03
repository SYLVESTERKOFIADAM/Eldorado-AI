from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol
from uuid import UUID

from backend.security.passwords import (
    PasswordHashError,
    hash_password,
    needs_rehash,
    verify_password,
)

MAX_EMAIL_LENGTH = 320
MAX_PASSWORD_LENGTH = 1024

# Hashed with the same Argon2id parameters as real credentials, so an
# unknown account costs the same time as a wrong password.
_DUMMY_HASH = hash_password("eldorado-dummy-password-not-a-credential")


@dataclass(frozen=True)
class LoginCredential:
    user_id: UUID
    password_hash: str


@dataclass(frozen=True)
class LoginSuccess:
    user_id: UUID
    needs_rehash: bool


class CredentialStore(Protocol):
    def get_login_credential(
        self,
        email: str,
    ) -> LoginCredential | None:
        """Return a credential only for a verified, active account."""


def authenticate_password(
    store: CredentialStore,
    email: str,
    password: str,
) -> LoginSuccess | None:
    """
    Verify an email/password pair.

    Returns None for every failure (malformed input, unknown, unverified
    or inactive account, wrong password, corrupted stored hash) so
    callers cannot distinguish the cause.
    """
    if (
        not isinstance(email, str)
        or not isinstance(password, str)
        or not email.strip()
        or not password
        or len(email) > MAX_EMAIL_LENGTH
        or len(password) > MAX_PASSWORD_LENGTH
    ):
        return None

    credential = store.get_login_credential(email.strip().lower())

    if credential is None:
        verify_password(password, _DUMMY_HASH)
        return None

    try:
        matched = verify_password(password, credential.password_hash)
    except PasswordHashError:
        return None

    if not matched:
        return None

    return LoginSuccess(
        user_id=credential.user_id,
        needs_rehash=needs_rehash(credential.password_hash),
    )