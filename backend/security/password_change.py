from __future__ import annotations

from enum import Enum
from typing import Protocol
from uuid import UUID

from backend.security.passwords import (
    PasswordHashError,
    hash_password,
    verify_password,
)
from backend.security.registration import (
    MAX_PASSWORD_LENGTH,
    RegistrationInputError,
    validate_password,
)


class ChangeOutcome(str, Enum):
    CHANGED = "CHANGED"
    WRONG_CURRENT = "WRONG_CURRENT"
    CONFLICT = "CONFLICT"


class PasswordChangeStore(Protocol):
    def get_password_hash(self, user_id: UUID) -> str | None:
        """The authenticated user's stored hash, or None."""

    def replace_password_hash(
        self,
        user_id: UUID,
        expected_hash: str,
        new_hash: str,
    ) -> bool:
        """
        Compare-and-swap the stored hash and revoke the user's sessions.

        False when the stored hash no longer matches expected_hash.
        """


def change_password(
    store: PasswordChangeStore,
    user_id: UUID,
    current_password: str,
    new_password: str,
) -> ChangeOutcome:
    """
    Change an authenticated user's password.

    Raises RegistrationInputError when the new password breaks policy.
    Store errors propagate, and callers must fail closed.
    """
    validate_password(new_password, "")

    if (
        not isinstance(current_password, str)
        or not current_password
        or len(current_password) > MAX_PASSWORD_LENGTH
    ):
        return ChangeOutcome.WRONG_CURRENT

    if new_password == current_password:
        raise RegistrationInputError(
            "New password must be different from the current password."
        )

    stored_hash = store.get_password_hash(user_id)

    if stored_hash is None:
        return ChangeOutcome.WRONG_CURRENT

    try:
        matched = verify_password(current_password, stored_hash)
    except PasswordHashError:
        return ChangeOutcome.WRONG_CURRENT

    if not matched:
        return ChangeOutcome.WRONG_CURRENT

    if store.replace_password_hash(
        user_id,
        stored_hash,
        hash_password(new_password),
    ):
        return ChangeOutcome.CHANGED

    return ChangeOutcome.CONFLICT