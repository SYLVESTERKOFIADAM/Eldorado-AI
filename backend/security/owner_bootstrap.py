from __future__ import annotations

from typing import Protocol
from uuid import UUID

from backend.security.passwords import hash_password
from backend.security.registration import (
    RegistrationInputError,
    normalize_email,
    validate_password,
)

OWNER_MIN_PASSWORD_LENGTH = 16


class OwnerBootstrapError(RuntimeError):
    """
    Raised when the owner account cannot be safely created.

    Messages are safe to show on the console and never contain the
    password.
    """


class OwnerStore(Protocol):
    def create_owner_account(
        self,
        email: str,
        password_hash: str,
    ) -> UUID | None:
        """
        Create the verified owner and return its id, or None when an
        account already exists.
        """


def bootstrap_owner(
    store: OwnerStore,
    email: str,
    password: str,
) -> str:
    """
    Create the single, already-verified owner account.

    Eldorado is a private single-owner system. This validates and hashes
    the credentials, then asks the database to create the owner in one
    locked, atomic step (bootstrap_owner_account, migration 0013). The
    database refuses when any account exists, so the single-owner rule
    holds even if two bootstraps race. The operator running this command
    locally with database-owner access is the proof of ownership, so the
    account is created already verified.

    Returns the normalized owner email address.
    """
    try:
        normalized_email = normalize_email(email)
    except RegistrationInputError as exc:
        raise OwnerBootstrapError(str(exc)) from None

    if (
        not isinstance(password, str)
        or len(password) < OWNER_MIN_PASSWORD_LENGTH
    ):
        raise OwnerBootstrapError(
            "Owner password must be at least "
            f"{OWNER_MIN_PASSWORD_LENGTH} characters."
        )

    try:
        validate_password(password, normalized_email)
    except RegistrationInputError as exc:
        raise OwnerBootstrapError(str(exc)) from None

    owner_id = store.create_owner_account(
        normalized_email,
        hash_password(password),
    )

    if owner_id is None:
        raise OwnerBootstrapError(
            "An account already exists. Refusing to create a second owner."
        )

    return normalized_email