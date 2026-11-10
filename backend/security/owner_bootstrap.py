from __future__ import annotations

from typing import Protocol

from backend.security.registration import (
    AccountStore,
    RegistrationInputError,
    normalize_email,
    register_account,
    verify_email,
)

OWNER_MIN_PASSWORD_LENGTH = 16


class OwnerBootstrapError(RuntimeError):
    """
    Raised when the owner account cannot be safely created.

    Messages are safe to show on the console and never contain the
    password.
    """


class AccountCounter(Protocol):
    def count_accounts(self) -> int:
        """Return the number of accounts, regardless of row-level security."""


def bootstrap_owner(
    accounts: AccountStore,
    counter: AccountCounter,
    email: str,
    password: str,
) -> str:
    """
    Create the single, already-verified owner account.

    Eldorado is a private single-owner system, so this refuses to run
    when any account exists. It reuses the registration service for
    validation and hashing, then consumes the verification token
    immediately, because the operator running this command locally with
    database-owner access is the proof of ownership.

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

    if counter.count_accounts() != 0:
        raise OwnerBootstrapError(
            "An account already exists. Refusing to create a second owner."
        )

    try:
        result = register_account(accounts, normalized_email, password)
    except RegistrationInputError as exc:
        raise OwnerBootstrapError(str(exc)) from None

    if result.verification_token is None:
        raise OwnerBootstrapError("The owner account could not be created.")

    if not verify_email(accounts, result.verification_token):
        raise OwnerBootstrapError(
            "The owner account was created but could not be verified."
        )

    return normalized_email