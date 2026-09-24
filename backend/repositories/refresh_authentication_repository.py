from __future__ import annotations

from abc import ABC, abstractmethod
from contextlib import AbstractContextManager
from dataclasses import dataclass
from enum import Enum
from typing import Iterator
from uuid import UUID

from psycopg import Connection


class RefreshAuthenticationState(str, Enum):
    VALID = "VALID"
    REPLAY = "REPLAY"
    INVALID = "INVALID"


@dataclass(frozen=True)
class RefreshAuthenticationResult:
    """
    Result produced by PostgreSQL after authenticating a refresh credential.

    Identity fields exist only for VALID and REPLAY results.
    INVALID never exposes ownership information.
    """

    state: RefreshAuthenticationState
    user_id: UUID | None = None
    session_id: UUID | None = None
    token_family_id: UUID | None = None
    refresh_token_id: UUID | None = None

    def __post_init__(self) -> None:
        if self.state is RefreshAuthenticationState.INVALID:
            if any(
                value is not None
                for value in (
                    self.user_id,
                    self.session_id,
                    self.token_family_id,
                    self.refresh_token_id,
                )
            ):
                raise ValueError(
                    "INVALID refresh authentication cannot expose identity."
                )

        if self.state in (
            RefreshAuthenticationState.VALID,
            RefreshAuthenticationState.REPLAY,
        ):
            if any(
                value is None
                for value in (
                    self.user_id,
                    self.session_id,
                    self.token_family_id,
                    self.refresh_token_id,
                )
            ):
                raise ValueError(
                    "Authenticated refresh results require complete identity."
                )


@dataclass(frozen=True)
class RefreshTransactionContext:
    """
    Trusted context for an authenticated refresh transaction.

    The database transaction remains open while this context is used.
    """

    connection: Connection
    authentication: RefreshAuthenticationResult


class RefreshAuthenticationRepository(ABC):
    """
    Boundary for authenticated refresh transactions.

    The transaction must remain open after authentication so refresh-token
    rotation can occur atomically under the same locks and RLS identity.
    """

    @abstractmethod
    def refresh_transaction(
        self,
        presented_token_hash: str,
    ) -> AbstractContextManager[RefreshTransactionContext]:
        """
        Authenticate the refresh credential and yield its authenticated
        PostgreSQL transaction.

        Implementations must never accept a caller-supplied application
        user ID.
        """
        raise NotImplementedError
