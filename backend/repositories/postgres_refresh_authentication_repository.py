from __future__ import annotations

from contextlib import contextmanager
from typing import Iterator
from uuid import UUID

from backend.database.connection import DatabaseConnection
from backend.repositories.refresh_authentication_repository import (
    RefreshAuthenticationRepository,
    RefreshAuthenticationResult,
    RefreshAuthenticationState,
    RefreshTransactionContext,
)


class PostgresRefreshAuthenticationRepository(
    RefreshAuthenticationRepository
):
    """
    PostgreSQL refresh-authentication implementation.

    DatabaseConnection owns the single authentication-function invocation
    and transaction boundary. This repository translates the trusted
    database result into the application contract.
    """

    def __init__(self, database: DatabaseConnection) -> None:
        self._database = database

    @contextmanager
    def refresh_transaction(
        self,
        presented_token_hash: str,
    ) -> Iterator[RefreshTransactionContext]:
        with self._database.refresh_transaction(
            presented_token_hash
        ) as (connection, database_authentication):

            state = RefreshAuthenticationState(
                database_authentication.state
            )

            if state is RefreshAuthenticationState.INVALID:
                raise PermissionError(
                    "Refresh credential is invalid."
                )

            if (
                database_authentication.user_id is None
                or database_authentication.session_id is None
                or database_authentication.token_family_id is None
                or database_authentication.refresh_token_id is None
            ):
                raise RuntimeError(
                    "Authenticated refresh result is incomplete."
                )

            result = RefreshAuthenticationResult(
                state=state,
                user_id=UUID(
                    str(database_authentication.user_id)
                ),
                session_id=UUID(
                    str(database_authentication.session_id)
                ),
                token_family_id=UUID(
                    str(database_authentication.token_family_id)
                ),
                refresh_token_id=UUID(
                    str(database_authentication.refresh_token_id)
                ),
            )

            yield RefreshTransactionContext(
                connection=connection,
                authentication=result,
            )
