from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
from typing import Iterator
from uuid import UUID

import psycopg
from psycopg import Connection


@dataclass(frozen=True)
class RefreshDatabaseAuthentication:
    """
    Trusted authentication result returned by PostgreSQL.

    INVALID never carries identity. VALID and REPLAY carry the complete
    identity required by the refresh transaction.
    """

    state: str
    user_id: UUID | None
    session_id: UUID | None
    token_family_id: UUID | None
    refresh_token_id: UUID | None


class DatabaseConnection:
    """
    PostgreSQL connection boundary for Eldorado-AI.

    Security properties:
    - Uses parameterized SQL.
    - Establishes authenticated application identity transaction-locally.
    - Never uses a session-level app.current_user_id.
    - Refresh authentication occurs before establishing RLS identity.
    - Refresh authentication and subsequent rotation share one transaction.
    """

    def __init__(self, dsn: str) -> None:
        if not dsn.strip():
            raise ValueError("Database DSN must not be empty.")

        self._dsn = dsn

    @contextmanager
    def transaction(self, user_id: UUID) -> Iterator[Connection]:
        """
        Open a transaction authenticated to exactly one application user.
        """
        with psycopg.connect(self._dsn) as connection:
            with connection.transaction():
                with connection.cursor() as cursor:
                    cursor.execute(
                        "SELECT set_config("
                        "'app.current_user_id', %s, true"
                        ")",
                        (str(user_id),),
                    )

                yield connection

    @contextmanager
    def refresh_transaction(
        self,
        presented_token_hash: str,
    ) -> Iterator[
        tuple[Connection, RefreshDatabaseAuthentication]
    ]:
        """
        Authenticate a refresh credential and establish its trusted RLS
        identity within the same transaction.

        The SECURITY DEFINER authentication function:
        - locks refresh_tokens first;
        - locks the owning session second;
        - validates lifecycle state;
        - returns the trusted user identity.

        VALID and REPLAY establish the trusted RLS identity.

        INVALID terminates the transaction without yielding a connection.

        The transaction remains open after authentication so refresh-token
        rotation or replay-family revocation can execute atomically under
        the same locks.
        """
        if not isinstance(presented_token_hash, str):
            raise TypeError(
                "Presented refresh token hash must be a string."
            )

        if not presented_token_hash.strip():
            raise ValueError(
                "Presented refresh token hash must not be blank."
            )

        with psycopg.connect(self._dsn) as connection:
            with connection.transaction():
                row = connection.execute(
                    """
                    SELECT
                        authentication_state,
                        user_id,
                        session_id,
                        token_family_id,
                        refresh_token_id
                    FROM public.authenticate_and_lock_refresh_credential(%s)
                    """,
                    (presented_token_hash,),
                ).fetchone()

                if row is None:
                    raise RuntimeError(
                        "Refresh authentication returned no result."
                    )

                state = str(row[0])

                if state == "INVALID":
                    raise PermissionError(
                        "Refresh credential is invalid."
                    )

                if state not in {"VALID", "REPLAY"}:
                    raise RuntimeError(
                        "Unknown refresh authentication state."
                    )

                user_id = row[1]

                if not isinstance(user_id, UUID):
                    user_id = UUID(str(user_id))

                session_id = row[2]
                token_family_id = row[3]
                refresh_token_id = row[4]

                authentication = RefreshDatabaseAuthentication(
                    state=state,
                    user_id=user_id,
                    session_id=UUID(str(session_id)),
                    token_family_id=UUID(str(token_family_id)),
                    refresh_token_id=UUID(str(refresh_token_id)),
                )

                # Both VALID and REPLAY require the trusted identity.
                # REPLAY needs it so the service can revoke the token
                # family through the normal RLS boundary.
                connection.execute(
                    "SELECT set_config("
                    "'app.current_user_id', %s, true"
                    ")",
                    (str(user_id),),
                )

                yield connection, authentication
