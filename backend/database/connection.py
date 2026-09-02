from __future__ import annotations

from contextlib import contextmanager
from typing import Iterator
from uuid import UUID

import psycopg
from psycopg import Connection


class DatabaseConnection:
    """
    PostgreSQL connection boundary for Eldorado-AI.

    Security properties:
    - Uses parameterized SQL.
    - Establishes the authenticated application user ID transaction-locally.
    - Never uses a session-level app.current_user_id.
    - Transaction completion automatically clears SET LOCAL state.
    """

    def __init__(self, dsn: str) -> None:
        if not dsn.strip():
            raise ValueError("Database DSN must not be empty.")

        self._dsn = dsn

    @contextmanager
    def transaction(self, user_id: UUID) -> Iterator[Connection]:
        """
        Open a transaction authenticated to exactly one application user.

        The RLS identity is transaction-local and therefore cannot leak
        into a later transaction when the connection is reused.
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