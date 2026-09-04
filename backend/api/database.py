from __future__ import annotations

import os
from contextlib import contextmanager
from typing import Iterator

from psycopg import Connection
from fastapi import Depends

from backend.api.auth import require_authenticated_user
from backend.database.connection import DatabaseConnection
from backend.security.authenticated_user import AuthenticatedUser


_DATABASE_DSN_ENV_VAR = "ELDORADO_DATABASE_DSN"


def _get_database_dsn() -> str:
    dsn = os.getenv(_DATABASE_DSN_ENV_VAR)

    if dsn is None or not dsn.strip():
        raise RuntimeError(
            f"{_DATABASE_DSN_ENV_VAR} is not configured"
        )

    return dsn


def get_database_connection() -> DatabaseConnection:
    """
    Construct the application's PostgreSQL connection boundary.

    The DSN comes only from controlled application configuration.
    It is never derived from request data, memory, or AI output.
    """
    return DatabaseConnection(_get_database_dsn())


@contextmanager
def authenticated_transaction(
    user: AuthenticatedUser,
    database: DatabaseConnection,
) -> Iterator[Connection]:
    """
    Open a PostgreSQL transaction bound to the authenticated user.

    The UUID originates exclusively from the verified authentication
    dependency and is passed directly to the existing transaction/RLS
    boundary.
    """
    with database.transaction(user.user_id) as connection:
        yield connection


def get_authenticated_transaction(
    user: AuthenticatedUser = Depends(require_authenticated_user),
    database: DatabaseConnection = Depends(get_database_connection),
) -> Iterator[Connection]:
    """
    FastAPI dependency for a transaction authenticated to the request user.
    """
    with authenticated_transaction(user, database) as connection:
        yield connection