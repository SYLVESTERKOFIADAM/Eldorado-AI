from __future__ import annotations

from datetime import datetime, timedelta, timezone
from uuid import UUID, uuid4

import psycopg
import pytest

from backend.database.connection import DatabaseConnection
from backend.repositories.postgres_refresh_authentication_repository import (
    PostgresRefreshAuthenticationRepository,
)


APP_DSN = "dbname=postgres user=eldorado_app host=localhost port=5432"
ADMIN_DSN = "dbname=postgres user=postgres host=localhost port=5432"

USER_A = UUID("76bab0d0-94f5-4925-a729-62e31726456f")


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _create_session(
    connection: psycopg.Connection,
) -> UUID:
    session_id = uuid4()
    created_at = _now()

    connection.execute(
        """
        INSERT INTO public.sessions (
            id,
            user_id,
            token_family_id,
            created_at,
            expires_at
        )
        VALUES (
            %s,
            %s,
            %s,
            %s,
            %s
        )
        """,
        (
            session_id,
            USER_A,
            uuid4(),
            created_at,
            created_at + timedelta(hours=1),
        ),
    )

    return session_id


def _create_refresh_token(
    connection: psycopg.Connection,
    session_id: UUID,
    token_hash: str,
) -> UUID:
    token_id = uuid4()
    issued_at = _now()

    connection.execute(
        """
        INSERT INTO public.refresh_tokens (
            id,
            session_id,
            token_hash,
            issued_at,
            expires_at
        )
        VALUES (
            %s,
            %s,
            %s,
            %s,
            %s
        )
        """,
        (
            token_id,
            session_id,
            token_hash,
            issued_at,
            issued_at + timedelta(days=30),
        ),
    )

    return token_id


def _seed_credential(token_hash: str) -> tuple[UUID, UUID]:
    with psycopg.connect(ADMIN_DSN) as connection:
        with connection.transaction():
            session_id = _create_session(connection)
            token_id = _create_refresh_token(
                connection,
                session_id,
                token_hash,
            )

    return session_id, token_id


def _cleanup_credential(
    session_id: UUID,
    token_id: UUID,
) -> None:
    with psycopg.connect(ADMIN_DSN) as connection:
        with connection.transaction():
            connection.execute(
                "DELETE FROM public.refresh_tokens WHERE id = %s",
                (token_id,),
            )
            connection.execute(
                "DELETE FROM public.sessions WHERE id = %s",
                (session_id,),
            )


def test_valid_refresh_transaction_establishes_rls_identity():
    token_hash = f"transaction-valid-{uuid4()}"
    session_id, token_id = _seed_credential(token_hash)

    try:
        database = DatabaseConnection(ADMIN_DSN)

        with database.refresh_transaction(token_hash) as (
            refresh_connection,
            authentication,
        ):
            assert authentication.state == "VALID"
            assert authentication.user_id == USER_A
            assert authentication.session_id == session_id
            assert authentication.refresh_token_id == token_id

            current_user = refresh_connection.execute(
                "SELECT public.current_app_user_id()"
            ).fetchone()[0]

            assert current_user == USER_A

            visible = refresh_connection.execute(
                """
                SELECT COUNT(*)
                FROM public.sessions
                WHERE id = %s
                """,
                (session_id,),
            ).fetchone()[0]

            assert visible == 1
    finally:
        _cleanup_credential(session_id, token_id)


def test_refresh_transaction_identity_is_transaction_local():
    token_hash = f"transaction-local-{uuid4()}"
    session_id, token_id = _seed_credential(token_hash)

    try:
        database = DatabaseConnection(ADMIN_DSN)

        with database.refresh_transaction(token_hash) as (
            refresh_connection,
            authentication,
        ):
            assert authentication.user_id == USER_A

            current_user = refresh_connection.execute(
                "SELECT public.current_app_user_id()"
            ).fetchone()[0]

            assert current_user == USER_A
    finally:
        _cleanup_credential(session_id, token_id)

    with psycopg.connect(APP_DSN) as app_connection:
        with app_connection.transaction():
            identity = app_connection.execute(
                "SELECT public.current_app_user_id()"
            ).fetchone()[0]

            assert identity is None


def test_invalid_refresh_transaction_does_not_establish_identity():
    database = DatabaseConnection(ADMIN_DSN)

    with pytest.raises(PermissionError):
        with database.refresh_transaction(
            f"unknown-{uuid4()}"
        ):
            pytest.fail(
                "Invalid refresh credentials must not yield a transaction."
            )


def test_refresh_repository_uses_same_authenticated_transaction():
    token_hash = f"repository-transaction-{uuid4()}"
    session_id, token_id = _seed_credential(token_hash)

    try:
        repository = PostgresRefreshAuthenticationRepository(
            DatabaseConnection(ADMIN_DSN)
        )

        with repository.refresh_transaction(token_hash) as context:
            assert context.authentication.state.value == "VALID"
            assert context.authentication.user_id == USER_A
            assert context.authentication.session_id == session_id
            assert context.authentication.refresh_token_id == token_id

            current_user = context.connection.execute(
                "SELECT public.current_app_user_id()"
            ).fetchone()[0]

            assert current_user == USER_A
    finally:
        _cleanup_credential(session_id, token_id)
