from __future__ import annotations

from datetime import datetime, timedelta, timezone
from uuid import UUID, uuid4

import psycopg
import pytest

APP_DSN = "dbname=postgres user=eldorado_app host=localhost port=5432"
ADMIN_DSN = "dbname=postgres user=postgres host=localhost port=5432"

USER_A = UUID("76bab0d0-94f5-4925-a729-62e31726456f")

FUNCTION = (
    "public.authenticate_and_lock_refresh_credential(text)"
)


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _create_session(
    connection: psycopg.Connection,
    *,
    user_id: UUID = USER_A,
    created_at: datetime | None = None,
    expires_at: datetime | None = None,
    revoked_at: datetime | None = None,
) -> UUID:
    session_id = uuid4()
    created_at = created_at or _now()
    expires_at = expires_at or (created_at + timedelta(hours=1))

    connection.execute(
        """
        INSERT INTO public.sessions (
            id,
            user_id,
            token_family_id,
            created_at,
            expires_at,
            revoked_at
        )
        VALUES (
            %s,
            %s,
            %s,
            %s,
            %s,
            %s
        )
        """,
        (
            session_id,
            user_id,
            uuid4(),
            created_at,
            expires_at,
            revoked_at,
        ),
    )

    return session_id


def _create_refresh_token(
    connection: psycopg.Connection,
    session_id: UUID,
    *,
    issued_at: datetime | None = None,
    token_hash: str | None = None,
    expires_at: datetime | None = None,
    consumed_at: datetime | None = None,
) -> UUID:
    token_id = uuid4()
    issued_at = issued_at or _now()
    expires_at = expires_at or (issued_at + timedelta(days=30))

    connection.execute(
        """
        INSERT INTO public.refresh_tokens (
            id,
            session_id,
            token_hash,
            issued_at,
            expires_at,
            consumed_at
        )
        VALUES (
            %s,
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
            token_hash or f"test-token-{uuid4()}",
            issued_at,
            expires_at,
            consumed_at,
        ),
    )

    return token_id


def _call_function(
    connection: psycopg.Connection,
    token_hash: str,
):
    return connection.execute(
        """
        SELECT *
        FROM public.authenticate_and_lock_refresh_credential(%s)
        """,
        (token_hash,),
    ).fetchone()


def test_valid_refresh_credential_returns_trusted_identity():
    token_hash = f"valid-{uuid4()}"

    with psycopg.connect(ADMIN_DSN) as connection:
        with connection.transaction():
            session_id = _create_session(connection)
            token_id = _create_refresh_token(
                connection,
                session_id,
                token_hash=token_hash,
            )

            result = _call_function(connection, token_hash)

            assert result is not None
            assert result[0] == "VALID"
            assert result[1] == USER_A
            assert result[2] == session_id
            assert result[4] == token_id

            connection.execute(
                "DELETE FROM public.refresh_tokens WHERE id = %s",
                (token_id,),
            )
            connection.execute(
                "DELETE FROM public.sessions WHERE id = %s",
                (session_id,),
            )


def test_consumed_refresh_credential_returns_replay():
    token_hash = f"replay-{uuid4()}"
    issued_at = _now()
    consumed_at = issued_at + timedelta(seconds=1)

    with psycopg.connect(ADMIN_DSN) as connection:
        with connection.transaction():
            session_id = _create_session(connection)
            token_id = _create_refresh_token(
                connection,
                session_id,
                token_hash=token_hash,
                issued_at=issued_at,
                consumed_at=consumed_at,
            )

            result = _call_function(connection, token_hash)

            assert result is not None
            assert result[0] == "REPLAY"
            assert result[1] == USER_A
            assert result[2] == session_id
            assert result[4] == token_id

            connection.execute(
                "DELETE FROM public.refresh_tokens WHERE id = %s",
                (token_id,),
            )
            connection.execute(
                "DELETE FROM public.sessions WHERE id = %s",
                (session_id,),
            )


@pytest.mark.parametrize(
    "token_hash",
    [
        "",
        "   ",
        "unknown-refresh-token",
    ],
)
def test_invalid_refresh_credentials_are_collapsed(
    token_hash: str,
):
    with psycopg.connect(APP_DSN) as connection:
        with connection.transaction():
            result = _call_function(connection, token_hash)

    assert result is not None
    assert result[0] == "INVALID"
    assert result[1] is None
    assert result[2] is None
    assert result[3] is None
    assert result[4] is None


def test_expired_refresh_token_returns_invalid():
    token_hash = f"expired-token-{uuid4()}"
    issued_at = _now() - timedelta(days=1)

    with psycopg.connect(ADMIN_DSN) as connection:
        with connection.transaction():
            session_id = _create_session(connection)
            token_id = _create_refresh_token(
                connection,
                session_id,
                token_hash=token_hash,
                issued_at=issued_at,
                expires_at=issued_at + timedelta(seconds=1),
            )

            result = _call_function(connection, token_hash)

            assert result is not None
            assert result[0] == "INVALID"
            assert result[1] is None
            assert result[2] is None
            assert result[3] is None
            assert result[4] is None

            connection.execute(
                "DELETE FROM public.refresh_tokens WHERE id = %s",
                (token_id,),
            )
            connection.execute(
                "DELETE FROM public.sessions WHERE id = %s",
                (session_id,),
            )


def test_expired_session_returns_invalid():
    token_hash = f"expired-session-{uuid4()}"
    created_at = _now() - timedelta(days=2)

    with psycopg.connect(ADMIN_DSN) as connection:
        with connection.transaction():
            session_id = _create_session(
                connection,
                created_at=created_at,
                expires_at=created_at + timedelta(seconds=1),
            )
            token_id = _create_refresh_token(
                connection,
                session_id,
                token_hash=token_hash,
                issued_at=created_at,
            )

            result = _call_function(connection, token_hash)

            assert result is not None
            assert result[0] == "INVALID"
            assert result[1] is None
            assert result[2] is None
            assert result[3] is None
            assert result[4] is None

            connection.execute(
                "DELETE FROM public.refresh_tokens WHERE id = %s",
                (token_id,),
            )
            connection.execute(
                "DELETE FROM public.sessions WHERE id = %s",
                (session_id,),
            )


def test_revoked_session_returns_invalid():
    token_hash = f"revoked-session-{uuid4()}"
    created_at = _now()
    revoked_at = created_at + timedelta(seconds=1)

    with psycopg.connect(ADMIN_DSN) as connection:
        with connection.transaction():
            session_id = _create_session(
                connection,
                created_at=created_at,
                revoked_at=revoked_at,
            )
            token_id = _create_refresh_token(
                connection,
                session_id,
                token_hash=token_hash,
                issued_at=created_at,
            )

            result = _call_function(connection, token_hash)

            assert result is not None
            assert result[0] == "INVALID"
            assert result[1] is None
            assert result[2] is None
            assert result[3] is None
            assert result[4] is None

            connection.execute(
                "DELETE FROM public.refresh_tokens WHERE id = %s",
                (token_id,),
            )
            connection.execute(
                "DELETE FROM public.sessions WHERE id = %s",
                (session_id,),
            )


def test_function_execution_is_not_public():
    with psycopg.connect(ADMIN_DSN) as connection:
        acl = connection.execute(
            """
            SELECT proacl
            FROM pg_proc AS p
            JOIN pg_namespace AS n
              ON n.oid = p.pronamespace
            WHERE n.nspname = 'public'
              AND p.proname =
                  'authenticate_and_lock_refresh_credential'
        """
        ).fetchone()[0]

    assert acl is not None
    assert not any(entry.startswith("=") for entry in acl)


def test_app_role_can_execute_function():
    with psycopg.connect(ADMIN_DSN) as connection:
        app_execute = connection.execute(
            """
            SELECT has_function_privilege(
                'eldorado_app',
                %s,
                'EXECUTE'
            )
            """,
            (FUNCTION,),
        ).fetchone()[0]

    assert app_execute is True


def test_function_owner_is_postgres():
    with psycopg.connect(ADMIN_DSN) as connection:
        owner = connection.execute(
            """
            SELECT pg_get_userbyid(p.proowner)
            FROM pg_proc AS p
            JOIN pg_namespace AS n
              ON n.oid = p.pronamespace
            WHERE n.nspname = 'public'
              AND p.proname =
                  'authenticate_and_lock_refresh_credential'
        """
        ).fetchone()[0]

    assert owner == "postgres"


def test_function_is_security_definer():
    with psycopg.connect(ADMIN_DSN) as connection:
        security_definer = connection.execute(
            """
            SELECT p.prosecdef
            FROM pg_proc AS p
            JOIN pg_namespace AS n
              ON n.oid = p.pronamespace
            WHERE n.nspname = 'public'
              AND p.proname =
                  'authenticate_and_lock_refresh_credential'
        """
        ).fetchone()[0]

    assert security_definer is True


def test_function_has_fixed_search_path():
    with psycopg.connect(ADMIN_DSN) as connection:
        search_path = connection.execute(
            """
            SELECT proconfig
            FROM pg_proc AS p
            JOIN pg_namespace AS n
              ON n.oid = p.pronamespace
            WHERE n.nspname = 'public'
              AND p.proname =
                  'authenticate_and_lock_refresh_credential'
        """
        ).fetchone()[0]

    assert search_path is not None
    assert any(
        setting.replace(" ", "") == "search_path=pg_catalog,public"
        for setting in search_path
    )


def test_function_uses_schema_qualified_relations():
    with psycopg.connect(ADMIN_DSN) as connection:
        definition = connection.execute(
            """
            SELECT pg_get_functiondef(p.oid)
            FROM pg_proc AS p
            JOIN pg_namespace AS n
              ON n.oid = p.pronamespace
            WHERE n.nspname = 'public'
              AND p.proname =
                  'authenticate_and_lock_refresh_credential'
        """
        ).fetchone()[0]

    assert "public.refresh_tokens" in definition
    assert "public.sessions" in definition


def test_function_does_not_set_application_identity():
    token_hash = f"identity-check-{uuid4()}"

    with psycopg.connect(ADMIN_DSN) as connection:
        with connection.transaction():
            session_id = _create_session(connection)
            token_id = _create_refresh_token(
                connection,
                session_id,
                token_hash=token_hash,
            )

            before = connection.execute(
                "SELECT current_app_user_id()"
            ).fetchone()[0]

            assert before is None

            result = _call_function(connection, token_hash)

            assert result[0] == "VALID"

            after = connection.execute(
                "SELECT current_app_user_id()"
            ).fetchone()[0]

            assert after is None

            connection.execute(
                "DELETE FROM public.refresh_tokens WHERE id = %s",
                (token_id,),
            )
            connection.execute(
                "DELETE FROM public.sessions WHERE id = %s",
                (session_id,),
            )

def test_function_ignores_shadowed_relations():
    token_hash = f"shadow-test-{uuid4()}"

    with psycopg.connect(ADMIN_DSN) as connection:
        with connection.transaction():
            schema_name = f"shadow_refresh_{uuid4().hex}"

            connection.execute(
                f'CREATE SCHEMA "{schema_name}"'
            )

            try:
                connection.execute(
                    f'''
                    CREATE TABLE "{schema_name}".refresh_tokens (
                        token_hash TEXT PRIMARY KEY
                    )
                    '''
                )

                connection.execute(
                    f'''
                    CREATE TABLE "{schema_name}".sessions (
                        id UUID PRIMARY KEY,
                        user_id UUID NOT NULL
                    )
                    '''
                )

                session_id = _create_session(connection)

                token_id = _create_refresh_token(
                    connection,
                    session_id,
                    token_hash=token_hash,
                )

                connection.execute(
                    f'SET LOCAL search_path = "{schema_name}", public'
                )

                result = _call_function(connection, token_hash)

                assert result is not None
                assert result[0] == "VALID"
                assert result[1] == USER_A
                assert result[2] == session_id
                assert result[4] == token_id

                connection.execute(
                    "DELETE FROM public.refresh_tokens WHERE id = %s",
                    (token_id,),
                )
                connection.execute(
                    "DELETE FROM public.sessions WHERE id = %s",
                    (session_id,),
                )
            finally:
                connection.execute(
                    f'DROP SCHEMA "{schema_name}" CASCADE'
                )
