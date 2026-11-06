from __future__ import annotations

import uuid
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from types import SimpleNamespace

import psycopg
import pytest
from fastapi.testclient import TestClient
from psycopg import errors

from backend.api import auth_routes, resend_routes
from backend.api.app import create_app
from backend.database.account_store import PostgresAccountStore
from backend.database.migration_runner import MigrationRunner
from backend.database.rate_limit_store import PostgresRateLimitStore
from backend.database.verification_resend_store import (
    PostgresVerificationResendStore,
)
from backend.security.email_verification import (
    generate_email_verification_token,
)
from backend.security.passwords import hash_password

ADMIN_DSN = "dbname=postgres user=postgres host=localhost port=5432"

MIGRATIONS_DIR = (
    Path(__file__).resolve().parents[2]
    / "backend"
    / "database"
    / "migrations"
)

PASSWORD = "correct horse battery staple"
PASSWORD_HASH = hash_password(PASSWORD)
FUNCTION = "public.issue_email_verification_token(text, text)"


def _dsn(database_name: str, user: str) -> str:
    return (
        f"dbname={database_name} "
        f"user={user} "
        "host=localhost "
        "port=5432"
    )


class CapturingSender:
    def __init__(self) -> None:
        self.sent: list[tuple[str, str]] = []

    def send_verification(self, email: str, raw_token: str) -> None:
        self.sent.append((email, raw_token))


@pytest.fixture(scope="module")
def database_name():
    name = f"eldorado_resend_test_{uuid.uuid4().hex[:12]}"

    with psycopg.connect(ADMIN_DSN, autocommit=True) as connection:
        connection.execute(f'CREATE DATABASE "{name}"')

    try:
        MigrationRunner(_dsn(name, "postgres"), MIGRATIONS_DIR).migrate()
        yield name
    finally:
        with psycopg.connect(ADMIN_DSN, autocommit=True) as connection:
            connection.execute(
                """
                SELECT pg_terminate_backend(pid)
                FROM pg_stat_activity
                WHERE datname = %s
                  AND pid <> pg_backend_pid()
                """,
                (name,),
            )
            connection.execute(f'DROP DATABASE IF EXISTS "{name}"')


@pytest.fixture(scope="module")
def admin_dsn(database_name: str) -> str:
    return _dsn(database_name, "postgres")


@pytest.fixture(scope="module")
def app_dsn(database_name: str) -> str:
    # Run the whole session as the restricted application role.
    return (
        _dsn(database_name, "postgres")
        + " options='-c role=eldorado_app'"
    )


@pytest.fixture
def store(app_dsn: str) -> PostgresVerificationResendStore:
    return PostgresVerificationResendStore(app_dsn)


def _email() -> str:
    return f"user-{uuid.uuid4().hex}@example.com"


def _pending_account(app_dsn: str) -> tuple[str, str]:
    """Create a pending account. Returns (email, first token hash)."""
    email = _email()
    token = generate_email_verification_token()

    with psycopg.connect(app_dsn) as connection:
        connection.execute(
            "SELECT public.create_pending_email_account(%s, %s, %s)",
            (email, PASSWORD_HASH, token.token_hash),
        )

    return email, token.token_hash


def _age_tokens(admin_dsn: str, email: str, seconds: int = 120) -> None:
    """Move a user's tokens into the past so the cooldown has elapsed."""
    with psycopg.connect(admin_dsn) as connection:
        connection.execute(
            """
            UPDATE public.email_verification_tokens
            SET created_at = created_at - make_interval(secs => %s),
                expires_at = expires_at - make_interval(secs => %s)
            WHERE user_id = (
                SELECT id FROM public.users WHERE email = %s
            )
            """,
            (seconds, seconds, email),
        )


def _verify(app_dsn: str, token_hash: str) -> str:
    with psycopg.connect(app_dsn) as connection:
        return connection.execute(
            "SELECT public.verify_email_token(%s)", (token_hash,)
        ).fetchone()[0]


def _live_tokens(admin_dsn: str, email: str) -> int:
    with psycopg.connect(admin_dsn) as connection:
        return connection.execute(
            """
            SELECT count(*)
            FROM public.email_verification_tokens
            WHERE consumed_at IS NULL
              AND user_id = (
                  SELECT id FROM public.users WHERE email = %s
              )
            """,
            (email,),
        ).fetchone()[0]


def test_resend_issues_a_token_for_a_pending_account(
    admin_dsn: str,
    app_dsn: str,
    store: PostgresVerificationResendStore,
) -> None:
    email, _ = _pending_account(app_dsn)
    _age_tokens(admin_dsn, email)
    new_token = generate_email_verification_token()

    assert store.issue_verification_token(email, new_token.token_hash) is True
    assert _verify(app_dsn, new_token.token_hash) == "VERIFIED"


def test_resend_invalidates_older_tokens(
    admin_dsn: str,
    app_dsn: str,
    store: PostgresVerificationResendStore,
) -> None:
    email, old_hash = _pending_account(app_dsn)
    _age_tokens(admin_dsn, email)
    new_token = generate_email_verification_token()

    store.issue_verification_token(email, new_token.token_hash)

    assert _live_tokens(admin_dsn, email) == 1
    assert _verify(app_dsn, old_hash) == "INVALID"
    assert _verify(app_dsn, new_token.token_hash) == "VERIFIED"


def test_cooldown_blocks_an_immediate_resend_and_keeps_the_old_token(
    admin_dsn: str,
    app_dsn: str,
    store: PostgresVerificationResendStore,
) -> None:
    email, old_hash = _pending_account(app_dsn)
    new_token = generate_email_verification_token()

    assert store.issue_verification_token(email, new_token.token_hash) is False
    assert _live_tokens(admin_dsn, email) == 1
    assert _verify(app_dsn, new_token.token_hash) == "INVALID"
    assert _verify(app_dsn, old_hash) == "VERIFIED"


def test_cooldown_applies_after_a_resend(
    admin_dsn: str,
    app_dsn: str,
    store: PostgresVerificationResendStore,
) -> None:
    email, _ = _pending_account(app_dsn)
    _age_tokens(admin_dsn, email)

    first = generate_email_verification_token()
    second = generate_email_verification_token()

    assert store.issue_verification_token(email, first.token_hash) is True
    assert store.issue_verification_token(email, second.token_hash) is False
    assert _verify(app_dsn, first.token_hash) == "VERIFIED"


def test_unknown_email_issues_nothing(
    store: PostgresVerificationResendStore,
) -> None:
    token = generate_email_verification_token()

    assert store.issue_verification_token(_email(), token.token_hash) is False


def test_verified_account_issues_nothing(
    admin_dsn: str,
    app_dsn: str,
    store: PostgresVerificationResendStore,
) -> None:
    email, first_hash = _pending_account(app_dsn)
    assert _verify(app_dsn, first_hash) == "VERIFIED"
    _age_tokens(admin_dsn, email)
    token = generate_email_verification_token()

    assert store.issue_verification_token(email, token.token_hash) is False


def test_inactive_account_issues_nothing(
    admin_dsn: str,
    app_dsn: str,
    store: PostgresVerificationResendStore,
) -> None:
    email, _ = _pending_account(app_dsn)
    _age_tokens(admin_dsn, email)

    with psycopg.connect(admin_dsn) as connection:
        connection.execute(
            "UPDATE public.users SET is_active = FALSE WHERE email = %s",
            (email,),
        )

    token = generate_email_verification_token()

    assert store.issue_verification_token(email, token.token_hash) is False


def test_only_application_role_may_execute_the_function(
    admin_dsn: str,
) -> None:
    with psycopg.connect(admin_dsn) as connection:
        grantees = {
            row[0]
            for row in connection.execute(
                """
                SELECT acl.grantee
                FROM pg_proc AS proc,
                     aclexplode(proc.proacl) AS acl
                WHERE proc.oid = %s::regprocedure
                  AND acl.privilege_type = 'EXECUTE'
                """,
                (FUNCTION,),
            ).fetchall()
        }
        app_role = connection.execute(
            "SELECT 'eldorado_app'::regrole::oid"
        ).fetchone()[0]
        owner = connection.execute(
            "SELECT proowner FROM pg_proc WHERE oid = %s::regprocedure",
            (FUNCTION,),
        ).fetchone()[0]

    assert 0 not in grantees
    assert app_role in grantees
    assert grantees <= {app_role, owner}


def test_function_search_path_excludes_public(admin_dsn: str) -> None:
    with psycopg.connect(admin_dsn) as connection:
        settings = connection.execute(
            "SELECT proconfig FROM pg_proc WHERE oid = %s::regprocedure",
            (FUNCTION,),
        ).fetchone()[0] or []

    search_paths = [s for s in settings if s.startswith("search_path=")]

    assert len(search_paths) == 1
    assert "public" not in search_paths[0]


@pytest.mark.parametrize(
    ("email", "token_hash"),
    [
        ("   ", "a" * 64),
        ("user@example.com", "not-a-hash"),
    ],
)
def test_database_rejects_invalid_input(
    app_dsn: str,
    email: str,
    token_hash: str,
) -> None:
    with pytest.raises(errors.InvalidParameterValue):
        with psycopg.connect(app_dsn) as connection:
            connection.execute(
                "SELECT public.issue_email_verification_token(%s, %s)",
                (email, token_hash),
            )


def test_concurrent_resends_issue_exactly_one_token(
    admin_dsn: str,
    app_dsn: str,
    store: PostgresVerificationResendStore,
) -> None:
    email, _ = _pending_account(app_dsn)
    _age_tokens(admin_dsn, email)
    hashes = [
        generate_email_verification_token().token_hash for _ in range(8)
    ]

    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(
            pool.map(
                lambda token_hash: store.issue_verification_token(
                    email, token_hash
                ),
                hashes,
            )
        )

    assert sum(results) == 1
    assert _live_tokens(admin_dsn, email) == 1


@pytest.fixture
def api(app_dsn: str, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.delenv("ELDORADO_ENABLE_DOCS", raising=False)

    app = create_app()
    sender = CapturingSender()
    client_ip = f"test-{uuid.uuid4().hex}"

    app.dependency_overrides[auth_routes.get_account_store] = (
        lambda: PostgresAccountStore(app_dsn)
    )
    app.dependency_overrides[auth_routes.get_rate_limit_store] = (
        lambda: PostgresRateLimitStore(app_dsn)
    )
    app.dependency_overrides[auth_routes.get_email_sender] = lambda: sender
    app.dependency_overrides[auth_routes.get_client_ip] = lambda: client_ip
    app.dependency_overrides[resend_routes.get_resend_store] = (
        lambda: PostgresVerificationResendStore(app_dsn)
    )

    return SimpleNamespace(client=TestClient(app), sender=sender)


def _api_register(api, email: str) -> str:
    response = api.client.post(
        "/auth/register", json={"email": email, "password": PASSWORD}
    )
    assert response.status_code == 202
    return api.sender.sent[-1][1]


def _api_resend(api, email: str):
    return api.client.post(
        "/auth/resend-verification", json={"email": email}
    )


def _api_verify(api, token: str):
    return api.client.post("/auth/verify-email", json={"token": token})


def test_api_resend_replaces_the_link_end_to_end(
    api,
    admin_dsn: str,
) -> None:
    email = _email()
    first_token = _api_register(api, email)

    assert _api_resend(api, email).status_code == 202
    assert len(api.sender.sent) == 1

    _age_tokens(admin_dsn, email)

    assert _api_resend(api, email).status_code == 202
    assert len(api.sender.sent) == 2
    second_token = api.sender.sent[-1][1]

    assert _api_verify(api, first_token).status_code == 400
    assert _api_verify(api, second_token).status_code == 200

    with psycopg.connect(admin_dsn) as connection:
        verified_at = connection.execute(
            "SELECT email_verified_at FROM public.users WHERE email = %s",
            (email,),
        ).fetchone()[0]

    assert verified_at is not None


def test_api_responses_do_not_reveal_account_state(
    api,
    admin_dsn: str,
) -> None:
    pending = _email()
    verified = _email()
    unknown = _email()

    _api_register(api, pending)
    verified_token = _api_register(api, verified)
    assert _api_verify(api, verified_token).status_code == 200

    _age_tokens(admin_dsn, pending)
    sent_before = len(api.sender.sent)

    responses = [
        _api_resend(api, pending),
        _api_resend(api, verified),
        _api_resend(api, unknown),
    ]

    assert [r.status_code for r in responses] == [202, 202, 202]
    assert responses[0].json() == responses[1].json() == responses[2].json()
    assert len(api.sender.sent) == sent_before + 1