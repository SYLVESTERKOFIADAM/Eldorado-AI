from __future__ import annotations

import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import psycopg
import pytest
from psycopg import errors

from backend.database.migration_runner import MigrationRunner
from backend.database.rate_limit_store import PostgresRateLimitStore
from backend.security.rate_limit import (
    RateLimitPolicy,
    check_rate_limit,
    hash_rate_limit_key,
)

ADMIN_DSN = "dbname=postgres user=postgres host=localhost port=5432"

MIGRATIONS_DIR = (
    Path(__file__).resolve().parents[2]
    / "backend"
    / "database"
    / "migrations"
)

VALID_HASH = "a" * 64


def _dsn(database_name: str, user: str) -> str:
    return (
        f"dbname={database_name} "
        f"user={user} "
        "host=localhost "
        "port=5432"
    )


@pytest.fixture(scope="module")
def database_name():
    name = f"eldorado_ratelimit_test_{uuid.uuid4().hex[:12]}"

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
def store(app_dsn: str) -> PostgresRateLimitStore:
    return PostgresRateLimitStore(app_dsn)


def _identifier() -> str:
    return f"id-{uuid.uuid4().hex}"


def test_blank_dsn_is_rejected() -> None:
    with pytest.raises(ValueError):
        PostgresRateLimitStore("   ")


def test_limit_is_enforced_within_a_window(
    store: PostgresRateLimitStore,
) -> None:
    policy = RateLimitPolicy("limit_test", 3, 3600)
    identifier = _identifier()

    results = [
        check_rate_limit(store, policy, identifier) for _ in range(5)
    ]

    assert results == [True, True, True, False, False]


def test_keys_and_buckets_are_independent(
    store: PostgresRateLimitStore,
) -> None:
    first = RateLimitPolicy("bucket_one", 1, 3600)
    second = RateLimitPolicy("bucket_two", 1, 3600)
    identifier = _identifier()

    assert check_rate_limit(store, first, identifier) is True
    assert check_rate_limit(store, first, identifier) is False

    assert check_rate_limit(store, first, _identifier()) is True
    assert check_rate_limit(store, second, identifier) is True


def test_new_window_resets_the_count(
    store: PostgresRateLimitStore,
) -> None:
    policy = RateLimitPolicy("reset_test", 1, 1)
    identifier = _identifier()

    assert check_rate_limit(store, policy, identifier) is True

    time.sleep(1.2)

    assert check_rate_limit(store, policy, identifier) is True


def test_concurrent_attempts_never_exceed_the_limit(
    store: PostgresRateLimitStore,
) -> None:
    policy = RateLimitPolicy("concurrent_test", 5, 3600)
    identifier = _identifier()

    with ThreadPoolExecutor(max_workers=20) as pool:
        results = list(
            pool.map(
                lambda _: check_rate_limit(store, policy, identifier),
                range(20),
            )
        )

    assert sum(results) == 5


def test_only_hashed_keys_are_stored(
    admin_dsn: str,
    store: PostgresRateLimitStore,
) -> None:
    policy = RateLimitPolicy("hash_only_test", 5, 3600)
    identifier = f"{uuid.uuid4().hex}@example.com"

    check_rate_limit(store, policy, identifier)

    with psycopg.connect(admin_dsn) as connection:
        rows = connection.execute(
            """
            SELECT bucket, key_hash
            FROM public.auth_rate_limits
            WHERE bucket = %s
            """,
            (policy.bucket,),
        ).fetchall()

    assert len(rows) == 1
    assert rows[0][1] == hash_rate_limit_key(policy.bucket, identifier)
    assert identifier not in str(rows)


def test_application_role_has_no_direct_table_access(app_dsn: str) -> None:
    with pytest.raises(errors.InsufficientPrivilege):
        with psycopg.connect(app_dsn) as connection:
            connection.execute("SELECT * FROM public.auth_rate_limits")

    with pytest.raises(errors.InsufficientPrivilege):
        with psycopg.connect(app_dsn) as connection:
            connection.execute(
                """
                INSERT INTO public.auth_rate_limits
                    (bucket, key_hash, window_start, attempts)
                VALUES ('sneaky', %s, now(), 1)
                """,
                (VALID_HASH,),
            )


def test_application_role_cannot_purge(app_dsn: str) -> None:
    with pytest.raises(errors.InsufficientPrivilege):
        with psycopg.connect(app_dsn) as connection:
            connection.execute(
                "SELECT public.purge_expired_rate_limits()"
            )


@pytest.mark.parametrize(
    ("bucket", "key_hash", "limit", "window"),
    [
        ("Bad-Bucket", VALID_HASH, 1, 60),
        ("ok_bucket", "not-a-hash", 1, 60),
        ("ok_bucket", VALID_HASH, 0, 60),
        ("ok_bucket", VALID_HASH, 1, 0),
        ("ok_bucket", VALID_HASH, 1, 86401),
    ],
)
def test_database_rejects_invalid_input(
    app_dsn: str,
    bucket: str,
    key_hash: str,
    limit: int,
    window: int,
) -> None:
    with pytest.raises(errors.InvalidParameterValue):
        with psycopg.connect(app_dsn) as connection:
            connection.execute(
                "SELECT public.check_rate_limit(%s, %s, %s, %s)",
                (bucket, key_hash, limit, window),
            )


def test_purge_removes_only_old_windows(
    admin_dsn: str,
    store: PostgresRateLimitStore,
) -> None:
    old_key = hash_rate_limit_key("purge_test", _identifier())
    policy = RateLimitPolicy("purge_test", 5, 3600)
    current_identifier = _identifier()

    check_rate_limit(store, policy, current_identifier)
    current_key = hash_rate_limit_key("purge_test", current_identifier)

    with psycopg.connect(admin_dsn) as connection:
        connection.execute(
            """
            INSERT INTO public.auth_rate_limits
                (bucket, key_hash, window_start, attempts)
            VALUES ('purge_test', %s, now() - interval '3 days', 1)
            """,
            (old_key,),
        )

    with psycopg.connect(admin_dsn) as connection:
        removed = connection.execute(
            "SELECT public.purge_expired_rate_limits()"
        ).fetchone()[0]

    assert removed >= 1

    with psycopg.connect(admin_dsn) as connection:
        remaining = {
            row[0]
            for row in connection.execute(
                """
                SELECT key_hash
                FROM public.auth_rate_limits
                WHERE bucket = 'purge_test'
                """
            ).fetchall()
        }

    assert old_key not in remaining
    assert current_key in remaining


def test_purge_rejects_dangerously_short_age(admin_dsn: str) -> None:
    with pytest.raises(errors.InvalidParameterValue):
        with psycopg.connect(admin_dsn) as connection:
            connection.execute(
                "SELECT public.purge_expired_rate_limits(3600)"
            )