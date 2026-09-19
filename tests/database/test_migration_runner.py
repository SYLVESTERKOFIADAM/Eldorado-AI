from __future__ import annotations

import hashlib
import threading
import time
import uuid
from pathlib import Path

import psycopg
import pytest

from backend.database.migration_runner import (
    MigrationError,
    MigrationRunner,
)


ADMIN_DSN = (
    "dbname=postgres "
    "user=postgres "
    "host=localhost "
    "port=5432"
)


def write_migration(
    directory: Path,
    version: int,
    name: str,
    sql: str = "SELECT 1;",
) -> None:
    (directory / f"{version:04d}_{name}.sql").write_text(
        sql,
        encoding="utf-8",
    )


@pytest.fixture
def test_database() -> str:
    database_name = f"eldorado_migration_test_{uuid.uuid4().hex[:12]}"

    with psycopg.connect(ADMIN_DSN, autocommit=True) as connection:
        connection.execute(
            f'CREATE DATABASE "{database_name}"'
        )

    test_dsn = (
        f"dbname={database_name} "
        "user=postgres "
        "host=localhost "
        "port=5432"
    )

    try:
        yield test_dsn
    finally:
        with psycopg.connect(ADMIN_DSN, autocommit=True) as connection:
            connection.execute(
                """
                SELECT pg_terminate_backend(pid)
                FROM pg_stat_activity
                WHERE datname = %s
                  AND pid <> pg_backend_pid()
                """,
                (database_name,),
            )

            connection.execute(
                f'DROP DATABASE IF EXISTS "{database_name}"'
            )


def make_runner(
    tmp_path: Path,
    test_dsn: str,
) -> MigrationRunner:
    return MigrationRunner(
        test_dsn,
        tmp_path,
    )


def test_discover_returns_numeric_order(
    tmp_path: Path,
    test_database: str,
) -> None:
    write_migration(tmp_path, 1, "first")
    write_migration(tmp_path, 2, "second")
    write_migration(tmp_path, 3, "third")

    migrations = make_runner(
        tmp_path,
        test_database,
    ).discover()

    assert [m.version for m in migrations] == [1, 2, 3]
    assert [m.name for m in migrations] == [
        "first",
        "second",
        "third",
    ]


def test_discover_rejects_duplicate_versions(
    tmp_path: Path,
    test_database: str,
) -> None:
    write_migration(tmp_path, 1, "first")
    write_migration(tmp_path, 1, "duplicate")

    with pytest.raises(
        MigrationError,
        match="Duplicate migration version",
    ):
        make_runner(tmp_path, test_database).discover()


def test_discover_rejects_missing_version(
    tmp_path: Path,
    test_database: str,
) -> None:
    write_migration(tmp_path, 1, "first")
    write_migration(tmp_path, 3, "third")

    with pytest.raises(
        MigrationError,
        match="contiguous sequence",
    ):
        make_runner(tmp_path, test_database).discover()


def test_discover_rejects_missing_directory(
    tmp_path: Path,
    test_database: str,
) -> None:
    missing = tmp_path / "missing"

    with pytest.raises(
        MigrationError,
        match="does not exist",
    ):
        MigrationRunner(
            test_database,
            missing,
        ).discover()


def test_discover_calculates_sha256_checksum(
    tmp_path: Path,
    test_database: str,
) -> None:
    sql = "SELECT 42;\n"
    write_migration(tmp_path, 1, "first", sql)

    migration = make_runner(
        tmp_path,
        test_database,
    ).discover()[0]

    expected = hashlib.sha256(
        sql.encode("utf-8")
    ).hexdigest()

    assert migration.checksum == expected


def test_validate_history_rejects_unknown_version(
    tmp_path: Path,
    test_database: str,
) -> None:
    write_migration(tmp_path, 1, "first")

    runner = make_runner(
        tmp_path,
        test_database,
    )

    discovered = runner.discover()

    with pytest.raises(
        MigrationError,
        match="unknown migration",
    ):
        runner._validate_history(
            discovered,
            {2: ("second", "checksum")},
        )


def test_validate_history_rejects_name_mismatch(
    tmp_path: Path,
    test_database: str,
) -> None:
    write_migration(tmp_path, 1, "first")

    runner = make_runner(
        tmp_path,
        test_database,
    )

    discovered = runner.discover()

    with pytest.raises(
        MigrationError,
        match="name mismatch",
    ):
        runner._validate_history(
            discovered,
            {1: ("renamed", discovered[0].checksum)},
        )


def test_validate_history_rejects_checksum_mismatch(
    tmp_path: Path,
    test_database: str,
) -> None:
    write_migration(tmp_path, 1, "first")

    runner = make_runner(
        tmp_path,
        test_database,
    )

    discovered = runner.discover()

    with pytest.raises(
        MigrationError,
        match="checksum mismatch",
    ):
        runner._validate_history(
            discovered,
            {1: (discovered[0].name, "tampered-checksum")},
        )


def test_validate_history_rejects_gap(
    tmp_path: Path,
    test_database: str,
) -> None:
    write_migration(tmp_path, 1, "first")
    write_migration(tmp_path, 2, "second")
    write_migration(tmp_path, 3, "third")

    runner = make_runner(
        tmp_path,
        test_database,
    )

    discovered = runner.discover()

    with pytest.raises(
        MigrationError,
        match="gap or invalid order",
    ):
        runner._validate_history(
            discovered,
            {
                1: (
                    discovered[0].name,
                    discovered[0].checksum,
                ),
                3: (
                    discovered[2].name,
                    discovered[2].checksum,
                ),
            },
        )


def test_strip_transaction_wrapper(
    tmp_path: Path,
    test_database: str,
) -> None:
    sql = """
BEGIN;

CREATE TABLE example_table (
    id INTEGER PRIMARY KEY
);

COMMIT;
"""

    stripped = MigrationRunner._strip_transaction_wrapper(sql)

    assert stripped == """CREATE TABLE example_table (
    id INTEGER PRIMARY KEY
);"""


def test_strip_transaction_wrapper_preserves_sql_without_wrapper(
    tmp_path: Path,
    test_database: str,
) -> None:
    sql = "CREATE TABLE example_table (id INTEGER);"

    assert (
        MigrationRunner._strip_transaction_wrapper(sql)
        == sql
    )


def test_baseline_records_migration_history(
    tmp_path: Path,
    test_database: str,
) -> None:
    write_migration(tmp_path, 1, "first")
    write_migration(tmp_path, 2, "second")

    runner = make_runner(
        tmp_path,
        test_database,
    )

    runner.baseline()

    with psycopg.connect(test_database) as connection:
        rows = connection.execute(
            """
            SELECT version, name, checksum
            FROM schema_migrations
            ORDER BY version
            """
        ).fetchall()

    assert [row[0] for row in rows] == [1, 2]
    assert [row[1] for row in rows] == [
        "first",
        "second",
    ]


def test_baseline_refuses_existing_history(
    tmp_path: Path,
    test_database: str,
) -> None:
    write_migration(tmp_path, 1, "first")

    runner = make_runner(
        tmp_path,
        test_database,
    )

    runner.baseline()

    with pytest.raises(
        MigrationError,
        match="refusing to baseline",
    ):
        runner.baseline()


def test_migrate_is_idempotent(
    tmp_path: Path,
    test_database: str,
) -> None:
    write_migration(
        tmp_path,
        1,
        "first",
        """
BEGIN;

CREATE TABLE migration_test_idempotent (
    id INTEGER PRIMARY KEY
);

COMMIT;
""",
    )

    runner = make_runner(
        tmp_path,
        test_database,
    )

    assert runner.migrate() == [1]
    assert runner.migrate() == []

    with psycopg.connect(test_database) as connection:
        exists = connection.execute(
            """
            SELECT to_regclass(
                'public.migration_test_idempotent'
            )
            """
        ).fetchone()[0]

    assert exists == "migration_test_idempotent"



def test_migrate_rolls_back_failed_migration(
    tmp_path: Path,
    test_database: str,
) -> None:
    # Migration 1 succeeds and commits.
    write_migration(
        tmp_path,
        1,
        "first",
        """
BEGIN;

CREATE TABLE migration_test_rollback (
    id INTEGER PRIMARY KEY
);

COMMIT;
""",
    )

    runner = make_runner(
        tmp_path,
        test_database,
    )

    assert runner.migrate() == [1]

    # Only after migration 1 has committed do we introduce
    # the intentionally broken migration 2.
    write_migration(
        tmp_path,
        2,
        "broken",
        """
BEGIN;

CREATE TABLE migration_test_should_rollback (
    id INTEGER PRIMARY KEY
);

THIS IS INVALID SQL;

COMMIT;
""",
    )

    with pytest.raises(Exception):
        runner.migrate()

    # Migration 2 must have rolled back completely.
    with psycopg.connect(test_database) as connection:
        rows = connection.execute(
            """
            SELECT version
            FROM schema_migrations
            ORDER BY version
            """
        ).fetchall()

        rolled_back_table = connection.execute(
            """
            SELECT to_regclass(
                'public.migration_test_should_rollback'
            )
            """
        ).fetchone()[0]

        successful_table = connection.execute(
            """
            SELECT to_regclass(
                'public.migration_test_rollback'
            )
            """
        ).fetchone()[0]

    assert [row[0] for row in rows] == [1]
    assert rolled_back_table is None
    assert successful_table == "migration_test_rollback"

def test_migrate_rejects_modified_applied_migration(
    tmp_path: Path,
    test_database: str,
) -> None:
    write_migration(tmp_path, 1, "first")

    runner = make_runner(
        tmp_path,
        test_database,
    )

    runner.baseline()

    migration_file = tmp_path / "0001_first.sql"

    migration_file.write_text(
        "SELECT 999;\n",
        encoding="utf-8",
    )

    with pytest.raises(
        MigrationError,
        match="checksum mismatch",
    ):
        runner.migrate()


def test_migrate_rejects_unknown_database_migration(
    tmp_path: Path,
    test_database: str,
) -> None:
    write_migration(tmp_path, 1, "first")

    runner = make_runner(
        tmp_path,
        test_database,
    )

    with psycopg.connect(test_database) as connection:
        with connection.transaction():
            connection.execute(
                """
                CREATE TABLE schema_migrations (
                    version INTEGER PRIMARY KEY,
                    name TEXT NOT NULL,
                    checksum TEXT NOT NULL,
                    applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
                )
                """
            )

            connection.execute(
                """
                INSERT INTO schema_migrations
                    (version, name, checksum)
                VALUES
                    (99, 'unknown', 'checksum')
                """
            )

    with pytest.raises(
        MigrationError,
        match="unknown migration",
    ):
        runner.migrate()



def test_concurrent_migration_runners_are_serialized(
    tmp_path: Path,
    test_database: str,
) -> None:
    write_migration(
        tmp_path,
        1,
        "first",
        """
BEGIN;

CREATE TABLE migration_test_concurrent (
    id INTEGER PRIMARY KEY
);

SELECT pg_sleep(2);

COMMIT;
""",
    )

    # Establish the migration ledger before the concurrent runners start.
    #
    # This isolates the concurrency test from the bootstrap race around
    # CREATE TABLE schema_migrations. The actual migration execution is
    # still protected by MigrationRunner's session-level advisory lock.
    with psycopg.connect(test_database) as connection:
        with connection.transaction():
            connection.execute(
                """
                CREATE TABLE schema_migrations (
                    version INTEGER PRIMARY KEY,
                    name TEXT NOT NULL,
                    checksum TEXT NOT NULL,
                    applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
                )
                """
            )

    runner_one = make_runner(
        tmp_path,
        test_database,
    )

    runner_two = make_runner(
        tmp_path,
        test_database,
    )

    results: list[tuple[str, object]] = []
    errors: list[BaseException] = []

    def run_runner(
        label: str,
        runner: MigrationRunner,
    ) -> None:
        try:
            started = time.monotonic()
            applied = runner.migrate()
            elapsed = time.monotonic() - started
            results.append((label, (applied, elapsed)))
        except BaseException as exc:
            errors.append(exc)

    thread_one = threading.Thread(
        target=run_runner,
        args=("one", runner_one),
    )

    thread_two = threading.Thread(
        target=run_runner,
        args=("two", runner_two),
    )

    thread_one.start()

    time.sleep(0.25)

    thread_two.start()

    thread_one.join(timeout=10)
    thread_two.join(timeout=10)

    assert not thread_one.is_alive()
    assert not thread_two.is_alive()

    assert not errors
    assert len(results) == 2

    applied_values = [
        result[1][0]
        for result in results
    ]

    assert sorted(
        applied_values,
        key=lambda value: len(value),
    ) == [
        [],
        [1],
    ]

    with psycopg.connect(test_database) as connection:
        rows = connection.execute(
            """
            SELECT version
            FROM schema_migrations
            ORDER BY version
            """
        ).fetchall()

        table_exists = connection.execute(
            """
            SELECT to_regclass(
                'public.migration_test_concurrent'
            )
            """
        ).fetchone()[0]

    assert [row[0] for row in rows] == [1]
    assert table_exists == "migration_test_concurrent"
