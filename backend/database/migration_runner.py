from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from pathlib import Path

import psycopg


_MIGRATION_PATTERN = re.compile(r"^(?P<version>\d{4})_(?P<name>.+)\.sql$")
_MIGRATION_LOCK_KEY = 81472931


class MigrationError(RuntimeError):
    """Raised when database migrations cannot be safely applied."""


@dataclass(frozen=True)
class Migration:
    version: int
    name: str
    filename: str
    sql: str
    checksum: str


class MigrationRunner:
    """
    Secure PostgreSQL migration runner.

    Security properties:
    - Migrations execute strictly in numeric filename order.
    - Each migration executes in its own transaction.
    - PostgreSQL advisory locking prevents concurrent runners.
    - Applied migration checksums detect historical modification.
    - Migration history is append-only from the runner's perspective.
    - DDL is executed using the migration/database-owner connection,
      never the restricted application role.
    """

    def __init__(
        self,
        dsn: str,
        migrations_dir: Path,
    ) -> None:
        if not dsn.strip():
            raise ValueError("Database DSN must not be empty.")

        self._dsn = dsn
        self._migrations_dir = migrations_dir

    def discover(self) -> list[Migration]:
        if not self._migrations_dir.exists():
            raise MigrationError(
                f"Migration directory does not exist: {self._migrations_dir}"
            )

        migrations: list[Migration] = []

        for path in sorted(self._migrations_dir.iterdir()):
            if not path.is_file():
                continue

            match = _MIGRATION_PATTERN.match(path.name)
            if match is None:
                continue

            sql = path.read_text(encoding="utf-8")
            checksum = hashlib.sha256(
                sql.encode("utf-8")
            ).hexdigest()

            migrations.append(
                Migration(
                    version=int(match.group("version")),
                    name=match.group("name"),
                    filename=path.name,
                    sql=sql,
                    checksum=checksum,
                )
            )

        versions = [migration.version for migration in migrations]

        if len(versions) != len(set(versions)):
            raise MigrationError("Duplicate migration version detected.")

        if versions != sorted(versions):
            raise MigrationError(
                "Migration files are not in numeric order."
            )

        expected = list(range(1, len(versions) + 1))

        if versions != expected:
            raise MigrationError(
                "Migration versions must form a contiguous sequence "
                "starting at 0001."
            )

        return migrations

    def _ensure_history_table(self, connection: psycopg.Connection) -> None:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS schema_migrations (
                version INTEGER PRIMARY KEY,
                name TEXT NOT NULL,
                checksum TEXT NOT NULL,
                applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
            )
            """
        )

    def _get_applied(
        self,
        connection: psycopg.Connection,
    ) -> dict[int, tuple[str, str]]:
        rows = connection.execute(
            """
            SELECT version, name, checksum
            FROM schema_migrations
            ORDER BY version
            """
        ).fetchall()

        return {
            int(version): (str(name), str(checksum))
            for version, name, checksum in rows
        }

    @staticmethod
    def _strip_transaction_wrapper(sql: str) -> str:
        """
        Remove the explicit BEGIN/COMMIT wrapper used by the project's
        migration files.

        The runner itself owns the transaction boundary.
        """

        lines = sql.splitlines()

        while lines and not lines[0].strip():
            lines.pop(0)

        while lines and not lines[-1].strip():
            lines.pop()

        if lines and lines[0].strip().upper() == "BEGIN;":
            lines.pop(0)

        while lines and not lines[0].strip():
            lines.pop(0)

        if lines and lines[-1].strip().upper() == "COMMIT;":
            lines.pop()

        return "\n".join(lines).strip()

    def baseline(self) -> None:
        """
        Record the currently existing migration set without executing it.

        This is intended ONLY for an already-migrated database.

        The method verifies that all expected migration files exist and
        records their exact checksums. It refuses to baseline a database
        that already contains migration history.
        """

        migrations = self.discover()

        with psycopg.connect(self._dsn) as connection:
            with connection.transaction():
                connection.execute(
                    f"SELECT pg_advisory_lock({_MIGRATION_LOCK_KEY})"
                )

                self._ensure_history_table(connection)

                applied = self._get_applied(connection)

                if applied:
                    raise MigrationError(
                        "schema_migrations is not empty; refusing to baseline."
                    )

                for migration in migrations:
                    connection.execute(
                        """
                        INSERT INTO schema_migrations
                            (version, name, checksum)
                        VALUES
                            (%s, %s, %s)
                        """,
                        (
                            migration.version,
                            migration.name,
                            migration.checksum,
                        ),
                    )

    def migrate(self) -> list[int]:
        """
        Apply all pending migrations.

        Returns the versions applied during this invocation.
        """

        migrations = self.discover()
        applied_versions: list[int] = []

        with psycopg.connect(self._dsn) as connection:
            with connection.transaction():
                connection.execute(
                    f"SELECT pg_advisory_lock({_MIGRATION_LOCK_KEY})"
                )
                self._ensure_history_table(connection)

            with connection.transaction():
                applied = self._get_applied(connection)

                self._validate_history(migrations, applied)

            for migration in migrations:
                with connection.transaction():
                    applied = self._get_applied(connection)

                    existing = applied.get(migration.version)

                    if existing is not None:
                        continue

                    expected_version = (
                        max(applied.keys(), default=0) + 1
                    )

                    if migration.version != expected_version:
                        raise MigrationError(
                            "Migration sequence violation: "
                            f"expected {expected_version:04d}, "
                            f"found {migration.version:04d}."
                        )

                    sql = self._strip_transaction_wrapper(
                        migration.sql
                    )

                    if not sql:
                        raise MigrationError(
                            f"Migration {migration.filename} is empty."
                        )

                    connection.execute(sql) # type: ignore

                    connection.execute(
                        """
                        INSERT INTO schema_migrations
                            (version, name, checksum)
                        VALUES
                            (%s, %s, %s)
                        """,
                        (
                            migration.version,
                            migration.name,
                            migration.checksum,
                        ),
                    )

                    applied_versions.append(migration.version)

        return applied_versions

    @staticmethod
    def _validate_history(
        migrations: list[Migration],
        applied: dict[int, tuple[str, str]],
    ) -> None:
        migration_by_version = {
            migration.version: migration
            for migration in migrations
        }

        for version, (name, checksum) in applied.items():
            migration = migration_by_version.get(version)

            if migration is None:
                raise MigrationError(
                    f"Database contains unknown migration "
                    f"version {version:04d}."
                )

            if name != migration.name:
                raise MigrationError(
                    f"Migration {version:04d} name mismatch: "
                    f"database={name!r}, "
                    f"file={migration.name!r}."
                )

            if checksum != migration.checksum:
                raise MigrationError(
                    f"Migration {version:04d} checksum mismatch. "
                    "A previously applied migration has been modified."
                )

        versions = sorted(applied)

        if versions != list(range(1, len(versions) + 1)):
            raise MigrationError(
                "Applied migration history contains a gap or invalid order."
            )
