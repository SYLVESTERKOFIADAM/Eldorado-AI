import os
import sys
from pathlib import Path

import psycopg

from backend.database.migration_runner import MigrationRunner

dsn = os.environ["ELDORADO_MIGRATION_DSN"]
runner = MigrationRunner(dsn, Path("backend/database/migrations"))


def applied() -> list[int]:
    with psycopg.connect(dsn) as connection:
        exists = connection.execute(
            "SELECT to_regclass('schema_migrations')"
        ).fetchone()[0]
        if exists is None:
            return []
        rows = connection.execute(
            "SELECT version FROM schema_migrations ORDER BY version"
        ).fetchall()
        return [int(r[0]) for r in rows]


mode = sys.argv[1]

if mode == "status":
    files = runner.discover()
    print(f"FILES:{len(files)}")
    print("APPLIED:" + ",".join(str(v) for v in applied()))
elif mode == "migrate":
    done = runner.migrate()
    print("APPLIED_NOW:" + ",".join(str(v) for v in done))
else:
    raise SystemExit("unknown mode")