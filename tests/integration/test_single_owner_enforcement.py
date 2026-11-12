from __future__ import annotations

import re
import shutil
import uuid
from datetime import datetime, timezone
from pathlib import Path

import psycopg
import pytest

from backend.database.migration_runner import MigrationRunner
from backend.database.owner_store import PostgresOwnerStore
from backend.security.owner_bootstrap import bootstrap_owner

ADMIN_DSN = "dbname=postgres user=postgres host=localhost port=5432"
ARGON2_HASH = "$argon2id$v=19$m=65536,t=3,p=4$c29tZXNhbHQ$c29tZWhhc2g"


def _find_migrations_dir() -> Path:
    for parent in Path(__file__).resolve().parents:
        candidate = parent / "backend" / "database" / "migrations"
        if candidate.is_dir():
            return candidate
    raise RuntimeError("Could not locate backend/database/migrations")


MIGRATIONS_DIR = _find_migrations_dir()


def _dsn(database_name: str) -> str:
    return f"dbname={database_name} user=postgres host=localhost port=5432"


def _create_database() -> str:
    name = f"eldorado_owner_test_{uuid.uuid4().hex}"
    with psycopg.connect(ADMIN_DSN, autocommit=True) as connection:
        connection.execute(f'CREATE DATABASE "{name}"')
    return name


def _drop_database(name: str) -> None:
    with psycopg.connect(ADMIN_DSN, autocommit=True) as connection:
        connection.execute(f'DROP DATABASE IF EXISTS "{name}" WITH (FORCE)')


@pytest.fixture
def database_name():
    name = _create_database()
    try:
        MigrationRunner(_dsn(name), MIGRATIONS_DIR).migrate()
        yield name
    finally:
        _drop_database(name)


@pytest.fixture
def admin_dsn(database_name: str) -> str:
    return _dsn(database_name)


@pytest.fixture
def app_dsn(database_name: str) -> str:
    return _dsn(database_name) + " options='-c role=eldorado_app'"


@pytest.fixture
def legacy_database(tmp_path: Path):
    """A database migrated only as far as 0012, like the dev database."""
    staged = tmp_path / "migrations"
    staged.mkdir()
    for path in MIGRATIONS_DIR.iterdir():
        match = re.match(r"^(\d{4})_", path.name)
        if path.is_file() and match and int(match.group(1)) <= 12:
            shutil.copy(path, staged / path.name)

    name = _create_database()
    try:
        MigrationRunner(_dsn(name), staged).migrate()
        yield name
    finally:
        _drop_database(name)


def _bootstrap(admin_dsn: str, email: str = "owner@example.com") -> uuid.UUID:
    with psycopg.connect(admin_dsn) as connection:
        return connection.execute(
            "SELECT public.bootstrap_owner_account(%s::text, %s::text)",
            (email, ARGON2_HASH),
        ).fetchone()[0]


def _register(app_dsn: str, email: str) -> uuid.UUID:
    token_hash = uuid.uuid4().hex + uuid.uuid4().hex
    with psycopg.connect(app_dsn) as connection:
        return connection.execute(
            "SELECT public.create_pending_email_account("
            "%s::text, %s::text, %s::text)",
            (email, ARGON2_HASH, token_hash),
        ).fetchone()[0]


def _insert_user(
    admin_dsn: str,
    *,
    email: str | None = None,
    owner: bool = False,
) -> uuid.UUID:
    password_hash = ARGON2_HASH if email else None
    verified_at = datetime.now(timezone.utc) if email else None
    with psycopg.connect(admin_dsn) as connection:
        return connection.execute(
            "INSERT INTO public.users "
            "(email, password_hash, email_verified_at, is_owner) "
            "VALUES (%s, %s, %s, %s) RETURNING id",
            (email, password_hash, verified_at, owner),
        ).fetchone()[0]


def _insert_legacy_user(dsn: str, email: str | None) -> None:
    password_hash = ARGON2_HASH if email else None
    verified_at = datetime.now(timezone.utc) if email else None
    with psycopg.connect(dsn) as connection:
        connection.execute(
            "INSERT INTO public.users "
            "(email, password_hash, email_verified_at) VALUES (%s, %s, %s)",
            (email, password_hash, verified_at),
        )


def _app_write_privileges(dsn: str) -> list[bool]:
    with psycopg.connect(dsn) as connection:
        return [
            connection.execute(
                "SELECT has_table_privilege("
                "'eldorado_app', 'public.users', %s)",
                (privilege,),
            ).fetchone()[0]
            for privilege in ("INSERT", "UPDATE", "DELETE", "TRUNCATE")
        ]


def test_bootstrap_creates_verified_active_owner(admin_dsn: str) -> None:
    user_id = _bootstrap(admin_dsn, "  Owner@Example.COM ")

    with psycopg.connect(admin_dsn) as connection:
        row = connection.execute(
            "SELECT email, is_owner, is_active, "
            "email_verified_at IS NOT NULL "
            "FROM public.users WHERE id = %s",
            (user_id,),
        ).fetchone()

    assert row == ("owner@example.com", True, True, True)


def test_bootstrap_refuses_a_second_owner(admin_dsn: str) -> None:
    _bootstrap(admin_dsn)

    with pytest.raises(psycopg.errors.ObjectNotInPrerequisiteState):
        _bootstrap(admin_dsn, "other@example.com")

    with psycopg.connect(admin_dsn) as connection:
        count = connection.execute(
            "SELECT count(*) FROM public.users WHERE email IS NOT NULL"
        ).fetchone()[0]
    assert count == 1


def test_bootstrap_refuses_when_pending_account_exists(
    admin_dsn: str,
    app_dsn: str,
) -> None:
    _register(app_dsn, "pending@example.com")

    with pytest.raises(psycopg.errors.ObjectNotInPrerequisiteState):
        _bootstrap(admin_dsn)


@pytest.mark.parametrize(
    ("email", "password_hash"),
    [
        ("", ARGON2_HASH),
        (None, ARGON2_HASH),
        ("owner@example.com", "not-an-argon2id-hash"),
        ("owner@example.com", None),
    ],
)
def test_bootstrap_rejects_invalid_input(
    admin_dsn: str,
    email: str | None,
    password_hash: str | None,
) -> None:
    with pytest.raises(psycopg.errors.InvalidParameterValue):
        with psycopg.connect(admin_dsn) as connection:
            connection.execute(
                "SELECT public.bootstrap_owner_account(%s::text, %s::text)",
                (email, password_hash),
            )


def test_app_role_cannot_run_bootstrap(app_dsn: str) -> None:
    with pytest.raises(psycopg.errors.InsufficientPrivilege):
        with psycopg.connect(app_dsn) as connection:
            connection.execute(
                "SELECT public.bootstrap_owner_account(%s::text, %s::text)",
                ("owner@example.com", ARGON2_HASH),
            )


def test_registration_still_works_before_an_owner_exists(
    app_dsn: str,
) -> None:
    assert isinstance(_register(app_dsn, "first@example.com"), uuid.UUID)


def test_registration_is_refused_once_owner_exists(
    admin_dsn: str,
    app_dsn: str,
) -> None:
    _bootstrap(admin_dsn)

    with pytest.raises(psycopg.errors.InsufficientPrivilege):
        _register(app_dsn, "second@example.com")


def test_direct_insert_is_refused_once_owner_exists(admin_dsn: str) -> None:
    _bootstrap(admin_dsn)

    with pytest.raises(psycopg.errors.InsufficientPrivilege):
        _insert_user(admin_dsn, email="second@example.com")


def test_accounts_without_email_remain_possible_after_owner(
    admin_dsn: str,
) -> None:
    _bootstrap(admin_dsn)

    assert isinstance(_insert_user(admin_dsn), uuid.UUID)


def test_unique_index_allows_only_one_owner(admin_dsn: str) -> None:
    _bootstrap(admin_dsn)

    with pytest.raises(psycopg.errors.UniqueViolation):
        _insert_user(admin_dsn, email="second@example.com", owner=True)


def test_owner_requires_an_email(admin_dsn: str) -> None:
    with pytest.raises(psycopg.errors.CheckViolation):
        _insert_user(admin_dsn, owner=True)


def test_app_role_has_no_write_privileges_on_users(admin_dsn: str) -> None:
    assert _app_write_privileges(admin_dsn) == [False, False, False, False]


def test_new_functions_are_hardened(admin_dsn: str) -> None:
    with psycopg.connect(admin_dsn) as connection:
        rows = connection.execute(
            "SELECT p.proname, p.prosecdef, pg_get_userbyid(p.proowner), "
            "p.proconfig "
            "FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace "
            "WHERE n.nspname = 'public' AND p.proname IN "
            "('bootstrap_owner_account', 'guard_single_owner_account')"
        ).fetchall()

    assert len(rows) == 2
    for _name, security_definer, owner, config in rows:
        assert security_definer is True
        assert owner == "postgres"
        settings = [c for c in (config or []) if c.startswith("search_path=")]
        assert settings, "search_path must be pinned"
        assert "public" not in settings[0]


def test_upgrade_marks_the_single_email_account_as_owner(
    legacy_database: str,
) -> None:
    dsn = _dsn(legacy_database)
    with psycopg.connect(dsn) as connection:
        connection.execute(
            "GRANT INSERT, UPDATE, DELETE ON public.users TO eldorado_app"
        )
    _insert_legacy_user(dsn, None)
    _insert_legacy_user(dsn, None)
    _insert_legacy_user(dsn, "owner@example.com")

    applied = MigrationRunner(dsn, MIGRATIONS_DIR).migrate()

    assert applied == [13]
    with psycopg.connect(dsn) as connection:
        rows = connection.execute(
            "SELECT email, is_owner FROM public.users"
        ).fetchall()
    assert len(rows) == 3
    assert [r for r in rows if r[1]] == [("owner@example.com", True)]
    assert _app_write_privileges(dsn) == [False, False, False, False]


def test_upgrade_fails_when_two_login_capable_accounts_exist(
    legacy_database: str,
) -> None:
    dsn = _dsn(legacy_database)
    _insert_legacy_user(dsn, "one@example.com")
    _insert_legacy_user(dsn, "two@example.com")

    with pytest.raises(psycopg.errors.ObjectNotInPrerequisiteState):
        MigrationRunner(dsn, MIGRATIONS_DIR).migrate()

    with psycopg.connect(dsn) as connection:
        latest = connection.execute(
            "SELECT max(version) FROM schema_migrations"
        ).fetchone()[0]
        column = connection.execute(
            "SELECT count(*) FROM information_schema.columns "
            "WHERE table_schema = 'public' AND table_name = 'users' "
            "AND column_name = 'is_owner'"
        ).fetchone()[0]
    assert latest == 12
    assert column == 0


def test_owner_store_creates_then_refuses(admin_dsn: str) -> None:
    store = PostgresOwnerStore(admin_dsn)

    first = store.create_owner_account("owner@example.com", ARGON2_HASH)
    second = store.create_owner_account("other@example.com", ARGON2_HASH)

    assert isinstance(first, uuid.UUID)
    assert second is None


def test_owner_store_cannot_run_as_the_app_role(app_dsn: str) -> None:
    with pytest.raises(psycopg.errors.InsufficientPrivilege):
        PostgresOwnerStore(app_dsn).create_owner_account(
            "owner@example.com",
            ARGON2_HASH,
        )


def test_bootstrap_owner_end_to_end(admin_dsn: str) -> None:
    owner = bootstrap_owner(
        PostgresOwnerStore(admin_dsn),
        "  Owner@Example.COM ",
        "a-sufficiently-long-owner-passphrase",
    )

    assert owner == "owner@example.com"
    with psycopg.connect(admin_dsn) as connection:
        row = connection.execute(
            "SELECT is_owner, is_active, email_verified_at IS NOT NULL, "
            "password_hash LIKE '$argon2id$%%' "
            "FROM public.users WHERE email = %s",
            (owner,),
        ).fetchone()
    assert row == (True, True, True, True)

    with pytest.raises(Exception, match="already exists"):
        bootstrap_owner(
            PostgresOwnerStore(admin_dsn),
            "other@example.com",
            "another-sufficiently-long-passphrase",
        )
