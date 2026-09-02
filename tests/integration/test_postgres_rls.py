from uuid import UUID

import psycopg

from backend.database.connection import DatabaseConnection


DSN = "dbname=postgres user=eldorado_app host=localhost port=5432"

USER_A = UUID("76bab0d0-94f5-4925-a729-62e31726456f")
USER_B = UUID("dd0939fc-c93a-4f20-93de-3c1d6c88804f")

MEMORY_A = UUID("d6f6e0cb-cf12-489f-8635-afa669f570da")
MEMORY_B = UUID("04fc10e5-ca9a-4fc9-bba1-7a19ac184f55")


def test_user_a_can_read_only_own_memory():
    database = DatabaseConnection(DSN)

    with database.transaction(USER_A) as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT id, user_id
                FROM memories
                ORDER BY id
                """
            )
            rows = cursor.fetchall()

    assert len(rows) == 1
    assert rows[0][0] == MEMORY_A
    assert rows[0][1] == USER_A


def test_user_b_can_read_only_own_memory():
    database = DatabaseConnection(DSN)

    with database.transaction(USER_B) as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT id, user_id
                FROM memories
                ORDER BY id
                """
            )
            rows = cursor.fetchall()

    assert len(rows) == 1
    assert rows[0][0] == MEMORY_B
    assert rows[0][1] == USER_B


def test_cross_user_read_returns_no_rows():
    database = DatabaseConnection(DSN)

    with database.transaction(USER_A) as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT id, user_id, content
                FROM memories
                WHERE id = %s
                """,
                (MEMORY_B,),
            )
            row = cursor.fetchone()

    assert row is None


def test_cross_user_update_changes_zero_rows():
    database = DatabaseConnection(DSN)

    with database.transaction(USER_A) as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                UPDATE memories
                SET content = %s
                WHERE id = %s
                """,
                ("ATTACK SHOULD FAIL", MEMORY_B),
            )

            affected_rows = cursor.rowcount

    assert affected_rows == 0


def test_cross_user_insert_is_rejected():
    database = DatabaseConnection(DSN)

    try:
        with database.transaction(USER_A) as connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    """
                    INSERT INTO memories (
                        user_id,
                        memory_type,
                        content,
                        provenance,
                        status
                    )
                    VALUES (%s, %s, %s, %s, %s)
                    """,
                    (
                        USER_B,
                        "preference",
                        "CROSS USER INSERT SHOULD FAIL",
                        "explicit_user_statement",
                        "active",
                    ),
                )
    except psycopg.errors.InsufficientPrivilege:
        return

    raise AssertionError(
        "Cross-user INSERT was not rejected by RLS."
    )


def test_same_user_insert_is_allowed_and_rolled_back():
    database = DatabaseConnection(DSN)

    inserted_user_id = None

    try:
        with database.transaction(USER_A) as connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    """
                    INSERT INTO memories (
                        user_id,
                        memory_type,
                        content,
                        provenance,
                        status
                    )
                    VALUES (%s, %s, %s, %s, %s)
                    RETURNING user_id
                    """,
                    (
                        USER_A,
                        "preference",
                        "RLS SAME USER AUTOMATED TEST",
                        "explicit_user_statement",
                        "active",
                    ),
                )

                inserted_user_id = cursor.fetchone()[0]

            raise RuntimeError("ROLLBACK_TEST")
    except RuntimeError as exc:
        assert str(exc) == "ROLLBACK_TEST"

    assert inserted_user_id == USER_A


def test_malformed_identity_fails_closed():
    with psycopg.connect(DSN) as connection:
        with connection.transaction():
            with connection.cursor() as cursor:
                cursor.execute(
                    "SELECT set_config("
                    "'app.current_user_id', %s, true"
                    ")",
                    ("not-a-valid-uuid",),
                )

                cursor.execute(
                    """
                    SELECT id
                    FROM memories
                    """
                )

                rows = cursor.fetchall()

    assert rows == []


def test_missing_identity_fails_closed():
    with psycopg.connect(DSN) as connection:
        with connection.transaction():
            with connection.cursor() as cursor:
                cursor.execute(
                    """
                    SELECT id
                    FROM memories
                    """
                )

                rows = cursor.fetchall()

    assert rows == []


def test_identity_is_transaction_local():
    database = DatabaseConnection(DSN)

    with database.transaction(USER_A) as connection:
        with connection.cursor() as cursor:
            cursor.execute("SELECT current_app_user_id()")
            identity = cursor.fetchone()[0]

    assert identity == USER_A

    with psycopg.connect(DSN) as connection:
        with connection.transaction():
            with connection.cursor() as cursor:
                cursor.execute(
                    "SELECT current_app_user_id()"
                )
                identity_after_transaction = cursor.fetchone()[0]

    assert identity_after_transaction is None
