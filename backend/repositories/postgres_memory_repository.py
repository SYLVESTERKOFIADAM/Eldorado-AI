from __future__ import annotations

from uuid import UUID

from backend.database.connection import DatabaseConnection
from backend.models.memory import (
    MemoryProvenance,
    MemoryRecord,
    MemorySensitivity,
    MemoryStatus,
    MemoryType,
)
from backend.repositories.memory_repository import MemoryRepository


class PostgresMemoryRepository(MemoryRepository):
    """
    PostgreSQL-backed memory repository.

    Security boundary:
    - The authenticated user ID establishes the PostgreSQL RLS identity.
    - MemoryRecord.user_id is persisted data, not an authorization source.
    - PostgreSQL RLS enforces cross-user isolation.
    """

    def __init__(
        self,
        database: DatabaseConnection,
        authenticated_user_id: UUID,
    ) -> None:
        self._database = database
        self._authenticated_user_id = authenticated_user_id

    def save(self, memory: MemoryRecord) -> MemoryRecord:
        with self._database.transaction(
            self._authenticated_user_id
        ) as connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    """
                    INSERT INTO memories (
                        id,
                        user_id,
                        memory_type,
                        content,
                        provenance,
                        confidence,
                        sensitivity,
                        status,
                        user_approved,
                        conflict_key,
                        created_at,
                        updated_at,
                        last_used_at,
                        expires_at
                    )
                    VALUES (
                        %s, %s, %s, %s, %s, %s, %s,
                        %s, %s, %s, %s, %s, %s, %s
                    )
                    RETURNING
                        id,
                        user_id,
                        memory_type,
                        content,
                        provenance,
                        confidence,
                        sensitivity,
                        status,
                        user_approved,
                        conflict_key,
                        created_at,
                        updated_at,
                        last_used_at,
                        expires_at
                    """,
                    (
                        memory.id,
                        memory.user_id,
                        memory.memory_type.value,
                        memory.content,
                        memory.provenance.value,
                        memory.confidence,
                        memory.sensitivity.value,
                        memory.status.value,
                        memory.user_approved,
                        memory.conflict_key,
                        memory.created_at,
                        memory.updated_at,
                        memory.last_used_at,
                        memory.expires_at,
                    ),
                )

                row = cursor.fetchone()

        if row is None:
            raise RuntimeError("Memory INSERT returned no row.")

        return self._row_to_memory(row)

    def get(self, memory_id: UUID) -> MemoryRecord | None:
        with self._database.transaction(
            self._authenticated_user_id
        ) as connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    """
                    SELECT
                        id,
                        user_id,
                        memory_type,
                        content,
                        provenance,
                        confidence,
                        sensitivity,
                        status,
                        user_approved,
                        conflict_key,
                        created_at,
                        updated_at,
                        last_used_at,
                        expires_at
                    FROM memories
                    WHERE id = %s
                    """,
                    (memory_id,),
                )

                row = cursor.fetchone()

        if row is None:
            return None

        return self._row_to_memory(row)

    def update(self, memory: MemoryRecord) -> MemoryRecord:
        with self._database.transaction(
            self._authenticated_user_id
        ) as connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    """
                    UPDATE memories
                    SET
                        user_id = %s,
                        memory_type = %s,
                        content = %s,
                        provenance = %s,
                        confidence = %s,
                        sensitivity = %s,
                        status = %s,
                        user_approved = %s,
                        conflict_key = %s,
                        created_at = %s,
                        updated_at = %s,
                        last_used_at = %s,
                        expires_at = %s
                    WHERE id = %s
                    RETURNING
                        id,
                        user_id,
                        memory_type,
                        content,
                        provenance,
                        confidence,
                        sensitivity,
                        status,
                        user_approved,
                        conflict_key,
                        created_at,
                        updated_at,
                        last_used_at,
                        expires_at
                    """,
                    (
                        memory.user_id,
                        memory.memory_type.value,
                        memory.content,
                        memory.provenance.value,
                        memory.confidence,
                        memory.sensitivity.value,
                        memory.status.value,
                        memory.user_approved,
                        memory.conflict_key,
                        memory.created_at,
                        memory.updated_at,
                        memory.last_used_at,
                        memory.expires_at,
                        memory.id,
                    ),
                )

                row = cursor.fetchone()

        if row is None:
            raise LookupError("Memory was not found.")

        return self._row_to_memory(row)

    def list_by_user(
        self,
        user_id: UUID,
    ) -> list[MemoryRecord]:
        with self._database.transaction(
            self._authenticated_user_id
        ) as connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    """
                    SELECT
                        id,
                        user_id,
                        memory_type,
                        content,
                        provenance,
                        confidence,
                        sensitivity,
                        status,
                        user_approved,
                        conflict_key,
                        created_at,
                        updated_at,
                        last_used_at,
                        expires_at
                    FROM memories
                    WHERE user_id = %s
                    ORDER BY updated_at DESC
                    """,
                    (user_id,),
                )

                rows = cursor.fetchall()

        return [
            self._row_to_memory(row)
            for row in rows
        ]

    def delete(self, memory_id: UUID) -> None:
        with self._database.transaction(
            self._authenticated_user_id
        ) as connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    """
                    DELETE FROM memories
                    WHERE id = %s
                    """,
                    (memory_id,),
                )

    @staticmethod
    def _row_to_memory(row: tuple) -> MemoryRecord:
        return MemoryRecord(
            id=row[0],
            user_id=row[1],
            memory_type=MemoryType(row[2]),
            content=row[3],
            provenance=MemoryProvenance(row[4]),
            confidence=row[5],
            sensitivity=MemorySensitivity(row[6]),
            status=MemoryStatus(row[7]),
            user_approved=row[8],
            conflict_key=row[9],
            created_at=row[10],
            updated_at=row[11],
            last_used_at=row[12],
            expires_at=row[13],
        )