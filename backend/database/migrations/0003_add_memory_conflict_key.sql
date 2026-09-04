-- Eldorado-AI
-- Migration 0003: Add structured memory conflict identity
--
-- Security principles:
--   1. Conflict identity is personalization metadata, not authorization.
--   2. Existing memories remain valid with a NULL conflict key.
--   3. Conflict matching remains scoped to authenticated ownership.
--   4. The conflict key cannot grant permissions or capabilities.

BEGIN;

ALTER TABLE memories
    ADD COLUMN conflict_key TEXT;

ALTER TABLE memories
    ADD CONSTRAINT memories_conflict_key_not_blank
    CHECK (
        conflict_key IS NULL
        OR length(trim(conflict_key)) > 0
    );

CREATE INDEX idx_memories_user_type_conflict_status
    ON memories(user_id, memory_type, conflict_key, status);

COMMIT;
