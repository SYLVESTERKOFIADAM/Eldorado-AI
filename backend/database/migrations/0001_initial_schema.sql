-- Eldorado-AI
-- Migration 0001: Initial secure persistence schema
--
-- Security principles:
--   1. Memory is personalization data, not authorization.
--   2. Every memory belongs to exactly one application user.
--   3. Row-Level Security protects cross-user isolation.
--   4. Application identity is supplied through a transaction-local setting.
--   5. Database superusers are never application identities.

BEGIN;

CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- ============================================================
-- Users
-- ============================================================

CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    external_subject TEXT UNIQUE,

    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),

    is_active BOOLEAN NOT NULL DEFAULT TRUE,

    CONSTRAINT users_external_subject_not_blank
        CHECK (
            external_subject IS NULL
            OR length(trim(external_subject)) > 0
        )
);

-- ============================================================
-- Memories
-- ============================================================

CREATE TABLE memories (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    user_id UUID NOT NULL
        REFERENCES users(id)
        ON DELETE CASCADE,

    memory_type TEXT NOT NULL,

    content TEXT NOT NULL,

    provenance TEXT NOT NULL,

    confidence DOUBLE PRECISION NOT NULL DEFAULT 0.0,

    sensitivity TEXT NOT NULL DEFAULT 'internal',

    status TEXT NOT NULL DEFAULT 'candidate',

    user_approved BOOLEAN NOT NULL DEFAULT FALSE,

    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_used_at TIMESTAMPTZ,
    expires_at TIMESTAMPTZ,

    CONSTRAINT memories_content_not_blank
        CHECK (length(trim(content)) > 0),

    CONSTRAINT memories_confidence_range
        CHECK (confidence >= 0.0 AND confidence <= 1.0),

    CONSTRAINT memories_memory_type_valid
        CHECK (
            memory_type IN (
                'profile',
                'preference',
                'episodic',
                'feedback',
                'project',
                'temporary'
            )
        ),

    CONSTRAINT memories_provenance_valid
        CHECK (
            provenance IN (
                'explicit_user_statement',
                'user_feedback',
                'conversation_inference',
                'imported_data',
                'external_content'
            )
        ),

    CONSTRAINT memories_sensitivity_valid
        CHECK (
            sensitivity IN (
                'public',
                'internal',
                'sensitive',
                'restricted'
            )
        ),

    CONSTRAINT memories_status_valid
        CHECK (
            status IN (
                'candidate',
                'active',
                'superseded',
                'deleted',
                'expired',
                'quarantined'
            )
        ),

    CONSTRAINT memories_external_requires_approval
        CHECK (
            provenance NOT IN (
                'external_content',
                'imported_data'
            )
            OR user_approved = TRUE
            OR status <> 'active'
        )
);

-- ============================================================
-- Indexes
-- ============================================================

CREATE INDEX idx_memories_user_id
    ON memories(user_id);

CREATE INDEX idx_memories_user_status
    ON memories(user_id, status);

CREATE INDEX idx_memories_user_type
    ON memories(user_id, memory_type);

CREATE INDEX idx_memories_user_updated
    ON memories(user_id, updated_at DESC);

-- ============================================================
-- Row-Level Security
-- ============================================================

ALTER TABLE users ENABLE ROW LEVEL SECURITY;
ALTER TABLE users FORCE ROW LEVEL SECURITY;

ALTER TABLE memories ENABLE ROW LEVEL SECURITY;
ALTER TABLE memories FORCE ROW LEVEL SECURITY;

-- ============================================================
-- User isolation policy
--
-- The application sets:
--
--   app.current_user_id = <UUID>
--
-- inside a transaction.
--
-- Missing/invalid identity results in no matching rows.
-- ============================================================

CREATE POLICY users_isolation_policy
    ON users
    USING (
        id = NULLIF(
            current_setting('app.current_user_id', true),
            ''
        )::UUID
    )
    WITH CHECK (
        id = NULLIF(
            current_setting('app.current_user_id', true),
            ''
        )::UUID
    );

-- ============================================================
-- Memory isolation policy
-- ============================================================

CREATE POLICY memories_isolation_policy
    ON memories
    USING (
        user_id = NULLIF(
            current_setting('app.current_user_id', true),
            ''
        )::UUID
    )
    WITH CHECK (
        user_id = NULLIF(
            current_setting('app.current_user_id', true),
            ''
        )::UUID
    );

COMMIT;