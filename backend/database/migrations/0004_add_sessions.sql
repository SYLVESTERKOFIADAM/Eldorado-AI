-- Eldorado-AI
-- Migration 0004: Add secure authentication sessions

BEGIN;

CREATE TABLE sessions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    user_id UUID NOT NULL
        REFERENCES users(id)
        ON DELETE CASCADE,

    token_family_id UUID NOT NULL,

    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_used_at TIMESTAMPTZ,
    expires_at TIMESTAMPTZ NOT NULL,

    revoked_at TIMESTAMPTZ,
    reuse_detected_at TIMESTAMPTZ,

    CONSTRAINT sessions_expiry_after_creation
        CHECK (expires_at > created_at),

    CONSTRAINT sessions_last_used_after_creation
        CHECK (
            last_used_at IS NULL
            OR last_used_at >= created_at
        ),

    CONSTRAINT sessions_revoked_after_creation
        CHECK (
            revoked_at IS NULL
            OR revoked_at >= created_at
        ),

    CONSTRAINT sessions_reuse_detected_after_creation
        CHECK (
            reuse_detected_at IS NULL
            OR reuse_detected_at >= created_at
        )
);

CREATE TABLE refresh_tokens (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    session_id UUID NOT NULL
        REFERENCES sessions(id)
        ON DELETE CASCADE,

    token_hash TEXT NOT NULL UNIQUE,

    issued_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ NOT NULL,

    consumed_at TIMESTAMPTZ,

    replaced_by_id UUID
        REFERENCES refresh_tokens(id)
        ON DELETE SET NULL,

    CONSTRAINT refresh_tokens_hash_not_blank
        CHECK (length(trim(token_hash)) > 0),

    CONSTRAINT refresh_tokens_expiry_after_issue
        CHECK (expires_at > issued_at),

    CONSTRAINT refresh_tokens_consumed_after_issue
        CHECK (
            consumed_at IS NULL
            OR consumed_at >= issued_at
        ),

    CONSTRAINT refresh_tokens_not_self_replaced
        CHECK (
            replaced_by_id IS NULL
            OR replaced_by_id <> id
        )
);

CREATE INDEX idx_sessions_user_id
    ON sessions(user_id);

CREATE INDEX idx_sessions_token_family_id
    ON sessions(token_family_id);

CREATE INDEX idx_sessions_expires_at
    ON sessions(expires_at);

CREATE INDEX idx_sessions_user_active
    ON sessions(user_id, expires_at)
    WHERE revoked_at IS NULL;

CREATE INDEX idx_refresh_tokens_session_id
    ON refresh_tokens(session_id);

CREATE INDEX idx_refresh_tokens_expires_at
    ON refresh_tokens(expires_at);

CREATE INDEX idx_refresh_tokens_active
    ON refresh_tokens(session_id, expires_at)
    WHERE consumed_at IS NULL;

CREATE INDEX idx_refresh_tokens_replaced_by_id
    ON refresh_tokens(replaced_by_id)
    WHERE replaced_by_id IS NOT NULL;

ALTER TABLE sessions ENABLE ROW LEVEL SECURITY;
ALTER TABLE sessions FORCE ROW LEVEL SECURITY;

ALTER TABLE refresh_tokens ENABLE ROW LEVEL SECURITY;
ALTER TABLE refresh_tokens FORCE ROW LEVEL SECURITY;

CREATE POLICY sessions_isolation_policy
    ON sessions
    USING (
        user_id = public.current_app_user_id()
    )
    WITH CHECK (
        user_id = public.current_app_user_id()
    );

CREATE POLICY refresh_tokens_isolation_policy
    ON refresh_tokens
    USING (
        EXISTS (
            SELECT 1
            FROM sessions
            WHERE sessions.id = refresh_tokens.session_id
              AND sessions.user_id = public.current_app_user_id()
        )
    )
    WITH CHECK (
        EXISTS (
            SELECT 1
            FROM sessions
            WHERE sessions.id = refresh_tokens.session_id
              AND sessions.user_id = public.current_app_user_id()
        )
    );

COMMIT;
