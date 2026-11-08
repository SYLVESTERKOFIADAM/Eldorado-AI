-- Eldorado-AI
-- Migration 0012: Password reset and password change
--
-- Security:
--   * Existing migrations remain immutable.
--   * Reset tokens are stored only as SHA-256 hashes, single use, 30 minutes.
--   * Only active, verified accounts can reset. 60 second issue cooldown.
--   * Completing a reset or change revokes every session for the user.
--   * The application role has no direct table access; it may execute the
--     four functions below. Execution is revoked from PUBLIC.

BEGIN;

CREATE TABLE public.password_reset_tokens (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    user_id UUID NOT NULL
        REFERENCES public.users(id)
        ON DELETE CASCADE,

    token_hash TEXT NOT NULL UNIQUE,

    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    expires_at TIMESTAMPTZ NOT NULL,
    consumed_at TIMESTAMPTZ,

    CONSTRAINT password_reset_token_hash_format
        CHECK (token_hash ~ '^[0-9a-f]{64}$'),

    CONSTRAINT password_reset_expiry_valid
        CHECK (expires_at > created_at),

    CONSTRAINT password_reset_consumption_valid
        CHECK (consumed_at IS NULL OR consumed_at >= created_at)
);

CREATE INDEX password_reset_tokens_user_id
    ON public.password_reset_tokens (user_id);

REVOKE ALL PRIVILEGES
    ON TABLE public.password_reset_tokens
    FROM PUBLIC, eldorado_app;

ALTER TABLE public.password_reset_tokens
    ENABLE ROW LEVEL SECURITY;

ALTER TABLE public.password_reset_tokens
    FORCE ROW LEVEL SECURITY;

CREATE POLICY password_reset_tokens_user_isolation
    ON public.password_reset_tokens
    USING (user_id = public.current_app_user_id())
    WITH CHECK (user_id = public.current_app_user_id());

-- Issue a reset token for an active, verified account.
-- TRUE = stored, FALSE = declined (unknown, unverified, inactive, cooldown).
CREATE FUNCTION public.issue_password_reset_token(
    p_email TEXT,
    p_token_hash TEXT
)
RETURNS BOOLEAN
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
    normalized_email TEXT;
    target_user_id UUID;
    latest_created TIMESTAMPTZ;
    now_at TIMESTAMPTZ := clock_timestamp();
BEGIN
    IF p_email IS NULL OR btrim(p_email) = ''
       OR p_token_hash IS NULL
       OR p_token_hash !~ '^[0-9a-f]{64}$' THEN
        RAISE EXCEPTION USING
            ERRCODE = '22023',
            MESSAGE = 'Invalid password reset input';
    END IF;

    normalized_email := lower(btrim(p_email));

    SELECT account.id
    INTO target_user_id
    FROM public.users AS account
    WHERE account.email = normalized_email
      AND account.password_hash IS NOT NULL
      AND account.email_verified_at IS NOT NULL
      AND account.is_active = TRUE
    FOR UPDATE;

    IF NOT FOUND THEN
        RETURN FALSE;
    END IF;

    -- Refresh the timestamp after acquiring the user lock.
    now_at := clock_timestamp();

    SELECT max(token.created_at)
    INTO latest_created
    FROM public.password_reset_tokens AS token
    WHERE token.user_id = target_user_id;

    IF latest_created IS NOT NULL
       AND latest_created > now_at - INTERVAL '60 seconds' THEN
        RETURN FALSE;
    END IF;

    UPDATE public.password_reset_tokens AS token
    SET consumed_at = now_at
    WHERE token.user_id = target_user_id
      AND token.consumed_at IS NULL;

    INSERT INTO public.password_reset_tokens (
        user_id,
        token_hash,
        created_at,
        expires_at
    )
    VALUES (
        target_user_id,
        p_token_hash,
        now_at,
        now_at + INTERVAL '30 minutes'
    );

    RETURN TRUE;
END;
$$;

ALTER FUNCTION public.issue_password_reset_token(TEXT, TEXT)
    OWNER TO postgres;

REVOKE ALL
ON FUNCTION public.issue_password_reset_token(TEXT, TEXT)
FROM PUBLIC;

GRANT EXECUTE
ON FUNCTION public.issue_password_reset_token(TEXT, TEXT)
TO eldorado_app;

-- Consume a reset token, set the new password hash and revoke all sessions.
-- Returns RESET or INVALID. Unknown, expired, used or otherwise invalid
-- tokens are indistinguishable.
CREATE FUNCTION public.reset_password(
    p_token_hash TEXT,
    p_new_password_hash TEXT
)
RETURNS TEXT
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
    token_row public.password_reset_tokens%ROWTYPE;
    target_user_id UUID;
    now_at TIMESTAMPTZ := clock_timestamp();
BEGIN
    IF p_token_hash IS NULL
       OR p_token_hash !~ '^[0-9a-f]{64}$'
       OR p_new_password_hash IS NULL
       OR p_new_password_hash NOT LIKE '$argon2id$%' THEN
        RETURN 'INVALID';
    END IF;

    -- Discover the owning user without locking the token row.
    SELECT token.user_id
    INTO target_user_id
    FROM public.password_reset_tokens AS token
    WHERE token.token_hash = p_token_hash;

    IF NOT FOUND THEN
        RETURN 'INVALID';
    END IF;

    -- Lock the user before locking any reset-token row.
    -- This matches issue_password_reset_token() lock ordering.
    SELECT account.id
    INTO target_user_id
    FROM public.users AS account
    WHERE account.id = target_user_id
      AND account.password_hash IS NOT NULL
      AND account.email_verified_at IS NOT NULL
      AND account.is_active = TRUE
    FOR UPDATE;

    IF NOT FOUND THEN
        RETURN 'INVALID';
    END IF;

    -- Lock and revalidate the token after acquiring the user lock.
    SELECT token.*
    INTO token_row
    FROM public.password_reset_tokens AS token
    WHERE token.token_hash = p_token_hash
      AND token.user_id = target_user_id
    FOR UPDATE;

    IF NOT FOUND THEN
        RETURN 'INVALID';
    END IF;

    -- Use the current time after any lock wait.
    now_at := clock_timestamp();

    IF token_row.consumed_at IS NOT NULL
       OR token_row.expires_at <= now_at THEN
        RETURN 'INVALID';
    END IF;

    UPDATE public.users AS account
    SET password_hash = p_new_password_hash,
        updated_at = now_at
    WHERE account.id = target_user_id;

    UPDATE public.password_reset_tokens AS token
    SET consumed_at = now_at
    WHERE token.user_id = target_user_id
      AND token.consumed_at IS NULL;

    UPDATE public.sessions AS session_row
    SET revoked_at = now_at
    WHERE session_row.user_id = target_user_id
      AND session_row.revoked_at IS NULL;

    RETURN 'RESET';
END;
$$;

ALTER FUNCTION public.reset_password(TEXT, TEXT)
    OWNER TO postgres;

REVOKE ALL
ON FUNCTION public.reset_password(TEXT, TEXT)
FROM PUBLIC;

GRANT EXECUTE
ON FUNCTION public.reset_password(TEXT, TEXT)
TO eldorado_app;

-- The authenticated user's own password hash. Identity comes only from the
-- transaction-local app.current_user_id, never from a parameter.
CREATE FUNCTION public.get_own_password_hash()
RETURNS TEXT
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
    SELECT account.password_hash
    FROM public.users AS account
    WHERE account.id = public.current_app_user_id()
      AND account.is_active = TRUE
      AND account.email_verified_at IS NOT NULL;
$$;

ALTER FUNCTION public.get_own_password_hash()
    OWNER TO postgres;

REVOKE ALL
ON FUNCTION public.get_own_password_hash()
FROM PUBLIC;

GRANT EXECUTE
ON FUNCTION public.get_own_password_hash()
TO eldorado_app;

-- Compare-and-swap the authenticated user's password hash, then revoke
-- all of that user's sessions. FALSE if the stored hash no longer matches.
CREATE FUNCTION public.change_own_password(
    p_expected_hash TEXT,
    p_new_hash TEXT
)
RETURNS BOOLEAN
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
    current_user_uuid UUID := public.current_app_user_id();
    changed_user_id UUID;
    now_at TIMESTAMPTZ := clock_timestamp();
BEGIN
    IF p_expected_hash IS NULL
       OR p_new_hash IS NULL
       OR p_new_hash NOT LIKE '$argon2id$%' THEN
        RAISE EXCEPTION USING
            ERRCODE = '22023',
            MESSAGE = 'Invalid password change input';
    END IF;

    IF current_user_uuid IS NULL THEN
        RETURN FALSE;
    END IF;

    UPDATE public.users AS account
    SET password_hash = p_new_hash,
        updated_at = now_at
    WHERE account.id = current_user_uuid
      AND account.password_hash = p_expected_hash
      AND account.is_active = TRUE
      AND account.email_verified_at IS NOT NULL
    RETURNING account.id INTO changed_user_id;

    IF NOT FOUND THEN
        RETURN FALSE;
    END IF;

    -- Outstanding reset tokens must not survive a password change.
    UPDATE public.password_reset_tokens AS token
    SET consumed_at = now_at
    WHERE token.user_id = current_user_uuid
      AND token.consumed_at IS NULL;

    UPDATE public.sessions AS session_row
    SET revoked_at = now_at
    WHERE session_row.user_id = current_user_uuid
      AND session_row.revoked_at IS NULL;

    RETURN TRUE;
END;
$$;

ALTER FUNCTION public.change_own_password(TEXT, TEXT)
    OWNER TO postgres;

REVOKE ALL
ON FUNCTION public.change_own_password(TEXT, TEXT)
FROM PUBLIC;

GRANT EXECUTE
ON FUNCTION public.change_own_password(TEXT, TEXT)
TO eldorado_app;

COMMIT;