-- Eldorado-AI
-- Migration 0007: Email accounts and ownership verification
--
-- Security:
--   * Existing migrations remain immutable.
--   * Email/password accounts begin unverified.
--   * Verification tokens are stored only as SHA-256 hashes.
--   * Unauthenticated operations use narrowly scoped SECURITY DEFINER functions.
--   * Function execution is revoked from PUBLIC and granted to eldorado_app.
--   * No unrestricted table privileges are granted to the application role.

BEGIN;

ALTER TABLE public.users
    ADD COLUMN email TEXT,
    ADD COLUMN password_hash TEXT,
    ADD COLUMN email_verified_at TIMESTAMPTZ;

ALTER TABLE public.users
    ADD CONSTRAINT users_email_canonical
        CHECK (email IS NULL OR email = lower(btrim(email))),
    ADD CONSTRAINT users_email_password_pair
        CHECK (
            (email IS NULL AND password_hash IS NULL
                AND email_verified_at IS NULL)
            OR
            (email IS NOT NULL AND password_hash IS NOT NULL)
        ),
    ADD CONSTRAINT users_email_not_blank
        CHECK (email IS NULL OR length(btrim(email)) > 0),
    ADD CONSTRAINT users_password_hash_argon2id
        CHECK (
            password_hash IS NULL
            OR password_hash LIKE '$argon2id$%'
        );

CREATE UNIQUE INDEX users_email_unique
    ON public.users (email)
    WHERE email IS NOT NULL;

CREATE TABLE public.email_verification_tokens (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    user_id UUID NOT NULL
        REFERENCES public.users(id)
        ON DELETE CASCADE,

    token_hash TEXT NOT NULL UNIQUE,

    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    expires_at TIMESTAMPTZ NOT NULL,
    consumed_at TIMESTAMPTZ,

    CONSTRAINT email_verification_token_hash_format
        CHECK (token_hash ~ '^[0-9a-f]{64}$'),

    CONSTRAINT email_verification_expiry_valid
        CHECK (expires_at > created_at),

    CONSTRAINT email_verification_consumption_valid
        CHECK (consumed_at IS NULL OR consumed_at >= created_at)
);

CREATE INDEX email_verification_tokens_user_id
    ON public.email_verification_tokens (user_id);

-- Verification-token access is available only through the controlled
-- SECURITY DEFINER functions below, not direct application table access.
REVOKE ALL PRIVILEGES
    ON TABLE public.email_verification_tokens
    FROM PUBLIC, eldorado_app;

ALTER TABLE public.email_verification_tokens
    ENABLE ROW LEVEL SECURITY;

ALTER TABLE public.email_verification_tokens
    FORCE ROW LEVEL SECURITY;

CREATE POLICY email_verification_tokens_user_isolation
    ON public.email_verification_tokens
    USING (user_id = public.current_app_user_id())
    WITH CHECK (user_id = public.current_app_user_id());

-- Create a pending account and its verification token atomically.
-- The database generates the user ID and fixes the token lifetime at 30 minutes.
CREATE OR REPLACE FUNCTION public.create_pending_email_account(
    p_email TEXT,
    p_password_hash TEXT,
    p_token_hash TEXT
)
RETURNS UUID
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
    normalized_email TEXT;
    new_user_id UUID;
    now_at TIMESTAMPTZ := clock_timestamp();
BEGIN
    IF p_email IS NULL OR btrim(p_email) = '' THEN
        RAISE EXCEPTION USING
            ERRCODE = '22023',
            MESSAGE = 'Invalid registration input';
    END IF;

    normalized_email := lower(btrim(p_email));

    IF p_password_hash IS NULL
       OR p_password_hash NOT LIKE '$argon2id$%'
       OR p_token_hash IS NULL
       OR p_token_hash !~ '^[0-9a-f]{64}$' THEN
        RAISE EXCEPTION USING
            ERRCODE = '22023',
            MESSAGE = 'Invalid registration input';
    END IF;

    INSERT INTO public.users (
        email,
        password_hash,
        email_verified_at,
        is_active
    )
    VALUES (
        normalized_email,
        p_password_hash,
        NULL,
        TRUE
    )
    RETURNING id INTO new_user_id;

    INSERT INTO public.email_verification_tokens (
        user_id,
        token_hash,
        created_at,
        expires_at
    )
    VALUES (
        new_user_id,
        p_token_hash,
        now_at,
        now_at + INTERVAL '30 minutes'
    );

    RETURN new_user_id;
END;
$$;

ALTER FUNCTION public.create_pending_email_account(TEXT, TEXT, TEXT)
    OWNER TO postgres;

REVOKE ALL
ON FUNCTION public.create_pending_email_account(TEXT, TEXT, TEXT)
FROM PUBLIC;

GRANT EXECUTE
ON FUNCTION public.create_pending_email_account(TEXT, TEXT, TEXT)
TO eldorado_app;

-- Atomically consume a valid verification token and verify its account.
-- Unknown, expired, already-used, or otherwise invalid tokens return INVALID.
CREATE OR REPLACE FUNCTION public.verify_email_token(
    p_token_hash TEXT
)
RETURNS TEXT
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
    token_row public.email_verification_tokens%ROWTYPE;
    verified_user_id UUID;
BEGIN
    IF p_token_hash IS NULL
       OR p_token_hash !~ '^[0-9a-f]{64}$' THEN
        RETURN 'INVALID';
    END IF;

    SELECT token.*
    INTO token_row
    FROM public.email_verification_tokens AS token
    WHERE token.token_hash = p_token_hash
    FOR UPDATE;

    IF NOT FOUND
       OR token_row.consumed_at IS NOT NULL
       OR token_row.expires_at <= clock_timestamp() THEN
        RETURN 'INVALID';
    END IF;

    UPDATE public.users AS account
    SET email_verified_at = clock_timestamp(),
        updated_at = clock_timestamp()
    WHERE account.id = token_row.user_id
      AND account.email IS NOT NULL
      AND account.email_verified_at IS NULL
      AND account.is_active = TRUE
    RETURNING account.id INTO verified_user_id;

    IF NOT FOUND THEN
        RETURN 'INVALID';
    END IF;

    UPDATE public.email_verification_tokens
    SET consumed_at = clock_timestamp()
    WHERE id = token_row.id
      AND consumed_at IS NULL;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'Verification token consumption failed';
    END IF;

    RETURN 'VERIFIED';
END;
$$;

ALTER FUNCTION public.verify_email_token(TEXT)
    OWNER TO postgres;

REVOKE ALL
ON FUNCTION public.verify_email_token(TEXT)
FROM PUBLIC;

GRANT EXECUTE
ON FUNCTION public.verify_email_token(TEXT)
TO eldorado_app;

COMMIT;
