-- Eldorado-AI
-- Migration 0011: Resend email verification
--
-- Security:
--   * Existing migrations remain immutable.
--   * Only an active, unverified account can receive a new token.
--   * The account row is locked first, so concurrent resends serialize.
--   * A 60 second cooldown limits email bombing independent of rate limits.
--   * Older unconsumed tokens are invalidated (consumed_at) when a new
--     token is issued, so only the newest link works.
--   * Execution is revoked from PUBLIC and granted to eldorado_app.

BEGIN;

CREATE FUNCTION public.issue_email_verification_token(
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
            MESSAGE = 'Invalid verification input';
    END IF;

    normalized_email := lower(btrim(p_email));

    SELECT account.id
    INTO target_user_id
    FROM public.users AS account
    WHERE account.email = normalized_email
      AND account.email_verified_at IS NULL
      AND account.is_active = TRUE
    FOR UPDATE;

    IF NOT FOUND THEN
        RETURN FALSE;
    END IF;

    SELECT max(token.created_at)
    INTO latest_created
    FROM public.email_verification_tokens AS token
    WHERE token.user_id = target_user_id;

    IF latest_created IS NOT NULL
       AND latest_created > now_at - INTERVAL '60 seconds' THEN
        RETURN FALSE;
    END IF;

    UPDATE public.email_verification_tokens AS token
    SET consumed_at = now_at
    WHERE token.user_id = target_user_id
      AND token.consumed_at IS NULL;

    INSERT INTO public.email_verification_tokens (
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

ALTER FUNCTION public.issue_email_verification_token(TEXT, TEXT)
    OWNER TO postgres;

REVOKE ALL
ON FUNCTION public.issue_email_verification_token(TEXT, TEXT)
FROM PUBLIC;

GRANT EXECUTE
ON FUNCTION public.issue_email_verification_token(TEXT, TEXT)
TO eldorado_app;

COMMIT;