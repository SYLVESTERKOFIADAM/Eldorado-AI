-- Eldorado-AI
-- Migration 0008: Verified-only login lookup and function hardening
--
-- Security:
--   * Existing migrations remain immutable.
--   * Login credentials are returned only for verified, active accounts.
--   * Unknown, unverified and inactive accounts are indistinguishable (no row).
--   * search_path excludes public for the 0007 SECURITY DEFINER functions.

BEGIN;

CREATE FUNCTION public.get_login_credential(
    p_email TEXT
)
RETURNS TABLE (
    out_user_id UUID,
    out_password_hash TEXT
)
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
    SELECT account.id, account.password_hash
    FROM public.users AS account
    WHERE account.email = lower(btrim(p_email))
      AND account.password_hash IS NOT NULL
      AND account.email_verified_at IS NOT NULL
      AND account.is_active = TRUE;
$$;

ALTER FUNCTION public.get_login_credential(TEXT)
    OWNER TO postgres;

REVOKE ALL
ON FUNCTION public.get_login_credential(TEXT)
FROM PUBLIC;

GRANT EXECUTE
ON FUNCTION public.get_login_credential(TEXT)
TO eldorado_app;

ALTER FUNCTION public.create_pending_email_account(TEXT, TEXT, TEXT)
    SET search_path = pg_catalog, pg_temp;

ALTER FUNCTION public.verify_email_token(TEXT)
    SET search_path = pg_catalog, pg_temp;

COMMIT;