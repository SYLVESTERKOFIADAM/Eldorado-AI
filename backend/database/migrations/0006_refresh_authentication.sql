BEGIN;

-- ============================================================================
-- MIGRATION 0006
-- SECURITY-DEFINER FUNCTION
--
-- Purpose:
--   Authenticate a presented refresh-token hash before the application has
--   an authenticated user identity available for normal RLS transactions.
--
-- Security requirements:
--   * Function executes with the privileges of its owner (postgres).
--   * search_path is fixed to trusted schemas.
--   * Security-sensitive relations are fully schema-qualified.
--   * No dynamic SQL.
--   * No caller-supplied user ID.
--   * No mutation other than row locking.
--   * Authentication state is collapsed to VALID / REPLAY / INVALID.
--   * PUBLIC execution is explicitly revoked.
--   * eldorado_app receives EXECUTE only.
--
-- Lock-order invariant:
--   Any operation that needs both a refresh-token row and its session row
--   must acquire the refresh-token lock before the session lock.
--
-- The function intentionally does NOT:
--   * set app.current_user_id;
--   * issue access tokens;
--   * issue replacement refresh tokens;
--   * consume refresh tokens;
--   * revoke sessions;
--   * revoke token families.
--
-- Those responsibilities remain in the application transaction/service
-- boundary after trusted identity has been established.
-- ============================================================================

CREATE OR REPLACE FUNCTION public.authenticate_and_lock_refresh_credential(
    presented_token_hash TEXT
)
RETURNS TABLE (
    authentication_state TEXT,
    user_id UUID,
    session_id UUID,
    token_family_id UUID,
    refresh_token_id UUID
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
    refresh_row public.refresh_tokens%ROWTYPE;
    session_row public.sessions%ROWTYPE;
BEGIN
    /*
     * Blank credentials are rejected without querying the database.
     * The caller receives the same INVALID state as an unknown credential.
     */
    IF presented_token_hash IS NULL
       OR btrim(presented_token_hash) = '' THEN
        authentication_state := 'INVALID';
        user_id := NULL;
        session_id := NULL;
        token_family_id := NULL;
        refresh_token_id := NULL;
        RETURN NEXT;
        RETURN;
    END IF;

    /*
     * LOCK ORDER: 1 of 2
     *
     * Lock the refresh-token row first.
     *
     * This is intentionally a separate statement from the session lock.
     * The refresh-token lock remains held until the surrounding transaction
     * commits or rolls back.
     */
    SELECT rt.*
    INTO refresh_row
    FROM public.refresh_tokens AS rt
    WHERE rt.token_hash = presented_token_hash
    FOR UPDATE;

    /*
     * Unknown credentials are deliberately indistinguishable from other
     * invalid credentials.
     */
    IF NOT FOUND THEN
        authentication_state := 'INVALID';
        user_id := NULL;
        session_id := NULL;
        token_family_id := NULL;
        refresh_token_id := NULL;
        RETURN NEXT;
        RETURN;
    END IF;

    /*
     * LOCK ORDER: 2 of 2
     *
     * Lock the owning session only after the refresh-token row has been
     * locked. All future operations that need both rows must preserve this
     * ordering.
     */
    SELECT s.*
    INTO session_row
    FROM public.sessions AS s
    WHERE s.id = refresh_row.session_id
    FOR UPDATE;

    /*
     * A refresh token without its owning session should never exist because
     * of the foreign-key constraint. Fail closed if database state is ever
     * inconsistent.
     */
    IF NOT FOUND THEN
        authentication_state := 'INVALID';
        user_id := NULL;
        session_id := NULL;
        token_family_id := NULL;
        refresh_token_id := NULL;
        RETURN NEXT;
        RETURN;
    END IF;

    /*
     * A previously consumed token is materially different from every other
     * authentication failure: it indicates possible refresh-token replay.
     *
     * Do not expose expiry/revocation/unknown distinctions to the caller.
     */
    IF refresh_row.consumed_at IS NOT NULL THEN
        authentication_state := 'REPLAY';
        user_id := session_row.user_id;
        session_id := session_row.id;
        token_family_id := session_row.token_family_id;
        refresh_token_id := refresh_row.id;
        RETURN NEXT;
        RETURN;
    END IF;

    /*
     * Expired refresh tokens and invalid session state collapse to INVALID.
     *
     * These checks happen while both rows are locked, preventing the
     * authentication decision from being made against an independently
     * changing lifecycle state.
     */
    IF refresh_row.expires_at <= clock_timestamp()
       OR session_row.expires_at <= clock_timestamp()
       OR session_row.revoked_at IS NOT NULL THEN
        authentication_state := 'INVALID';
        user_id := NULL;
        session_id := NULL;
        token_family_id := NULL;
        refresh_token_id := NULL;
        RETURN NEXT;
        RETURN;
    END IF;

    /*
     * VALID is the only successful authentication result.
     *
     * user_id originates from the trusted database row, never from the
     * presented credential or caller input.
     */
    authentication_state := 'VALID';
    user_id := session_row.user_id;
    session_id := session_row.id;
    token_family_id := session_row.token_family_id;
    refresh_token_id := refresh_row.id;

    RETURN NEXT;
END;
$$;

ALTER FUNCTION public.authenticate_and_lock_refresh_credential(TEXT)
    OWNER TO postgres;

REVOKE ALL
ON FUNCTION public.authenticate_and_lock_refresh_credential(TEXT)
FROM PUBLIC;

GRANT EXECUTE
ON FUNCTION public.authenticate_and_lock_refresh_credential(TEXT)
TO eldorado_app;

COMMIT;
