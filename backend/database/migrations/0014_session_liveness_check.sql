-- Eldorado-AI
-- Migration 0014: Per-request session liveness check
--
-- Security:
--   * Existing migrations remain immutable.
--   * Lets the API confirm that the session behind a verified access token
--     is still usable, so logout, password change and refresh-family
--     revocation take effect immediately instead of when the token expires.
--   * Both ids come from the verified token. No app.current_user_id is
--     needed, and a session id paired with someone else's user id is false.
--   * The answer is only TRUE or FALSE: unknown, foreign, revoked, expired
--     and inactive-user cases are indistinguishable to the caller.
--   * The application role gets no table access. Execution is revoked from
--     PUBLIC and granted to eldorado_app only.

BEGIN;

CREATE FUNCTION public.is_session_active(
    p_session_id UUID,
    p_user_id UUID
)
RETURNS BOOLEAN
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
    SELECT COALESCE(
        (
            SELECT TRUE
            FROM public.sessions AS s
            INNER JOIN public.users AS u
                ON u.id = s.user_id
            WHERE s.id = p_session_id
              AND s.user_id = p_user_id
              AND s.revoked_at IS NULL
              AND s.expires_at > clock_timestamp()
              AND u.is_active = TRUE
        ),
        FALSE
    );
$$;

ALTER FUNCTION public.is_session_active(UUID, UUID)
    OWNER TO postgres;

REVOKE ALL
ON FUNCTION public.is_session_active(UUID, UUID)
FROM PUBLIC;

GRANT EXECUTE
ON FUNCTION public.is_session_active(UUID, UUID)
TO eldorado_app;

COMMIT;