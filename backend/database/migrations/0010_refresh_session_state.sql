-- Eldorado-AI
-- Migration 0010: Narrow session-state lookup for refresh rotation
--
-- Security:
--   * Existing migrations remain immutable.
--   * The application role gets no direct access to the users table.
--   * Only expires_at and is_active are exposed, and only for a session
--     owned by the transaction's authenticated user.
--   * Execution is revoked from PUBLIC and granted to eldorado_app.

BEGIN;

CREATE FUNCTION public.get_refresh_session_state(
    p_session_id UUID
)
RETURNS TABLE (
    out_expires_at TIMESTAMPTZ,
    out_is_active BOOLEAN
)
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
    SELECT s.expires_at, u.is_active
    FROM public.sessions AS s
    INNER JOIN public.users AS u
        ON u.id = s.user_id
    WHERE s.id = p_session_id
      AND s.user_id = public.current_app_user_id();
$$;

ALTER FUNCTION public.get_refresh_session_state(UUID)
    OWNER TO postgres;

REVOKE ALL
ON FUNCTION public.get_refresh_session_state(UUID)
FROM PUBLIC;

GRANT EXECUTE
ON FUNCTION public.get_refresh_session_state(UUID)
TO eldorado_app;

COMMIT;