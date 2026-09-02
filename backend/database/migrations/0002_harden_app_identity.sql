-- Eldorado-AI
-- Migration 0002: Harden application identity handling
--
-- Security principles:
--   1. Invalid or missing application identity must fail closed.
--   2. Application identity is transaction-local.
--   3. RLS must never directly cast untrusted session text to UUID.
--   4. Database superusers remain outside the application trust boundary.

BEGIN;

CREATE OR REPLACE FUNCTION public.current_app_user_id()
RETURNS uuid
LANGUAGE plpgsql
STABLE
AS $$
DECLARE
    raw_id TEXT;
BEGIN
    raw_id := NULLIF(
        current_setting('app.current_user_id', true),
        ''
    );

    IF raw_id IS NULL THEN
        RETURN NULL;
    END IF;

    BEGIN
        RETURN raw_id::UUID;
    EXCEPTION
        WHEN invalid_text_representation THEN
            RETURN NULL;
    END;
END;
$$;

DROP POLICY IF EXISTS users_isolation_policy ON users;
DROP POLICY IF EXISTS memories_isolation_policy ON memories;

CREATE POLICY users_isolation_policy
    ON users
    USING (
        id = public.current_app_user_id()
    )
    WITH CHECK (
        id = public.current_app_user_id()
    );

CREATE POLICY memories_isolation_policy
    ON memories
    USING (
        user_id = public.current_app_user_id()
    )
    WITH CHECK (
        user_id = public.current_app_user_id()
    );

COMMIT;