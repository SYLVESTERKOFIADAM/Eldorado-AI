-- Eldorado-AI
-- Migration 0013: Database-enforced single-owner account
--
-- Security:
--   * Existing migrations remain immutable.
--   * At most one owner can exist (unique partial index on is_owner).
--   * An owner must have an email, so the owner is always login-capable.
--   * bootstrap_owner_account creates the owner atomically under an
--     advisory lock and refuses if any email account already exists.
--     It is not executable by PUBLIC or by the application role.
--   * Once an owner exists, a trigger refuses every new email account,
--     whichever role or function inserts it.
--   * The application role loses direct write access to public.users.
--     SELECT is left unchanged.
--   * The migration fails if more than one login-capable account exists,
--     so the single owner is never chosen arbitrarily.

BEGIN;

ALTER TABLE public.users
    ADD COLUMN is_owner BOOLEAN NOT NULL DEFAULT FALSE;

DO $$
DECLARE
    login_capable INTEGER;
BEGIN
    SELECT count(*)
    INTO login_capable
    FROM public.users
    WHERE email IS NOT NULL;

    IF login_capable > 1 THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'Cannot enforce a single owner: more than one login-capable account exists';
    END IF;

    UPDATE public.users
    SET is_owner = TRUE
    WHERE email IS NOT NULL;
END;
$$;

ALTER TABLE public.users
    ADD CONSTRAINT users_owner_requires_email
        CHECK (NOT is_owner OR email IS NOT NULL);

CREATE UNIQUE INDEX users_single_owner
    ON public.users (is_owner)
    WHERE is_owner;

-- Refuse new email accounts once an owner exists. Runs as the function
-- owner so it can see the owner row despite row level security.
CREATE FUNCTION public.guard_single_owner_account()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
BEGIN
    IF NEW.email IS NULL OR NEW.is_owner THEN
        RETURN NEW;
    END IF;

    PERFORM pg_catalog.pg_advisory_xact_lock(81472933);

    IF EXISTS (SELECT 1 FROM public.users WHERE is_owner) THEN
        RAISE EXCEPTION USING
            ERRCODE = '42501',
            MESSAGE = 'Account creation is closed';
    END IF;

    RETURN NEW;
END;
$$;

ALTER FUNCTION public.guard_single_owner_account()
    OWNER TO postgres;

REVOKE ALL
ON FUNCTION public.guard_single_owner_account()
FROM PUBLIC, eldorado_app;

CREATE TRIGGER users_guard_single_owner
    BEFORE INSERT ON public.users
    FOR EACH ROW
    EXECUTE FUNCTION public.guard_single_owner_account();

-- Create the verified owner. Refuses if any email account exists.
CREATE FUNCTION public.bootstrap_owner_account(
    p_email TEXT,
    p_password_hash TEXT
)
RETURNS UUID
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
    normalized_email TEXT;
    new_user_id UUID;
BEGIN
    IF p_email IS NULL
       OR btrim(p_email) = ''
       OR p_password_hash IS NULL
       OR p_password_hash NOT LIKE '$argon2id$%' THEN
        RAISE EXCEPTION USING
            ERRCODE = '22023',
            MESSAGE = 'Invalid owner input';
    END IF;

    normalized_email := lower(btrim(p_email));

    PERFORM pg_catalog.pg_advisory_xact_lock(81472933);

    IF EXISTS (SELECT 1 FROM public.users WHERE email IS NOT NULL) THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'An account already exists; owner bootstrap refused';
    END IF;

    INSERT INTO public.users (
        email,
        password_hash,
        email_verified_at,
        is_active,
        is_owner
    )
    VALUES (
        normalized_email,
        p_password_hash,
        clock_timestamp(),
        TRUE,
        TRUE
    )
    RETURNING id INTO new_user_id;

    RETURN new_user_id;
END;
$$;

ALTER FUNCTION public.bootstrap_owner_account(TEXT, TEXT)
    OWNER TO postgres;

REVOKE ALL
ON FUNCTION public.bootstrap_owner_account(TEXT, TEXT)
FROM PUBLIC, eldorado_app;

-- The application role must not write users directly. Account changes go
-- through the SECURITY DEFINER functions.
REVOKE INSERT, UPDATE, DELETE, TRUNCATE, REFERENCES, TRIGGER
    ON TABLE public.users
    FROM PUBLIC, eldorado_app;

COMMIT;