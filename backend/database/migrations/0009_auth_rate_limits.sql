-- Eldorado-AI
-- Migration 0009: Persistent fixed-window rate limiting
--
-- Security:
--   * Existing migrations remain immutable.
--   * Keys are stored only as SHA-256 hex hashes.
--   * The application role has no direct table access.
--   * Counting is a single atomic upsert, safe under concurrency.
--   * The application role may execute check_rate_limit only.
--   * Purging is not granted to the application role.

BEGIN;

CREATE TABLE public.auth_rate_limits (
    bucket TEXT NOT NULL,
    key_hash TEXT NOT NULL,
    window_start TIMESTAMPTZ NOT NULL,
    attempts INTEGER NOT NULL,

    PRIMARY KEY (bucket, key_hash, window_start),

    CONSTRAINT auth_rate_limits_bucket_format
        CHECK (bucket ~ '^[a-z_]{1,32}$'),

    CONSTRAINT auth_rate_limits_key_hash_format
        CHECK (key_hash ~ '^[0-9a-f]{64}$'),

    CONSTRAINT auth_rate_limits_attempts_positive
        CHECK (attempts > 0)
);

CREATE INDEX auth_rate_limits_window_start
    ON public.auth_rate_limits (window_start);

REVOKE ALL PRIVILEGES
    ON TABLE public.auth_rate_limits
    FROM PUBLIC, eldorado_app;

-- Record one attempt and report whether it is within the limit.
-- TRUE = allowed, FALSE = limit exceeded for the current window.
CREATE FUNCTION public.check_rate_limit(
    p_bucket TEXT,
    p_key_hash TEXT,
    p_limit INTEGER,
    p_window_seconds INTEGER
)
RETURNS BOOLEAN
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
    current_window TIMESTAMPTZ;
    current_attempts INTEGER;
BEGIN
    IF p_bucket IS NULL OR p_bucket !~ '^[a-z_]{1,32}$'
       OR p_key_hash IS NULL OR p_key_hash !~ '^[0-9a-f]{64}$'
       OR p_limit IS NULL OR p_limit < 1 OR p_limit > 100000
       OR p_window_seconds IS NULL
       OR p_window_seconds < 1 OR p_window_seconds > 86400 THEN
        RAISE EXCEPTION USING
            ERRCODE = '22023',
            MESSAGE = 'Invalid rate limit input';
    END IF;

    current_window := to_timestamp(
        (floor(
            extract(epoch FROM clock_timestamp())::double precision
            / p_window_seconds
        ) * p_window_seconds)::double precision
    );

    INSERT INTO public.auth_rate_limits AS limits (
        bucket,
        key_hash,
        window_start,
        attempts
    )
    VALUES (
        p_bucket,
        p_key_hash,
        current_window,
        1
    )
    ON CONFLICT (bucket, key_hash, window_start)
    DO UPDATE SET attempts = limits.attempts + 1
    RETURNING limits.attempts INTO current_attempts;

    RETURN current_attempts <= p_limit;
END;
$$;

ALTER FUNCTION public.check_rate_limit(TEXT, TEXT, INTEGER, INTEGER)
    OWNER TO postgres;

REVOKE ALL
ON FUNCTION public.check_rate_limit(TEXT, TEXT, INTEGER, INTEGER)
FROM PUBLIC;

GRANT EXECUTE
ON FUNCTION public.check_rate_limit(TEXT, TEXT, INTEGER, INTEGER)
TO eldorado_app;

-- Maintenance only: remove windows that ended at least p_min_age_seconds ago.
-- Not granted to the application role.
CREATE FUNCTION public.purge_expired_rate_limits(
    p_min_age_seconds INTEGER DEFAULT 172800
)
RETURNS BIGINT
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
    removed BIGINT;
BEGIN
    IF p_min_age_seconds IS NULL OR p_min_age_seconds < 86400 THEN
        RAISE EXCEPTION USING
            ERRCODE = '22023',
            MESSAGE = 'Invalid purge age';
    END IF;

    DELETE FROM public.auth_rate_limits
    WHERE window_start < clock_timestamp()
        - make_interval(secs => p_min_age_seconds);

    GET DIAGNOSTICS removed = ROW_COUNT;

    RETURN removed;
END;
$$;

ALTER FUNCTION public.purge_expired_rate_limits(INTEGER)
    OWNER TO postgres;

REVOKE ALL
ON FUNCTION public.purge_expired_rate_limits(INTEGER)
FROM PUBLIC;

COMMIT;