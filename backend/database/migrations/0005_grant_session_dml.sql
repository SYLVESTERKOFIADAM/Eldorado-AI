-- Eldorado-AI
-- Migration 0005: Grant application DML access to session tables
--
-- Security:
--   - eldorado_app receives only required DML privileges.
--   - Ownership remains with postgres.
--   - RLS remains the row-level authorization boundary.
--   - No schema CREATE privilege is granted.

BEGIN;

GRANT SELECT, INSERT, UPDATE, DELETE
ON sessions
TO eldorado_app;

GRANT SELECT, INSERT, UPDATE, DELETE
ON refresh_tokens
TO eldorado_app;

COMMIT;
