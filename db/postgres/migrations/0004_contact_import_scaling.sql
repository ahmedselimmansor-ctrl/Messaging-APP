-- 0004: make contact import scale past a small user table.
--
-- Migration 0003 computes the phone HMAC inside the query, which keeps pepper
-- rotation free but makes import a sequential scan. That is fine at ten
-- thousand users and unacceptable at ten million: it is the one endpoint a
-- client calls with hundreds of values at once.
--
-- The fix is a functional index on the HMAC. It pins the pepper into the
-- index definition, so rotating the pepper now requires rebuilding this index
-- — a real cost, and the honest trade for a query that stays fast.
--
-- Apply this only once the pepper is stable, and set it from the same value
-- the auth service reads from CONTACT_PEPPER.

BEGIN;

-- Rotation procedure, for when it is needed:
--
--   1. CREATE INDEX CONCURRENTLY users_phone_hash_new_idx ON users
--        (translate(encode(hmac(phone, '<new-pepper>', 'sha256'), 'base64'), '+/=', '-_'));
--   2. Deploy the auth service with the new CONTACT_PEPPER.
--   3. DROP INDEX CONCURRENTLY users_phone_hash_idx;
--   4. ALTER INDEX users_phone_hash_new_idx RENAME TO users_phone_hash_idx;
--
-- Both indexes exist during steps 1-3, so imports keep working throughout.
--
-- The pepper below is the development placeholder. Replace it before applying
-- to any environment that matters; scripts/render-env.sh prints the value.
CREATE INDEX IF NOT EXISTS users_phone_hash_idx
    ON users (
        translate(encode(hmac(phone, 'local-development-pepper', 'sha256'), 'base64'), '+/=', '-_')
    )
    WHERE deleted_at IS NULL AND banned = false;

COMMIT;
