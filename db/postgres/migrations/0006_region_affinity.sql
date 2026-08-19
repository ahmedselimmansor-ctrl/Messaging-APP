-- 0006: give every chat a home region.
--
-- Sequence allocation must have a single writer per chat. Sequences come from
-- a Redis INCR and ordering comes from one Kafka partition; both are regional.
-- Two regions allocating for one chat would mint duplicate sequence numbers
-- and silently overwrite history — the worst failure this system has.
--
-- So a chat is pinned to the region that created it, and a send from
-- elsewhere is proxied there. This column is what records that.

BEGIN;

-- Empty for existing rows, which the application reads as "local". That is
-- correct for a single-region deployment and correct for every chat that
-- existed before a second region was added, because those chats were all
-- created in the original one.
ALTER TABLE chats ADD COLUMN IF NOT EXISTS home_region text NOT NULL DEFAULT '';

-- Backfill explicitly rather than relying on the empty-means-local reading,
-- so the column says what it means once a second region exists.
--
-- Set this to the region the cluster ran in before the migration.
UPDATE chats SET home_region = 'europe-west1' WHERE home_region = '';

-- Chats are never rehomed: moving one would mean migrating its sequence
-- counter atomically between two Redis clusters while messages are in flight,
-- which cannot be done safely. A chat in the wrong region is a chat that pays
-- one extra round trip, which is a far smaller problem.
COMMENT ON COLUMN chats.home_region IS
    'The region that allocates this chat''s sequence numbers. Fixed at creation; never updated.';

-- Operational: how many chats each region owns, for capacity planning.
CREATE INDEX IF NOT EXISTS chats_home_region_idx
    ON chats (home_region) WHERE deleted_at IS NULL;

COMMIT;
