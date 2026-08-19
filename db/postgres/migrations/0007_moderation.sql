-- 0007: reports and account bans.
--
-- Two things were missing. Users had no way to report abuse, and the `banned`
-- column added in 0001 was never enforced anywhere — a banned account could
-- still sign in and still send. This migration adds the storage for the first
-- and the context needed to make the second reviewable.
--
-- The design principle: a ban is an administrative action taken against a
-- person, so it must record who did it, when, and why. A boolean alone cannot
-- answer "why is this account banned?" six months later, which is exactly when
-- the question gets asked.

BEGIN;

-- ---------------------------------------------------------------------------
-- Ban context
-- ---------------------------------------------------------------------------

ALTER TABLE users ADD COLUMN IF NOT EXISTS banned_at     timestamptz;
ALTER TABLE users ADD COLUMN IF NOT EXISTS banned_reason text;
-- The operator who did it. Not a foreign key to users: operators are staff
-- identities from the admin service, not accounts on the platform, and a
-- foreign key here would either force staff to have user rows or break.
ALTER TABLE users ADD COLUMN IF NOT EXISTS banned_by     text;

-- `banned` and `banned_at` must agree. Without this, code that checks one and
-- code that checks the other can disagree about whether an account is banned,
-- and the disagreement surfaces as an account that cannot log in but appears
-- active in every admin view.
ALTER TABLE users DROP CONSTRAINT IF EXISTS users_ban_consistent;
ALTER TABLE users ADD CONSTRAINT users_ban_consistent
    CHECK ((banned = false AND banned_at IS NULL)
        OR (banned = true  AND banned_at IS NOT NULL));

-- ---------------------------------------------------------------------------
-- Reports
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS reports (
    id             bigint PRIMARY KEY,

    -- Who reported. ON DELETE CASCADE: if a reporter deletes their account the
    -- report goes with it, because it was their statement to make.
    reporter_id    bigint      NOT NULL REFERENCES users (id) ON DELETE CASCADE,

    -- What was reported. A report always names a user — the subject — and
    -- optionally the specific message that prompted it.
    subject_id     bigint      NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    chat_id        bigint      REFERENCES chats (id) ON DELETE SET NULL,
    message_seq    bigint,

    reason         text        NOT NULL,
    -- The reporter's own words, capped. Free text from an untrusted party
    -- that staff will read, so it is length-bounded here and escaped on
    -- display.
    detail         text        NOT NULL DEFAULT '',

    state          text        NOT NULL DEFAULT 'open',

    -- Resolution.
    resolved_at    timestamptz,
    resolved_by    text,
    resolution     text,

    created_at     timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT reports_reason_valid CHECK (
        reason IN ('spam', 'abuse', 'violence', 'csam', 'illegal', 'impersonation', 'other')),
    CONSTRAINT reports_state_valid CHECK (
        state IN ('open', 'reviewing', 'actioned', 'dismissed')),
    CONSTRAINT reports_detail_length CHECK (char_length(detail) <= 2000),
    -- Reporting yourself is always a mistake or an attempt to pollute the
    -- queue.
    CONSTRAINT reports_not_self CHECK (reporter_id <> subject_id),
    -- A resolved report must say who resolved it. Otherwise the queue empties
    -- with no record of who made the decisions.
    CONSTRAINT reports_resolution_attributed CHECK (
        (state IN ('open', 'reviewing') AND resolved_at IS NULL)
     OR (state IN ('actioned', 'dismissed') AND resolved_at IS NOT NULL AND resolved_by IS NOT NULL))
);

-- The moderation queue: open reports, oldest first. Partial, because the
-- resolved ones are the overwhelming majority over time and are never read
-- this way.
CREATE INDEX IF NOT EXISTS reports_open_idx
    ON reports (created_at) WHERE state IN ('open', 'reviewing');

-- "Show me everything reported about this account" — the query a moderator
-- runs before deciding, and the one that turns ten separate reports into a
-- pattern.
CREATE INDEX IF NOT EXISTS reports_subject_idx
    ON reports (subject_id, created_at DESC);

-- Rate limiting and duplicate suppression: one open report per reporter per
-- subject. Without it, a coordinated group can bury an account in identical
-- reports, and the queue depth stops meaning anything.
CREATE UNIQUE INDEX IF NOT EXISTS reports_one_open_per_pair
    ON reports (reporter_id, subject_id) WHERE state IN ('open', 'reviewing');

-- ---------------------------------------------------------------------------
-- Grants
-- ---------------------------------------------------------------------------

-- The chat service files reports; it cannot read the queue or resolve
-- anything. A report is written by the platform on a user's behalf and read
-- only by staff.
GRANT INSERT ON reports TO svc_chat;
GRANT SELECT (id, reporter_id, subject_id, state) ON reports TO svc_chat;

-- The auth service must see whether an account is banned, to refuse it a
-- token. It does not get UPDATE on the ban columns: issuing tokens and
-- deciding who may have one are different jobs.
GRANT SELECT (id, banned, banned_at, banned_reason) ON users TO svc_auth;

-- ---------------------------------------------------------------------------
-- The admin role
-- ---------------------------------------------------------------------------
--
-- NOLOGIN and no password, exactly like the roles in 0002. On Cloud SQL these
-- authenticate through IAM database authentication — the Cloud SQL proxy runs
-- with --auto-iam-authn and the pod's Workload Identity is the credential — so
-- there is no password to leak, rotate, or leave in a migration.

DO $$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'svc_admin') THEN
        CREATE ROLE svc_admin NOLOGIN;
    END IF;
END $$;

GRANT SELECT, INSERT, UPDATE ON reports TO svc_admin;
GRANT SELECT ON chats, chat_members TO svc_admin;

-- Note the column lists. A moderator needs to identify an account and see its
-- state; they do not need its phone number, and `phone` is absent from both
-- grants below. The absence is what makes "moderators cannot see phone
-- numbers" a property of the database rather than a policy nobody can check.
--
-- There is no Cassandra grant at all for this role, and admin-service has no
-- Cassandra client, so message content is equally out of reach.
GRANT SELECT (id, username, display_name, about_text, avatar_object, lang_code,
              banned, banned_at, banned_reason, banned_by,
              created_at, updated_at, deleted_at) ON users TO svc_admin;
GRANT UPDATE (banned, banned_at, banned_reason, banned_by, updated_at) ON users TO svc_admin;

-- Devices, for "how many sessions does this account have" — without the push
-- token, which is a credential for sending to someone's phone.
GRANT SELECT (id, user_id, platform, app_version, device_model,
              created_at, last_seen_at, revoked_at) ON devices TO svc_admin;

-- The reporter's side of a report needs resolving to a display name in the
-- moderation UI, which the users grant above already covers.

COMMIT;
