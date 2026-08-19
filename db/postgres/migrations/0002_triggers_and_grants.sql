-- 0002: maintenance triggers, autovacuum tuning and least-privilege grants.

BEGIN;

-- ---------------------------------------------------------------------------
-- updated_at maintenance
-- ---------------------------------------------------------------------------
--
-- Doing this in a trigger rather than in every UPDATE statement means a
-- forgotten SET updated_at cannot silently produce a stale timestamp — and
-- the chat list orders on it, so a stale one is user-visible.
CREATE OR REPLACE FUNCTION touch_updated_at() RETURNS trigger AS $$
BEGIN
    NEW.updated_at = now();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS users_touch_updated_at ON users;
CREATE TRIGGER users_touch_updated_at
    BEFORE UPDATE ON users
    FOR EACH ROW EXECUTE FUNCTION touch_updated_at();

DROP TRIGGER IF EXISTS chats_touch_updated_at ON chats;
CREATE TRIGGER chats_touch_updated_at
    BEFORE UPDATE ON chats
    FOR EACH ROW EXECUTE FUNCTION touch_updated_at();

-- ---------------------------------------------------------------------------
-- Autovacuum tuning
-- ---------------------------------------------------------------------------
--
-- chat_sequences is updated once per message across the whole platform, which
-- makes it the highest-churn table by an order of magnitude. The default
-- autovacuum threshold (20% of the table) would let it bloat badly before a
-- vacuum triggered, and it is a small table where a vacuum is cheap — so
-- vacuum it aggressively.
ALTER TABLE chat_sequences SET (
    autovacuum_vacuum_scale_factor = 0.02,
    autovacuum_analyze_scale_factor = 0.02,
    autovacuum_vacuum_cost_delay = 0
);

-- chat_members sees a write per read receipt, which is frequent but far less
-- so than chat_sequences.
ALTER TABLE chat_members SET (
    autovacuum_vacuum_scale_factor = 0.05,
    autovacuum_analyze_scale_factor = 0.05
);

-- otp_challenges is insert-then-delete: the purge job removes whole days at a
-- time, leaving large dead tuple counts behind.
ALTER TABLE otp_challenges SET (
    autovacuum_vacuum_scale_factor = 0.05
);

-- ---------------------------------------------------------------------------
-- Least-privilege roles
-- ---------------------------------------------------------------------------
--
-- One role per service, each with only the access it needs. This is what makes
-- a compromised media service unable to read the phone-number column, and it
-- is why the roles are created here rather than everything sharing one
-- superuser DSN.
--
-- Passwords are not set here: on Cloud SQL these roles authenticate through
-- IAM database authentication, so there is no password to leak or rotate.

DO $$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'svc_auth') THEN
        CREATE ROLE svc_auth NOLOGIN;
    END IF;
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'svc_chat') THEN
        CREATE ROLE svc_chat NOLOGIN;
    END IF;
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'svc_push') THEN
        CREATE ROLE svc_push NOLOGIN;
    END IF;
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'svc_readonly') THEN
        CREATE ROLE svc_readonly NOLOGIN;
    END IF;
END $$;

-- auth-service owns accounts and sessions.
GRANT SELECT, INSERT, UPDATE ON users, devices, otp_challenges TO svc_auth;
GRANT SELECT ON chats, chat_members TO svc_auth;

-- chat-service owns conversations and membership.
GRANT SELECT, INSERT, UPDATE ON chats, chat_members, chat_sequences TO svc_chat;
GRANT SELECT ON users TO svc_chat;
GRANT SELECT, INSERT, DELETE ON contacts, blocklist TO svc_chat;

-- The push path only ever reads, and it must not be able to read phone
-- numbers or OTP hashes at all.
GRANT SELECT (id, user_id, push_token, platform, revoked_at) ON devices TO svc_push;
GRANT UPDATE (push_token) ON devices TO svc_push;
GRANT SELECT (chat_id, user_id, muted_until, left_at) ON chat_members TO svc_push;
GRANT SELECT (id, display_name) ON users TO svc_push;
GRANT SELECT (id, chat_type, title) ON chats TO svc_push;
GRANT SELECT, INSERT, UPDATE ON chat_sequences TO svc_push;

-- Analytics and debugging: everything except the columns that identify a
-- person or authenticate them.
GRANT SELECT (id, username, display_name, lang_code, banned, created_at, deleted_at)
    ON users TO svc_readonly;
GRANT SELECT ON chats, chat_members, chat_sequences TO svc_readonly;

COMMIT;
