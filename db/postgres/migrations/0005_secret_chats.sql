-- 0005: end-to-end encrypted conversations.
--
-- The important thing about this table is what it does not contain. There is
-- no key column and there never will be: the server relays two public
-- Diffie-Hellman values and stores a fingerprint it can compare but not
-- invert. Everything needed to read the messages exists only on the two
-- devices.
--
-- If a future migration adds a column that could hold key material, the
-- product has stopped being end-to-end encrypted and the documentation must
-- say so.

BEGIN;

CREATE TABLE IF NOT EXISTS secret_chats (
    id                    bigint PRIMARY KEY,

    -- The initiator. The asymmetry matters for exactly one thing: on a rekey
    -- the admin is the side that proposes.
    admin_id              bigint      NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    admin_device_id       bigint      NOT NULL,

    participant_id        bigint      NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    -- Null until the participant accepts from a specific device. A secret
    -- chat is between two *devices*, not two accounts: the key never leaves
    -- the device that derived it, so a second device of the same user cannot
    -- read the conversation.
    participant_device_id bigint      NOT NULL DEFAULT 0,

    state                 text        NOT NULL DEFAULT 'requested',

    -- Public Diffie-Hellman values, base64. A passive observer of any DH
    -- exchange sees these.
    g_a                   text        NOT NULL DEFAULT '',
    g_b                   text        NOT NULL DEFAULT '',

    -- A hash of the derived key, so each side can confirm the other reached
    -- the same one. Not the key.
    key_fingerprint       bigint      NOT NULL DEFAULT 0,

    -- The self-destruct timer, enforced by the clients. The server stores it
    -- so the setting survives a reinstall; it cannot enforce it, because it
    -- cannot read the messages.
    ttl_seconds           integer     NOT NULL DEFAULT 0,

    created_at            timestamptz NOT NULL DEFAULT now(),
    ready_at              timestamptz,
    discarded_at          timestamptz,

    CONSTRAINT secret_chats_state_valid
        CHECK (state IN ('requested', 'ready', 'discarded')),
    CONSTRAINT secret_chats_distinct_parties
        CHECK (admin_id <> participant_id),
    CONSTRAINT secret_chats_ttl_sane
        CHECK (ttl_seconds >= 0 AND ttl_seconds <= 604800)
);

CREATE INDEX IF NOT EXISTS secret_chats_admin_idx
    ON secret_chats (admin_id) WHERE state <> 'discarded';

CREATE INDEX IF NOT EXISTS secret_chats_participant_idx
    ON secret_chats (participant_id) WHERE state <> 'discarded';

-- Only one pending request between a given pair at a time. Without this, a
-- client that retries a request creates a second chat and the participant is
-- shown two identical invitations.
CREATE UNIQUE INDEX IF NOT EXISTS secret_chats_pending_pair_idx
    ON secret_chats (LEAST(admin_id, participant_id), GREATEST(admin_id, participant_id))
    WHERE state = 'requested';

GRANT SELECT, INSERT, UPDATE ON secret_chats TO svc_chat;

COMMIT;
